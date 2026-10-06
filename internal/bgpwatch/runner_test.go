package bgpwatch

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
)

// recordingRunner is the unit tier's stand-in for vtysh: it answers each query
// from a fixed map and records every query it was asked, so a test can assert both
// on the parse AND on the exact command surface bgpwatch used.
type recordingRunner struct {
	mu      sync.Mutex
	queries []string
	answers map[string]string
	err     error
}

func (r *recordingRunner) Show(_ context.Context, query string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, query)
	if r.err != nil {
		return "", r.err
	}
	if a, ok := r.answers[query]; ok {
		return a, nil
	}
	return "{}", nil
}

func (r *recordingRunner) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

// TestPollerSummaryIssuesReadOnlyShow checks the command surface: a summary poll
// issues exactly one query, and it is the read-only `bgp summary json` — no verb,
// no configuration mode, nothing that could mutate.
func TestPollerSummaryIssuesReadOnlyShow(t *testing.T) {
	rr := &recordingRunner{answers: map[string]string{
		"bgp summary json": `{"ipv4Unicast":{"routerId":"192.0.2.2","as":64496,"peers":{"192.0.2.3":{"state":"Established","pfxRcd":0,"pfxSnt":2}}}}`,
	}}
	p := New(config.BGPWatchConfig{Enabled: true, MaxPrefixes: 10, Interval: time.Second}, rr)

	s, err := p.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if !s.Sessions["192.0.2.3"].Up {
		t.Errorf("session not up: %+v", s.Sessions["192.0.2.3"])
	}
	if got := rr.seen(); len(got) != 1 || got[0] != "bgp summary json" {
		t.Errorf("queries = %v, want exactly [bgp summary json]", got)
	}
}

// TestPollerRateLimitIsOneHz pins the 1 Hz cap: a second poll of any kind inside
// the window is refused with ErrRateLimited, and — crucially — issues NO command.
// The cap is what keeps a full-table JSON dump off a 1 vCPU router at any more
// than one per second.
func TestPollerRateLimitIsOneHz(t *testing.T) {
	now := time.Unix(1791314300, 0)
	rr := &recordingRunner{}
	p := New(config.BGPWatchConfig{Enabled: true, MaxPrefixes: 10, Interval: time.Second}, rr)
	p.Clock = func() time.Time { return now }

	if _, err := p.Summary(context.Background()); err != nil {
		t.Fatalf("first Summary: %v", err)
	}
	if _, err := p.Summary(context.Background()); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second Summary error = %v, want ErrRateLimited", err)
	}
	// Also true across view kinds: the cap is per poller, not per query.
	if _, err := p.Prefixes(context.Background(), AFIPv4); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Prefixes inside the window error = %v, want ErrRateLimited", err)
	}
	if _, err := p.BestPath(context.Background(), AFIPv4, "198.51.100.0/24"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("BestPath inside the window error = %v, want ErrRateLimited", err)
	}
	if got := rr.seen(); len(got) != 1 {
		t.Errorf("rate-limited polls issued %d queries, want 1 (only the first poll may exec)", len(got))
	}

	// A second later the window has passed.
	now = now.Add(time.Second)
	if _, err := p.Summary(context.Background()); err != nil {
		t.Fatalf("Summary after the window: %v", err)
	}
}

// TestNewAppliesOneHzFloorEvenWhenConfigAsksFaster proves the floor is enforced in
// the type, not only in config validation: a Poller built directly with a
// sub-second interval still resolves to the floor.
func TestNewAppliesOneHzFloorEvenWhenConfigAsksFaster(t *testing.T) {
	p := New(config.BGPWatchConfig{Enabled: true, Interval: 100 * time.Millisecond}, nil)
	if got := p.interval(); got != config.MinBGPWatchInterval {
		t.Errorf("interval = %v, want the %v floor", got, config.MinBGPWatchInterval)
	}
	// A directly-built Poller (not via New) is covered too.
	raw := &Poller{Interval: 10 * time.Millisecond}
	if got := raw.interval(); got != config.MinBGPWatchInterval {
		t.Errorf("raw Poller interval = %v, want the floor", got)
	}
}

// TestPollerPrefixesCapsParsing checks the prefix cap reaches the parser: a table
// over the cap must surface ErrTooManyPrefixes through the poller, not a partial
// list.
func TestPollerPrefixesCapsParsing(t *testing.T) {
	rr := &recordingRunner{answers: map[string]string{
		"bgp ipv4 unicast json": fixture(t, "routes-too-many.json"),
	}}
	p := New(config.BGPWatchConfig{Enabled: true, MaxPrefixes: 2, Interval: time.Second}, rr)

	_, err := p.Prefixes(context.Background(), AFIPv4)
	var tooMany ErrTooManyPrefixes
	if !errors.As(err, &tooMany) {
		t.Fatalf("Prefixes error = %v, want ErrTooManyPrefixes", err)
	}
}

// TestPollerQueryShapes pins the exact query strings for each view, including the
// address family in the prefix-level views. A wrong view name would silently
// return an empty table, which is the failure that looks like "no prefixes".
func TestPollerQueryShapes(t *testing.T) {
	now := time.Unix(1791314300, 0)
	rr := &recordingRunner{answers: map[string]string{
		"bgp ipv6 unicast json":                 fixture(t, "routes-ipv6-empty.json"),
		"bgp ipv4 unicast 198.51.100.0/24 json": fixture(t, "bestpath-present.json"),
	}}
	p := New(config.BGPWatchConfig{Enabled: true}, rr)
	p.Clock = func() time.Time { return now }

	if _, err := p.Prefixes(context.Background(), AFIPv6); err != nil {
		t.Fatalf("Prefixes v6: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := p.BestPath(context.Background(), AFIPv4, "198.51.100.0/24"); err != nil {
		t.Fatalf("BestPath: %v", err)
	}
	want := []string{
		"bgp ipv6 unicast json",
		"bgp ipv4 unicast 198.51.100.0/24 json",
	}
	got := rr.seen()
	if len(got) != len(want) {
		t.Fatalf("queries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("query[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// An unknown AF is a programming error, not a query.
	if _, err := p.Prefixes(context.Background(), AF("ipx")); err == nil {
		t.Error("Prefixes accepted an unknown address family")
	}
}

// TestPollerRunEmitsConfiguredNeighbors drives the loop: only transits with a
// bgp_neighbor produce a Session, an up session reads up, and Run stops cleanly on
// cancellation.
func TestPollerRunEmitsConfiguredNeighbors(t *testing.T) {
	rr := &recordingRunner{answers: map[string]string{
		"bgp summary json": fixture(t, "summary-established.json"),
	}}
	p := New(config.BGPWatchConfig{Enabled: true, Interval: time.Second}, rr)

	var mu sync.Mutex
	got := map[string]Session{}
	p.Emit = func(s Session) {
		mu.Lock()
		got[s.Neighbor] = s
		mu.Unlock()
	}

	transits := []config.Transit{
		{Name: "main", BGPNeighbor: "192.0.2.11"},  // up
		{Name: "backup", BGPNeighbor: "192.0.2.3"}, // up in the fixture
		{Name: "no-bgp", BGPNeighbor: ""},          // not BGP-observed: no emission
		{Name: "ghost", BGPNeighbor: "192.0.2.99"}, // configured but absent: down
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, transits, nil); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := got[""]; ok {
		t.Error("a transit with no bgp_neighbor produced a session observation")
	}
	if s, ok := got["192.0.2.11"]; !ok || !s.Up {
		t.Errorf("main session = %+v, want up", s)
	}
	if s, ok := got["192.0.2.99"]; !ok || s.Up {
		t.Errorf("session for a neighbor absent from the summary = %+v, want a down observation", s)
	}
}

// readDirDot lists the package directory's Go file names.
func readDirDot(t *testing.T) ([]string, error) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// readFileT reads a package file, failing the test on error.
func readFileT(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // package-relative scan of our own sources
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(b)
}

// splitLines splits a file body on newlines.
func splitLines(s string) []string { return strings.Split(s, "\n") }

// TestSourceIssuesNoMutatingCommand is the structural half of the read-only
// promise: no production file in this package may contain a mutating vtysh verb.
// The scan strips comments first, so the package may explain what it does not do.
func TestSourceIssuesNoMutatingCommand(t *testing.T) {
	banned := []string{
		"conf" + "igure ",
		"write " + "file",
		"clear " + "bgp",
		"no " + "neighbor",
	}
	entries, err := readDirDot(t)
	if err != nil {
		t.Fatalf("readDir: %v", err)
	}
	scanned := 0
	for _, name := range entries {
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		for i, line := range splitLines(readFileT(t, name)) {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			for _, pat := range banned {
				if strings.Contains(code, pat) {
					t.Errorf("%s:%d contains %q in code — bgpwatch is read-only and may only issue `show`", name, i+1, pat)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files; the guard is vacuous")
	}
}
