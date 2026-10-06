package agent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/bgpwatch"
	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/decide"
	"github.com/ioseph-ai/transitd/internal/probes"
)

// fakeBGP is the unit tier's stand-in for bgpwatch.Runner: it answers `show bgp
// summary json` from a fixed document and records the queries it saw, so a test
// can prove the agent's BGP seam issues only read-only `show` lookups.
type fakeBGP struct {
	mu      sync.Mutex
	queries []string
	summary string
}

func (f *fakeBGP) Show(_ context.Context, query string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, query)
	return f.summary, nil
}

func (f *fakeBGP) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// bgpTestConfig builds a validated config with bgpwatch enabled and every transit
// naming a BGP neighbor. The neighbors are documentation addresses (RFC 5737) and
// are the keys the summary fixture uses, so a session observation can be attributed
// to a transit.
func bgpTestConfig(t *testing.T, names ...string) *config.Config {
	t.Helper()
	c := testConfig(t, names...)
	c.BGPWatch = config.BGPWatchConfig{Enabled: true, MaxPrefixes: 100, Interval: time.Second}
	for i := range c.Transits {
		c.Transits[i].BGPNeighbor = c.Transits[i].ProbeTarget
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("bgp fixture config does not validate: %v", err)
	}
	return c
}

// summaryFor renders a one-peer `show bgp summary json` with the given session
// state, keyed by neighbor. It is built, not read, so a test names exactly the
// state it means to exercise.
func summaryFor(neighbor, state string) string {
	return `{"ipv4Unicast":{"routerId":"192.0.2.2","as":64496,"peers":{` +
		`"` + neighbor + `":{"state":"` + state + `","peerState":"OK","pfxRcd":0,"pfxSnt":2}}}}`
}

// TestBGPWatchFeedsSessionDownIntoDecide is the card's agent-wiring assertion: a
// down BGP session for a transit must reach decide as SessionUp=false. The session
// state comes from bgpwatch, and the probe path is intact (a healthy sample), so the
// only thing that can mark the transit down is the BGP observation.
func TestBGPWatchFeedsSessionDownIntoDecide(t *testing.T) {
	const name = "bgp-down"
	c := bgpTestConfig(t, name)
	neighbor := c.Transits[0].BGPNeighbor

	bgp := &fakeBGP{summary: summaryFor(neighbor, "Idle (Admin)")}
	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{name: true}},
		Runner:   &scriptedRunner{reply: true, rttMs: 20},
		BGPWatch: bgp,
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Feed a healthy probe sample and the bgpwatch observation directly, bypassing
	// goroutines so the test is deterministic.
	a.obs[name] = probes.Sample{Transit: name, LatencyMs: 20, LossPct: 0}
	a.sessions[neighbor] = bgpwatch.Session{Neighbor: neighbor, State: bgpwatch.StateIdleAdmin, Up: false}

	h := a.healthView()
	if len(h) != 1 {
		t.Fatalf("health view = %+v, want one entry", h)
	}
	if h[0].SessionUp {
		t.Errorf("SessionUp = true for a transit whose BGP session bgpwatch reports down: %+v", h[0])
	}

	// And decide must not adopt a session-down transit: it is hard-down.
	a.evaluate()
	if got := a.engine.State.Primary; got != "" {
		t.Errorf("primary = %q, want empty — a session-down transit must not be adopted", got)
	}
}

// TestBGPWatchSessionUpKeepsTransitEligible is the positive half: an Established
// observation must leave a healthy transit eligible, so the wiring does not just
// suppress everything.
func TestBGPWatchSessionUpKeepsTransitEligible(t *testing.T) {
	const name = "bgp-up"
	c := bgpTestConfig(t, name)
	neighbor := c.Transits[0].BGPNeighbor

	bgp := &fakeBGP{summary: summaryFor(neighbor, "Established")}
	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{name: true}},
		Runner:   &scriptedRunner{reply: true, rttMs: 20},
		BGPWatch: bgp,
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.obs[name] = probes.Sample{Transit: name, LatencyMs: 20, LossPct: 0}
	a.sessions[neighbor] = bgpwatch.Session{Neighbor: neighbor, State: bgpwatch.StateEstablished, Up: true}

	h := a.healthView()
	if !h[0].SessionUp {
		t.Errorf("SessionUp = false for an Established session: %+v", h[0])
	}
	a.evaluate()
	if got := a.engine.State.Primary; got != name {
		t.Errorf("primary = %q, want %q (an Established transit is eligible)", got, name)
	}
}

// TestBGPWatchUnobservedSessionIsNotDown pins the conservative default: a transit
// that names a neighbor for which NO observation has arrived reads as up. "Not yet
// observed" must not be reported to decide as a hard-down session — that would be a
// fabricated input, and it is exactly the class of mistake suppression exists to
// avoid.
func TestBGPWatchUnobservedSessionIsNotDown(t *testing.T) {
	const name = "bgp-unseen"
	c := bgpTestConfig(t, name)

	bgp := &fakeBGP{summary: summaryFor(c.Transits[0].BGPNeighbor, "Established")}
	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{name: true}},
		Runner:   &scriptedRunner{reply: true, rttMs: 20},
		BGPWatch: bgp,
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No session observation recorded.
	a.obs[name] = probes.Sample{Transit: name, LatencyMs: 20, LossPct: 0}

	h := a.healthView()
	if !h[0].SessionUp {
		t.Errorf("SessionUp = false with no BGP observation; an unobserved session is not a down session: %+v", h[0])
	}
}

// TestBGPWatchNotEnabledIsProbeOnly checks the off switch: with bgpwatch disabled
// the agent still ranks on probe health and the transit reads up, as before issue
// #4. The session input is additive, not a new dependency of the decision path.
func TestBGPWatchNotEnabledIsProbeOnly(t *testing.T) {
	const name = "bgp-off"
	c := testConfig(t, name) // BGPWatch.Enabled false by default
	bgp := &fakeBGP{summary: summaryFor("198.51.100.99", "Idle (Admin)")}
	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{name: true}},
		Runner:   &scriptedRunner{reply: true, rttMs: 20},
		BGPWatch: bgp,
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.bgp != nil {
		t.Error("a poller was wired despite bgpwatch being disabled")
	}
	if len(bgp.seen()) != 0 {
		t.Errorf("the BGP runner was queried with bgpwatch disabled: %v", bgp.seen())
	}
	a.obs[name] = probes.Sample{Transit: name, LatencyMs: 20, LossPct: 0}
	if !a.healthView()[0].SessionUp {
		t.Error("a transit read down with bgpwatch disabled")
	}
}

// TestBGPWatchRunsReadOnlyPolls drives the full loop: with a fake BGP runner whose
// summary marks a session up, a session observation must reach the agent and only
// read-only queries must have been issued.
func TestBGPWatchRunsReadOnlyPolls(t *testing.T) {
	const name = "bgp-run"
	c := bgpTestConfig(t, name)
	neighbor := c.Transits[0].BGPNeighbor

	bgp := &fakeBGP{summary: summaryFor(neighbor, "Established")}
	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{name: true}},
		Runner:   &scriptedRunner{reply: true, rttMs: 20},
		BGPWatch: bgp,
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return a.bgpUp.Load() })

	queries := bgp.seen()
	if len(queries) == 0 {
		t.Fatal("bgpwatch issued no queries")
	}
	for _, q := range queries {
		if !strings.HasPrefix(q, "bgp ") || strings.Contains(q, "configure") {
			t.Errorf("bgpwatch issued a non-read-only query %q", q)
		}
	}
	// The observation must be visible to healthz: bgpwatch is a live capability.
	if got := a.Health().Features["bgpwatch"]; got != featureOK {
		t.Errorf("features[bgpwatch] = %q, want ok once a session observation arrived", got)
	}
}

// TestBGPWatchFeatureIsUnavailableWithoutObservation pins the healthz half: with
// the poller wired but nothing observed yet, bgpwatch reads "unavailable", so an
// operator can tell "not answering" from "not enabled" — the same discipline the
// probes feature follows.
func TestBGPWatchFeatureIsUnavailableWithoutObservation(t *testing.T) {
	c := bgpTestConfig(t, "bgp-hz")
	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{"bgp-hz": true}},
		Runner:   &scriptedRunner{},
		BGPWatch: &fakeBGP{},
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := a.Health().Features["bgpwatch"]; got != featureUnavailable {
		t.Errorf("features[bgpwatch] = %q before any observation, want unavailable", got)
	}
}

// TestDecideNeverSeesAct is the wiring half of "act is NOT wired to decide yet":
// after a decision cycle, no act batch has been applied and no act counter series
// has moved. The observe-only guard is structural; this is the behavioural check
// that a decision produces a log line and a counter, never a router change.
func TestDecideNeverSeesAct(t *testing.T) {
	const inc, chal = "no-act-inc", "no-act-chal"
	c := testConfig(t, inc, chal)
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{inc: true, chal: true}}, &scriptedRunner{})

	a.engine.State = &decide.State{Primary: inc, LastSwitch: time.Now().Add(-time.Hour), WinStreak: map[string]int{}}
	a.obs[inc] = probes.Sample{Transit: inc, LatencyMs: 80, LossPct: 0}
	a.obs[chal] = probes.Sample{Transit: chal, LatencyMs: 10, LossPct: 0}
	a.evaluate()

	// The switch is recorded, and no act executor exists to have applied it.
	if got := a.engine.State.Primary; got != chal {
		t.Fatalf("primary = %q, want %q", got, chal)
	}
	if n := actOpsTotal(t); n != 0 {
		t.Errorf("transitd_act_ops has %d series after a decision with act unwired, want 0", n)
	}
}

// actOpsTotal counts the series in transitd_act_ops. It is the counter act would
// move; with act unwired it must stay empty.
func actOpsTotal(t *testing.T) int {
	t.Helper()
	fams := gatherMetrics(t)
	return len(fams["transitd_act_ops"].GetMetric())
}
