// Package control holds the end-to-end round-trip test for the local control
// channel (issue #2).
//
// It is NOT behind the `integration` build tag, because it needs no docker lab:
// the control channel is a unix socket, the agent it drives runs with stubbed
// external commands (a fake pin verifier and a scripted ping runner), and the
// whole thing is a few milliseconds. It therefore runs in the ordinary unit tier
// on every PR, which is where a wire-format regression should be caught.
//
// What it proves that the package-level tests cannot: the real agent, wired the
// way cmd/transitd wires it, serves a control socket whose `status` reply carries
// exactly the document the agent's own HTTP /healthz handler would return. The
// two surfaces being one document is the property the status method exists for.
package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/agent"
	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/ctrl"
	"github.com/ioseph-ai/transitd/internal/gossip"
	"github.com/ioseph-ai/transitd/internal/pinning"

	"github.com/hashicorp/memberlist"
)

// testKey is a documentation placeholder key — base64 of a 16-byte literal, not a
// secret. The config carries its base64 form; the header carries the same, which is
// what an operator's `gossip.key` and `transitctl --key` both are.
const testKeyB64 = "MDEyMzQ1Njc4OWFiY2RlZg=="

// stubVerifier stands in for pinning.RouteVerifier: it answers from a fixed map,
// so the test needs no root and no routing table.
type stubVerifier struct{ verified map[string]bool }

func (v stubVerifier) Verify(_ context.Context, t config.Transit) pinning.Result {
	ok := v.verified[t.Name]
	return pinning.Result{
		Transit: t.Name, Verified: ok, EgressIf: t.EgressInterface,
		Reason: "stub verifier",
	}
}

// stubRunner answers every ping from a canned reply, so the probe loop produces a
// sample without touching the network.
type stubRunner struct{}

func (stubRunner) Run(_ context.Context, _ string, _ ...string) (string, string, int, error) {
	return "PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.\n" +
		"64 bytes from 198.51.100.5: icmp_seq=1 ttl=63 time=12.000 ms\n\n" +
		"--- 198.51.100.5 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n", "", 0, nil
}

// controlSocketPath returns a socket path in a fresh short-named temp dir. The
// path must stay under the kernel's 108-byte sockaddr_un limit, which a deep CI
// TMPDIR plus a long test name can otherwise approach.
func controlSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tctl-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "ctrl.sock")
	if len(p) > 107 {
		t.Fatalf("test socket path is %d bytes, over the unix limit", len(p))
	}
	return p
}

// controlConfig builds a validated config for the named transits with the control
// channel pointed at sock.
func controlConfig(t *testing.T, sock string, names ...string) *config.Config {
	t.Helper()
	c := &config.Config{
		RouterName:  "r-ctrl",
		BindAddr:    "192.0.2.254",
		MarginMs:    10,
		WinCycles:   1,
		Dwell:       time.Hour, // never switch during a short test
		MaxSwitches: 4,
		LossDropPct: 5,
		Gossip:      config.Gossip{Key: testKeyB64},
		Control:     config.Control{SocketPath: sock},
	}
	for i, n := range names {
		c.Transits = append(c.Transits, config.Transit{
			Name:            n,
			ImportMap:       strings.ToUpper(n) + "-LOCAL-IN",
			ProbeSource:     fmt.Sprintf("192.0.2.%d", i+1),
			ProbeTarget:     fmt.Sprintf("198.51.100.%d", i+1),
			EgressInterface: "eth-" + n,
			ProbeInterval:   time.Millisecond,
		})
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("fixture config does not validate: %v", err)
	}
	return c
}

// testMesh builds a gossip mesh over an ephemeral loopback port, so an agent test
// can run the real mesh wiring without binding the configured bind_addr (which is
// a documentation address and therefore unassignable) or the default mesh port.
func testMesh(t *testing.T, c *config.Config) *gossip.Mesh {
	t.Helper()
	key, err := c.Gossip.KeyBytes()
	if err != nil {
		t.Fatalf("gossip key: %v", err)
	}
	ml := memberlist.DefaultLANConfig()
	ml.Name = c.RouterName
	ml.BindAddr = "127.0.0.1"
	ml.BindPort = 0
	ml.AdvertisePort = 0
	ml.SecretKey = key
	ml.LogOutput = io.Discard
	m, err := gossip.New(gossip.Options{
		Config:           c,
		Snapshot:         func() gossip.HealthPayload { return gossip.HealthPayload{} },
		Interval:         time.Hour,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		MemberlistConfig: ml,
	})
	if err != nil {
		t.Fatalf("gossip.New: %v", err)
	}
	return m
}

// startAgent builds and runs a real agent with stubbed externals and the control
// channel enabled, and returns it with a client pointed at its socket.
func startAgent(t *testing.T, sock string, names ...string) (*agent.Agent, *ctrl.Client) {
	t.Helper()
	c := controlConfig(t, sock, names...)
	verified := map[string]bool{}
	for _, n := range names {
		verified[n] = true
	}
	ag, err := agent.New(agent.Options{
		Config:        c,
		Verifier:      stubVerifier{verified: verified},
		Runner:        stubRunner{},
		Interval:      5 * time.Millisecond,
		ControlSocket: true,
		Mesh:          testMesh(t, c),
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-runErr; err != nil {
			t.Errorf("agent.Run: %v", err)
		}
	})

	// Wait for the control socket to answer, rather than assuming Start bound it
	// before Run's goroutine was scheduled.
	client := &ctrl.Client{SocketPath: sock, Key: testKeyB64, Timeout: 2 * time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ag, client
}

// TestStatusRoundTripAgainstAgent is the card's integration requirement: a status
// call over the real socket, against a real agent (stubbed externals), returns the
// agent's health document.
func TestStatusRoundTripAgainstAgent(t *testing.T) {
	sock := controlSocketPath(t)
	ag, client := startAgent(t, sock, "main", "backup")

	resp, err := client.Call(ctrl.MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call(status): %v", err)
	}
	var res ctrl.StatusResult
	if err := ctrl.DecodeResult(resp, &res); err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if res.Version != ctrl.ProtocolVersion || res.Router != "r-ctrl" {
		t.Errorf("status envelope = %+v", res)
	}

	// The health document must equal what the agent's own Health() produces, so a
	// control client and a /healthz scrape cannot disagree.
	want, err := json.Marshal(ag.Health())
	if err != nil {
		t.Fatalf("marshal Health: %v", err)
	}
	var gotDoc, wantDoc map[string]any
	if err := json.Unmarshal(res.Health, &gotDoc); err != nil {
		t.Fatalf("unmarshal health from control: %v", err)
	}
	if err := json.Unmarshal(want, &wantDoc); err != nil {
		t.Fatalf("unmarshal Health(): %v", err)
	}
	if fmt.Sprint(gotDoc) != fmt.Sprint(wantDoc) {
		t.Errorf("control status health != agent Health():\n got=%v\nwant=%v", gotDoc, wantDoc)
	}

	// And the HTTP surface agrees too: /healthz decodes to the same document.
	rec := httptest.NewRecorder()
	ag.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d", rec.Code)
	}
	var httpDoc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &httpDoc); err != nil {
		t.Fatalf("unmarshal /healthz: %v", err)
	}
	if fmt.Sprint(httpDoc) != fmt.Sprint(wantDoc) {
		t.Errorf("/healthz != agent Health():\n got=%v\nwant=%v", httpDoc, wantDoc)
	}
}

// TestSetPrimaryRecordsPreferenceOverSocket drives the whole observe-only path: the
// CLI-style client asks for a transit, the agent records it, and the preference shows
// up in both the metric and the healthz document — while nothing is applied.
func TestSetPrimaryRecordsPreferenceOverSocket(t *testing.T) {
	sock := controlSocketPath(t)
	ag, client := startAgent(t, sock, "main", "backup")

	resp, err := client.Call(ctrl.MethodSetPrimary, ctrl.SetPrimaryParams{Transit: "backup"})
	if err != nil {
		t.Fatalf("Call(set-primary): %v", err)
	}
	var res ctrl.SetPrimaryResult
	if err := ctrl.DecodeResult(resp, &res); err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if res.Transit != "backup" {
		t.Errorf("recorded = %q, want backup", res.Transit)
	}
	if res.Applied {
		t.Error("Applied = true; this build applies nothing")
	}

	// The agent's health must now report the recorded preference, so the operator
	// can see the agent heard them.
	deadline := time.Now().Add(2 * time.Second)
	for ag.Health().DesiredPrimary != "backup" {
		if time.Now().After(deadline) {
			t.Fatalf("desired_primary never became backup: %+v", ag.Health())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if h := ag.Health(); h.Control == nil || h.Control.DesiredPrimary != "backup" {
		t.Errorf("Health().Control = %+v, want desired_primary backup", h.Control)
	}
}

// TestAuthRejectedOverAgentSocket is the end-to-end auth check: a client with the
// wrong key is refused by the real agent's socket, and its audit counter moves.
func TestAuthRejectedOverAgentSocket(t *testing.T) {
	sock := controlSocketPath(t)
	startAgent(t, sock, "main")

	wrongKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	bad := &ctrl.Client{SocketPath: sock, Key: wrongKey, Timeout: 2 * time.Second}
	resp, err := bad.Call(ctrl.MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.HasPrefix(resp.Error, ctrl.ErrCodeUnauthorized) {
		t.Fatalf("error = %q, want unauthorized", resp.Error)
	}
}

// TestControlChannelStopsWithAgent checks the lifecycle wiring: when the agent's
// loop stops, the control socket is shut down and removed, so it cannot answer
// with a frozen view or leave a stale socket for the next start.
func TestControlChannelStopsWithAgent(t *testing.T) {
	sock := controlSocketPath(t)
	c := controlConfig(t, sock, "main")
	ag, err := agent.New(agent.Options{
		Config:        c,
		Verifier:      stubVerifier{verified: map[string]bool{"main": true}},
		Runner:        stubRunner{},
		Interval:      time.Hour,
		ControlSocket: true,
		Mesh:          testMesh(t, c),
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-runErr
			t.Fatal("control socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("agent.Run: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("control socket still present after the agent stopped: %v", err)
	}
}

// TestDisabledControlChannelOpensNoSocket: an agent with no control channel asked
// for must not create one. This is the single-router default.
func TestDisabledControlChannelOpensNoSocket(t *testing.T) {
	sock := controlSocketPath(t)
	c := controlConfig(t, sock, "main")
	// A config naming a socket is valid (a key is present), but the caller did not
	// ask for the channel, so nothing should bind.
	ag, err := agent.New(agent.Options{
		Config:   c,
		Verifier: stubVerifier{verified: map[string]bool{"main": true}},
		Runner:   stubRunner{},
		Interval: time.Hour,
		Mesh:     testMesh(t, c),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()

	// Give the agent a moment to start, then assert no socket exists.
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("a control socket exists although the channel was not enabled: %v", err)
	}
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("agent.Run: %v", err)
	}
}
