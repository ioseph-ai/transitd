package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/hashicorp/memberlist"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/decide"
	"github.com/ioseph-ai/transitd/internal/gossip"
	"github.com/ioseph-ai/transitd/internal/metrics"
	"github.com/ioseph-ai/transitd/internal/pinning"
	"github.com/ioseph-ai/transitd/internal/probes"
)

// newTestMesh builds a mesh over an ephemeral loopback port, so an agent test can
// exercise the real gossip wiring without binding the default mesh port. The
// cadence is short so a test does not wait a production interval.
func newTestMesh(t *testing.T, c *config.Config) *gossip.Mesh {
	t.Helper()
	ml := memberlist.DefaultLANConfig()
	ml.Name = c.RouterName
	ml.BindAddr = "127.0.0.1"
	ml.BindPort = 0
	ml.AdvertisePort = 0
	key, err := c.Gossip.KeyBytes()
	if err != nil {
		t.Fatalf("gossip key: %v", err)
	}
	ml.SecretKey = key
	ml.LogOutput = io.Discard
	ml.ProbeInterval = 100 * time.Millisecond
	ml.PushPullInterval = 100 * time.Millisecond
	ml.GossipInterval = 50 * time.Millisecond
	m, err := gossip.New(gossip.Options{
		Config:           c,
		Snapshot:         func() gossip.HealthPayload { return gossip.HealthPayload{} },
		Interval:         50 * time.Millisecond,
		Log:              discardingLog(),
		MemberlistConfig: ml,
	})
	if err != nil {
		t.Fatalf("gossip.New: %v", err)
	}
	return m
}

// --- fakes -------------------------------------------------------------------

// fakeVerifier is the unit-tier stand-in for pinning.RouteVerifier: it answers
// from a fixed per-transit outcome map, with no `ip`, no root and no routing
// table involved.
type fakeVerifier struct {
	verified map[string]bool
	egress   map[string]string
}

func (f *fakeVerifier) Verify(_ context.Context, t config.Transit) pinning.Result {
	ok := f.verified[t.Name]
	eg := f.egress[t.Name]
	if eg == "" {
		eg = t.EgressInterface
	}
	reason := "fake: egress matches"
	if !ok {
		reason = "fake: probes egress elsewhere"
	}
	return pinning.Result{Transit: t.Name, Verified: ok, EgressIf: eg, Reason: reason}
}

// scriptedRunner answers every ping from one canned outcome. It never sleeps and
// never touches the network, so a loop driven by it is deterministic and fast.
type scriptedRunner struct {
	mu    sync.Mutex
	calls int
	reply bool
	rttMs float64
}

func (r *scriptedRunner) Run(_ context.Context, _ string, _ ...string) (string, string, int, error) {
	r.mu.Lock()
	r.calls++
	reply := r.reply
	rtt := r.rttMs
	r.mu.Unlock()

	if !reply {
		return "PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.\n\n" +
			"--- 198.51.100.5 ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", "", 1, nil
	}
	return "PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.\n" +
		"64 bytes from 198.51.100.5: icmp_seq=1 ttl=63 time=" + strconv.FormatFloat(rtt, 'f', 3, 64) + " ms\n\n" +
		"--- 198.51.100.5 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n", "", 0, nil
}

func (r *scriptedRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// discardingLog returns a logger that writes nothing, so a test's output is only
// its own assertions.
func discardingLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- fixtures ----------------------------------------------------------------

// testConfig builds a validated config for the named transits. Addresses are
// derived from each transit's index inside the RFC 5737 documentation ranges, so
// every transit is distinct and no deployment value is implied. Names should be
// unique per test: the metric registry is process-global, so reusing a name
// across tests would let one test's series leak into another's assertions.
func testConfig(t *testing.T, names ...string) *config.Config {
	t.Helper()
	c := &config.Config{
		RouterName:  "r-test",
		BindAddr:    "192.0.2.254",
		MarginMs:    10,
		WinCycles:   1,
		Dwell:       time.Millisecond,
		MaxSwitches: 4,
		LossDropPct: 5,
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

// newTestAgent builds an agent over the fixture with fakes injected. Interval is
// short so an end-to-end test reaches a decision cycle within its patience.
func newTestAgent(t *testing.T, c *config.Config, v *fakeVerifier, r probes.Runner) *Agent {
	t.Helper()
	a, err := New(Options{Config: c, Verifier: v, Runner: r, Interval: 5 * time.Millisecond, Log: discardingLog()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// newUncheckedAgent builds the agent's internals directly, bypassing New's
// validation. Only the suppression-vs-error test needs it: it must hand a
// verified transit a probe config that Validate would reject, to prove the loop
// constructor — not Validate — is what refuses it.
func newUncheckedAgent(c *config.Config, v *fakeVerifier, r probes.Runner) *Agent {
	a := &Agent{
		cfg:      c,
		log:      discardingLog(),
		interval: 5 * time.Millisecond,
		engine:   decide.NewEngine(c, &decide.State{WinStreak: map[string]int{}}),
		samples:  make(chan probes.Sample, 8),
		obs:      map[string]probes.Sample{},
	}
	a.sup = &probes.Supervisor{Runner: r, Verify: v.Verify, Emit: a.onSample}
	return a
}

// --- the wiring test the card asks for ---------------------------------------

// TestUnverifiedTransitProducesNoSamplesAndNoDecisions is the card's wiring test:
// an unverified transit must produce no samples and no decisions.
//
// It asserts on the observable surfaces rather than on internals — the probe
// binary never runs for that transit, no probe series is exported, its
// pin_verified gauge is a present 0, and no decision names it.
func TestUnverifiedTransitProducesNoSamplesAndNoDecisions(t *testing.T) {
	const good, bad = "wire-good", "wire-bad"
	c := testConfig(t, good, bad)
	verifier := &fakeVerifier{verified: map[string]bool{good: true, bad: false}}
	runner := &scriptedRunner{reply: true, rttMs: 20}
	a := newTestAgent(t, c, verifier, runner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait for the verified transit's first sample, so "bad produced nothing" is
	// asserted after the pipeline has demonstrably run.
	waitFor(t, time.Second, func() bool { return a.probed.Load() })

	h := a.Health()
	if !h.PinVerified[good] {
		t.Error("verified transit reported unverified")
	}
	if h.PinVerified[bad] {
		t.Error("unverified transit reported verified")
	}
	if h.Status != statusDegraded {
		t.Errorf("healthz status = %q, want degraded while a configured transit is unverified", h.Status)
	}
	if h.Features["probes"] != featureOK {
		t.Errorf("features[probes] = %q, want ok — the verified transit did emit a sample", h.Features["probes"])
	}
	if runner.callCount() == 0 {
		t.Error("no probe ran for the verified transit")
	}

	fams := gatherMetrics(t)
	if _, ok := seriesValue(t, fams["transitd_probe_latency_ms"], bad); ok {
		t.Error("unverified transit exported a probe_latency_ms series, want none")
	}
	if _, ok := seriesValue(t, fams["transitd_probe_loss_pct"], bad); ok {
		t.Error("unverified transit exported a probe_loss_pct series, want none")
	}
	if v, ok := seriesValue(t, fams["transitd_pin_verified"], bad); !ok || v != 0 {
		t.Errorf("unverified transit pin_verified = %v (present=%t), want a present 0", v, ok)
	}
	if n := decisionSeriesNaming(fams, bad); n != 0 {
		t.Errorf("decisions_total names the unverified transit %d times, want 0", n)
	}
}

// TestUnverifiedTransitRunsNoPing is the sharper form of the same property: the
// suppression is structural (no loop is built at all), so with every transit
// unverified the probe binary must never be invoked.
func TestUnverifiedTransitRunsNoPing(t *testing.T) {
	c := testConfig(t, "idle-a", "idle-b")
	verifier := &fakeVerifier{verified: map[string]bool{"idle-a": false, "idle-b": false}}
	runner := &scriptedRunner{reply: true, rttMs: 20}
	a := newTestAgent(t, c, verifier, runner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if n := runner.callCount(); n != 0 {
		t.Errorf("ping ran %d times, want 0 when every transit is unverified", n)
	}
	if a.probed.Load() {
		t.Error("agent reports a probe sample, want none when every transit is unverified")
	}
	h := a.Health()
	if h.Status != statusDegraded {
		t.Errorf("status = %q, want degraded", h.Status)
	}
	if h.Features["probes"] != featureUnavailable {
		t.Errorf("features[probes] = %q, want unavailable with no verified transit", h.Features["probes"])
	}
}

// TestRunExportsNoSamplesForUnverifiedTransit drives the whole loop: with one
// verified and one unverified transit, only the verified transit's series may
// exist after several cycles, and Run must still stop cleanly on cancellation.
func TestRunExportsNoSamplesForUnverifiedTransit(t *testing.T) {
	const good, bad = "run-good", "run-bad"
	c := testConfig(t, good, bad)
	verifier := &fakeVerifier{verified: map[string]bool{good: true, bad: false}}
	runner := &scriptedRunner{reply: true, rttMs: 15}
	a := newTestAgent(t, c, verifier, runner)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	waitFor(t, time.Second, func() bool { return a.probed.Load() })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if a.running.Load() {
		t.Error("agent still reports running after Run returned")
	}

	fams := gatherMetrics(t)
	if _, ok := seriesValue(t, fams["transitd_probe_latency_ms"], good); !ok {
		t.Error("verified transit exported no probe_latency_ms series")
	}
	if _, ok := seriesValue(t, fams["transitd_probe_latency_ms"], bad); ok {
		t.Error("unverified transit exported a probe_latency_ms series after a full Run")
	}
}

// --- the decision path -------------------------------------------------------

// TestEvaluateUsesOnlyObservedTransits drives the decision path directly with
// synthetic observations, bypassing the goroutines: it is the deterministic unit
// test of "feed probe results into decide.Evaluate". A verified transit that has
// not produced a sample yet must not appear in the health view at all — not as a
// fabricated zero-latency transit.
func TestEvaluateUsesOnlyObservedTransits(t *testing.T) {
	c := testConfig(t, "eval-a", "eval-b")
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{"eval-a": true, "eval-b": true}}, &scriptedRunner{})

	a.obs["eval-a"] = probes.Sample{Transit: "eval-a", LatencyMs: 30, LossPct: 0}

	health := a.healthView()
	if len(health) != 1 || health[0].Name != "eval-a" {
		t.Fatalf("health view = %+v, want exactly [eval-a]", health)
	}
	a.evaluate()
	if got := a.engine.State.Primary; got != "eval-a" {
		t.Errorf("primary = %q, want eval-a (the only observed transit)", got)
	}
}

// TestNoReplyIsNotZeroLatency pins the projection rule that keeps "no data" from
// looking like "infinitely fast": NaN latency must reach decide as +Inf, so a
// transit that has never replied can never win the ranking.
func TestNoReplyIsNotZeroLatency(t *testing.T) {
	c := testConfig(t, "dead-a")
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{"dead-a": true}}, &scriptedRunner{reply: false})
	a.obs["dead-a"] = probes.Sample{Transit: "dead-a", LatencyMs: math.NaN(), LossPct: 100}

	h := a.healthView()
	if len(h) != 1 {
		t.Fatalf("health view = %+v", h)
	}
	if h[0].EwmaMs != math.Inf(1) {
		t.Errorf("EwmaMs = %v, want +Inf for a transit that has never replied", h[0].EwmaMs)
	}
	if h[0].LossPct != 100 {
		t.Errorf("LossPct = %v, want 100", h[0].LossPct)
	}
	// And it is not adopted: at 100% loss decide excludes it, so Primary stays
	// empty rather than naming a transit the agent cannot measure.
	a.evaluate()
	if got := a.engine.State.Primary; got != "" {
		t.Errorf("primary = %q, want empty: a loss-excluded transit must not be adopted", got)
	}
}

// TestEvaluateFoldsSwitchBackIntoState exercises the driver step: Evaluate
// reports a switch without persisting it, so Agent.evaluate must set
// State.Primary or the next cycle's incumbent would be wrong. It also checks the
// audit counter records the from/to/reason triple from docs/design.md.
func TestEvaluateFoldsSwitchBackIntoState(t *testing.T) {
	const inc, chal = "audit-incumbent", "audit-challenger"
	c := testConfig(t, inc, chal)
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{inc: true, chal: true}}, &scriptedRunner{})

	a.engine.State = &decide.State{
		Primary:    inc,
		LastSwitch: time.Now().Add(-time.Hour), // dwell long expired
		WinStreak:  map[string]int{},
	}
	a.obs[inc] = probes.Sample{Transit: inc, LatencyMs: 80, LossPct: 0}
	a.obs[chal] = probes.Sample{Transit: chal, LatencyMs: 10, LossPct: 0}

	a.evaluate()
	if got := a.engine.State.Primary; got != chal {
		t.Fatalf("State.Primary = %q, want %q (the driver must persist the switch)", got, chal)
	}
	if n := decisionSeriesNaming(gatherMetrics(t), chal); n == 0 {
		t.Error("decisions_total does not record the switch to the challenger")
	}

	// Second cycle: the challenger is now the incumbent, so it must not switch
	// again — which is only true because the first cycle persisted.
	a.evaluate()
	if got := a.engine.State.Primary; got != chal {
		t.Errorf("State.Primary = %q after a second cycle, want %q", got, chal)
	}
}

// --- health and metrics surface ----------------------------------------------

// TestHealthzEndpoint checks the /healthz JSON contract: the three top-level
// fields, one pin_verified entry per configured transit (including the unverified
// one), and a degraded status when any is unverified.
func TestHealthzEndpoint(t *testing.T) {
	const good, bad = "hz-good", "hz-bad"
	c := testConfig(t, good, bad)
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{good: true, bad: false}}, &scriptedRunner{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a degraded agent still answers)", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got Health
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != statusDegraded {
		t.Errorf("status = %q, want degraded", got.Status)
	}
	if len(got.PinVerified) != 2 {
		t.Errorf("pin_verified has %d entries, want one per configured transit (2)", len(got.PinVerified))
	}
	if !got.PinVerified[good] || got.PinVerified[bad] {
		t.Errorf("pin_verified = %v", got.PinVerified)
	}
	if got.Features["act"] != featureUnavailable {
		t.Errorf("features[act] = %q, want unavailable — observe-only is a capability, not a fault", got.Features["act"])
	}
	if got.Features["decisions"] != featureUnavailable {
		t.Errorf("features[decisions] = %q, want unavailable before Run starts", got.Features["decisions"])
	}
}

// TestMetricsEndpointExportsTransitdNamespace checks /metrics serves the same
// registry the pinning and probe packages write into.
func TestMetricsEndpointExportsTransitdNamespace(t *testing.T) {
	const name = "me-a"
	c := testConfig(t, name)
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{name: true}}, &scriptedRunner{})
	metrics.SetPinVerified(name, true)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "transitd_pin_verified") {
		t.Error("/metrics does not export transitd_pin_verified")
	}
}

// TestHealthBeforeStartIsDegraded pins the safe default: before the preflight has
// run, nothing is proven, so every transit reads unverified and the agent says
// degraded. A healthz that reported "ok" here would be lying.
func TestHealthBeforeStartIsDegraded(t *testing.T) {
	c := testConfig(t, "pre-a", "pre-b")
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{"pre-a": true, "pre-b": true}}, &scriptedRunner{})

	h := a.Health()
	if h.Status != statusDegraded {
		t.Errorf("status before Start = %q, want degraded", h.Status)
	}
	for _, n := range []string{"pre-a", "pre-b"} {
		if h.PinVerified[n] {
			t.Errorf("pin_verified[%s] = true before the preflight ran", n)
		}
	}
}

// --- failure semantics -------------------------------------------------------

// TestStartIsSuppressionNotError checks the failure semantics of issue #1: a
// failed pin is a suppression, not an error; only a VERIFIED transit whose probe
// config is structurally invalid is a startup error.
func TestStartIsSuppressionNotError(t *testing.T) {
	c := testConfig(t, "bad-cfg")

	// An unverified transit is suppressed and reports no error, even though its
	// probe target is nonsense.
	unverified := newUncheckedAgent(c, &fakeVerifier{verified: map[string]bool{"bad-cfg": false}}, &scriptedRunner{})
	unverified.cfg.Transits[0].ProbeTarget = "not-an-ip"
	if err := unverified.Start(context.Background()); err != nil {
		t.Fatalf("Start with an unverified transit returned %v, want nil (suppression, not an error)", err)
	}

	// A verified transit with the same nonsense target is a startup error: the
	// suppression rule must never silently swallow a genuine config bug.
	verified := newUncheckedAgent(c, &fakeVerifier{verified: map[string]bool{"bad-cfg": true}}, &scriptedRunner{})
	verified.cfg.Transits[0].ProbeTarget = "not-an-ip"
	if err := verified.Start(context.Background()); err == nil {
		t.Fatal("Start with a verified transit whose probe config is invalid returned nil, want an error")
	}
}

// TestNewRejectsUnvalidatedConfig checks New is a validating seam: it never
// returns an agent over a config that has not passed Validate.
func TestNewRejectsUnvalidatedConfig(t *testing.T) {
	c := testConfig(t, "v-a")
	c.Transits[0].ProbeSource = "" // missing the pin
	if _, err := New(Options{Config: c, Log: discardingLog()}); err == nil {
		t.Fatal("New accepted a config with no probe_source")
	}
	if _, err := New(Options{Log: discardingLog()}); err == nil {
		t.Fatal("New accepted a nil Config")
	}
}

// TestRunReturnsErrorFromStart checks Run surfaces a Start failure instead of
// entering its loop over a half-wired pipeline.
func TestRunReturnsErrorFromStart(t *testing.T) {
	c := testConfig(t, "run-err")
	a := newUncheckedAgent(c, &fakeVerifier{verified: map[string]bool{"run-err": true}}, &scriptedRunner{})
	a.cfg.Transits[0].ProbeTarget = "not-an-ip"

	if err := a.Run(context.Background()); err == nil {
		t.Fatal("Run returned nil, want the Start error")
	}
}

// --- health mesh (issue #3) --------------------------------------------------

// TestHealthzOmitsGossipWhenUnconfigured checks the opt-in default surfaces
// cleanly: a router with no mesh must not report a gossip object at all, so an
// operator cannot mistake "not configured" for "configured and broken".
func TestHealthzOmitsGossipWhenUnconfigured(t *testing.T) {
	c := testConfig(t, "no-mesh")
	a := newTestAgent(t, c, &fakeVerifier{verified: map[string]bool{"no-mesh": true}}, &scriptedRunner{})

	h := a.Health()
	if h.Gossip != nil {
		t.Errorf("Health.Gossip = %+v, want nil for a router with no mesh", h.Gossip)
	}
	if h.Features["gossip"] != featureUnavailable {
		t.Errorf("features[gossip] = %q, want unavailable", h.Features["gossip"])
	}
}

// TestAgentStartsMeshAndPublishesSnapshot is the wiring test behind the card's
// "broadcasts a periodic HealthMsg containing the sender's per-transit probe
// summary + decide view". It runs the agent's real Start against a real mesh (an
// ephemeral loopback port) and asserts that the payload the mesh broadcasts is
// built from the agent's own observations and decision state.
func TestAgentStartsMeshAndPublishesSnapshot(t *testing.T) {
	const name = "mesh-pub"
	c := testConfig(t, name)
	c.Gossip.Key = "ZXhhbXBsZS1rZXktbm90LWEtc2VjcmV0LTMyYnl0ZXM="
	if err := c.Validate(); err != nil {
		t.Fatalf("fixture does not validate with a mesh: %v", err)
	}

	a, err := New(Options{
		Config:   c,
		Verifier: &fakeVerifier{verified: map[string]bool{name: true}},
		Runner:   &scriptedRunner{reply: true, rttMs: 21.5},
		Interval: 5 * time.Millisecond,
		Log:      discardingLog(),
		Mesh:     newTestMesh(t, c),
		OnPeer:   func(gossip.Message) {},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Run, not Start: the decision loop's tick is what republishes the snapshot
	// after samples arrive, so the loop has to be running for the payload to be
	// current.
	runErr := make(chan error, 1)
	go func() { runErr <- a.Run(ctx) }()
	waitFor(t, time.Second, func() bool { return a.probed.Load() })
	waitFor(t, 2*time.Second, func() bool { return len(a.currentSnapshot().Transits) == 1 })

	snap := a.currentSnapshot()
	if snap.Transits[0].Name != name {
		t.Fatalf("snapshot transit = %q, want %q", snap.Transits[0].Name, name)
	}
	if snap.Transits[0].EwmaMs == nil || *snap.Transits[0].EwmaMs != 21.5 {
		t.Errorf("snapshot ewma = %v, want 21.5", snap.Transits[0].EwmaMs)
	}

	// The healthz surface must now report the mesh as configured and joined.
	h := a.Health()
	if h.Gossip == nil {
		t.Fatal("Health.Gossip = nil while a mesh is running")
	}
	if !h.Gossip.Enabled || !h.Gossip.Joined {
		t.Errorf("gossip health = %+v, want enabled and joined (single-node mesh)", h.Gossip)
	}
	if h.Features["gossip"] != featureOK {
		t.Errorf("features[gossip] = %q, want ok", h.Features["gossip"])
	}

	// Cancel first, then wait: Run's ctx-cancel path is what shuts the mesh down,
	// and leaving a mesh listening past the test would leak a port into the next
	// test in the package.
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// --- observe-only structural guard -------------------------------------------

// TestAgentIsObserveOnly is the structural half of the card's OBSERVE-ONLY
// constraint: no production file in this package may reach a router mutation
// path. A grep is a blunt instrument, but it is one that fails loudly if someone
// wires act into the observe-only agent by accident.
//
// The scan strips comments first. The package's own documentation has to be able
// to *name* the thing it promises not to do — "observe-only: no vtysh writes" is
// the clearest way to say it — and a guard that forbade the word would push the
// explanation out of the code and let a real call hide behind the same word. What
// is forbidden is a mutation in executable code.
func TestAgentIsObserveOnly(t *testing.T) {
	// Assembled at run time so the guard's own source cannot trip it.
	banned := []string{
		"vty" + "sh",            // the FRR config CLI: any use is an act path
		"exec." + "Command",     // a second exec seam besides the probe/pin runners
		"clear " + "bgp",        // the soft-clear the act package will issue
		"local-" + "preference", // the LP write act will perform
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		scanned++
		b, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", e.Name(), err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			for _, pat := range banned {
				if strings.Contains(code, pat) {
					t.Errorf("%s:%d contains %q in code — the agent is observe-only and must not reach a router mutation path",
						e.Name(), i+1, pat)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files; the guard is vacuous")
	}
}

// --- helpers -----------------------------------------------------------------

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// gatherMetrics returns the current samples of the transitd registry by name.
func gatherMetrics(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(fams))
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

// decisionSeriesNaming counts decisions_total series naming transit in any label.
func decisionSeriesNaming(fams map[string]*dto.MetricFamily, transit string) int {
	fam := fams["transitd_decisions_total"]
	if fam == nil {
		return 0
	}
	n := 0
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetValue() == transit {
				n++
				break
			}
		}
	}
	return n
}

// seriesValue returns the gauge value of the series carrying transit in its
// `transit` label.
func seriesValue(t *testing.T, fam *dto.MetricFamily, transit string) (float64, bool) {
	t.Helper()
	if fam == nil {
		return 0, false
	}
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == metrics.LabelTransit && lp.GetValue() == transit {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}
