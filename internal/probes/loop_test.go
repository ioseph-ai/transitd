package probes

import (
	"context"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
	"github.com/ioseph-ai/transitd/internal/pinning"
)

func testTransit() config.Transit {
	return config.Transit{
		Name:            "main",
		ProbeSource:     "192.0.2.1",
		ProbeTarget:     "203.0.113.5",
		EgressInterface: "eth-transit",
		ProbeInterval:   time.Second,
	}
}

func newTestLoop(t *testing.T, r Runner) *Loop {
	t.Helper()
	l, err := NewLoop(testTransit(), r)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	l.Clock = func() time.Time { return fixed }
	l.Variant = VariantIputils // skip detection in the unit tier
	return l
}

// TestLoopEwmaConverges checks the EWMA is actually smoothing: a step from 100ms
// to 10ms must move part way, not snap, and must converge toward the new value.
func TestLoopEwmaConverges(t *testing.T) {
	f := &fakePing{scripts: []scriptedRun{replyFixture("100")}}
	l := newTestLoop(t, f)
	l.Alpha = 0.5

	first := l.Probe(context.Background())
	if first.LatencyMs != 100 {
		t.Fatalf("first sample latency = %v, want 100 (seed value)", first.LatencyMs)
	}

	f.scripts = []scriptedRun{replyFixture("10")}
	second := l.Probe(context.Background())
	// 0.5*10 + 0.5*100 = 55
	if second.LatencyMs != 55 {
		t.Errorf("second sample latency = %v, want 55", second.LatencyMs)
	}

	// Converges downward toward 10 within a handful of cycles.
	for i := 0; i < 20; i++ {
		l.Probe(context.Background())
	}
	lat, _ := l.Snapshot()
	if lat > 11 || lat < 10 {
		t.Errorf("after convergence latency = %v, want ~10", lat)
	}
}

// TestLoopLossWindow checks the rolling loss window: it averages over the last
// N cycles and forgets older ones.
func TestLoopLossWindow(t *testing.T) {
	f := &fakePing{scripts: []scriptedRun{timeoutFixture(), timeoutFixture(), replyFixture("5"), replyFixture("5")}}
	l := newTestLoop(t, f)
	l.Window = 4

	// 2 timeouts, 2 replies = 50% loss.
	var last Sample
	for i := 0; i < 4; i++ {
		last = l.Probe(context.Background())
	}
	if last.LossPct != 50 {
		t.Errorf("loss = %v, want 50", last.LossPct)
	}
	if last.Sent != 4 || last.Received != 2 {
		t.Errorf("counts = %d/%d, want 4/2", last.Sent, last.Received)
	}

	// Four more replies push the timeouts out of the window entirely.
	f.scripts = []scriptedRun{replyFixture("5")}
	for i := 0; i < 4; i++ {
		last = l.Probe(context.Background())
	}
	if last.LossPct != 0 {
		t.Errorf("loss after window rolled = %v, want 0", last.LossPct)
	}
	if last.Sent != 4 {
		t.Errorf("window size = %d, want capped at 4", last.Sent)
	}
}

// TestLoopLatencyNaNBeforeFirstReply pins the "no data" contract: latency is NaN
// until a reply arrives, so a consumer can distinguish "no measurement" from
// "zero milliseconds".
func TestLoopLatencyNaNBeforeFirstReply(t *testing.T) {
	f := &fakePing{scripts: []scriptedRun{timeoutFixture()}}
	l := newTestLoop(t, f)

	s := l.Probe(context.Background())
	if !isNaN(s.LatencyMs) {
		t.Errorf("latency = %v, want NaN before any reply", s.LatencyMs)
	}
	if s.LossPct != 100 {
		t.Errorf("loss = %v, want 100", s.LossPct)
	}
}

// TestLoopFragNeededIsNotLoss is the loop-level version of the parser's safety
// property: a fragmentation error must not be recorded as packet loss.
func TestLoopFragNeededIsNotLoss(t *testing.T) {
	frag := scriptedRun{
		stdout: "PING 198.51.100.5 (198.51.100.5) 2000(2028) bytes of data.\n" +
			"ping: sendmsg: Message too long\n\n" +
			"--- 198.51.100.5 ping statistics ---\n1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n",
		exit: 1,
	}
	f := &fakePing{scripts: []scriptedRun{frag}}
	l := newTestLoop(t, f)
	l.Window = 4

	s := l.Probe(context.Background())
	if s.Outcome != OutcomeFragNeeded {
		t.Fatalf("outcome = %v, want frag-needed", s.Outcome)
	}
	if s.LossPct != 0 {
		t.Errorf("loss = %v, want 0 (a frag-needed probe is not loss)", s.LossPct)
	}
}

// sampleSink collects emitted samples under a mutex so a test can read them
// while a probe goroutine is still running (go test -race runs in CI).
type sampleSink struct {
	mu  sync.Mutex
	got []Sample
}

func (s *sampleSink) emit(smp Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, smp)
}

func (s *sampleSink) snapshot() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Sample, len(s.got))
	copy(out, s.got)
	return out
}

// TestLoopRunEmitsAndStops checks Run probes once immediately and stops cleanly
// on cancellation.
func TestLoopRunEmitsAndStops(t *testing.T) {
	f := &fakePing{scripts: []scriptedRun{replyFixture("7")}}
	l := newTestLoop(t, f)
	l.Interval = 10 * time.Millisecond

	samples := make(chan Sample, 4)
	l.Emit = func(s Sample) { samples <- s }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.Run(ctx)
		close(done)
	}()

	select {
	case s := <-samples:
		if s.Transit != "main" {
			t.Errorf("sample transit = %q, want main", s.Transit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not emit an immediate sample")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancellation")
	}
}

// TestSupervisorSuppressesUnverifiedTransits is THE suppression test from issue
// #1: a transit that fails pin verification must produce no probe samples, no
// loop, and no metrics. The assertion is on the absence of the sample stream,
// not on a filter inside a consumer.
func TestSupervisorSuppressesUnverifiedTransits(t *testing.T) {
	f := &fakePing{scripts: []scriptedRun{replyFixture("5")}}

	sink := &sampleSink{}
	sup := &Supervisor{
		Runner: f,
		Verify: StaticVerify(map[string]bool{"good": true, "bad": false}),
		Emit:   sink.emit,
	}

	transits := []config.Transit{
		{Name: "good", ProbeSource: "192.0.2.1", ProbeTarget: "203.0.113.5", EgressInterface: "eth0", ProbeInterval: time.Second},
		{Name: "bad", ProbeSource: "192.0.2.2", ProbeTarget: "203.0.113.6", EgressInterface: "eth1", ProbeInterval: time.Second},
	}

	good, err := NewLoop(transits[0], f)
	if err != nil {
		t.Fatalf("NewLoop(good): %v", err)
	}
	bad, err := NewLoop(transits[1], f)
	if err != nil {
		t.Fatalf("NewLoop(bad): %v", err)
	}
	good.Variant, bad.Variant = VariantIputils, VariantIputils
	good.Interval, bad.Interval = 5*time.Millisecond, 5*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.StartWithLoops(ctx, transits, map[string]*Loop{"good": good, "bad": bad}); err != nil {
		t.Fatalf("StartWithLoops: %v", err)
	}

	// Let the good loop run a few cycles.
	time.Sleep(60 * time.Millisecond)

	if !sup.Verified("good") {
		t.Error("good transit not reported verified")
	}
	if sup.Verified("bad") {
		t.Error("bad transit reported verified")
	}

	// Every sample must come from the verified transit. A single sample from
	// "bad" fails the test.
	got := sink.snapshot()
	for _, s := range got {
		if s.Transit != "good" {
			t.Fatalf("received a sample from unverified transit %q: %+v", s.Transit, s)
		}
	}
	if len(got) == 0 {
		t.Fatal("verified transit produced no samples")
	}
}

// TestSupervisorUnverifiedTransitNeverStarted asserts the stronger structural
// property behind the suppression: StartWithLoops never invokes a loop for an
// unverified transit, so no ping is ever sent on its behalf.
func TestSupervisorUnverifiedTransitNeverStarted(t *testing.T) {
	f := &fakePing{scripts: []scriptedRun{replyFixture("5")}}
	sink := &sampleSink{}
	sup := &Supervisor{
		Runner: f,
		Verify: StaticVerify(map[string]bool{"bad": false}),
		Emit:   sink.emit,
	}
	tr := config.Transit{Name: "bad", ProbeSource: "192.0.2.2", ProbeTarget: "203.0.113.6", EgressInterface: "eth1"}
	bad, err := NewLoop(tr, f)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	bad.Variant = VariantIputils

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.StartWithLoops(ctx, []config.Transit{tr}, map[string]*Loop{"bad": bad}); err != nil {
		t.Fatalf("StartWithLoops: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	if n := len(sink.snapshot()); n != 0 {
		t.Fatalf("unverified transit emitted %d samples, want 0", n)
	}
	if n := f.calls; n != 0 {
		t.Fatalf("unverified transit ran the ping binary %d times, want 0", n)
	}
}

// TestSupervisorStartRejectsVerifiedTransitWithBadConfig checks the one genuine
// error path: a transit that PASSED verification but whose probe config cannot
// build a loop is a startup error, not a silent suppression.
func TestSupervisorStartRejectsVerifiedTransitWithBadConfig(t *testing.T) {
	sup := &Supervisor{
		Runner: &fakePing{},
		Verify: StaticVerify(map[string]bool{"broken": true}),
	}
	err := sup.Start(context.Background(), []config.Transit{
		{Name: "broken", ProbeSource: "192.0.2.1", ProbeTarget: "not-an-ip", EgressInterface: "eth0"},
	})
	if err == nil {
		t.Fatal("expected an error for a verified transit with an invalid probe target")
	}
}

// TestSupervisorUnverifiedExportsNoMetrics is the metrics half of suppression:
// after Start, an unverified transit must have a pin_verified=0 series but NO
// probe latency/loss series at all, while a verified transit has both.
func TestSupervisorUnverifiedExportsNoMetrics(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("metrics.Register: %v", err)
	}

	f := &fakePing{scripts: []scriptedRun{replyFixture("5")}}
	sink := &sampleSink{}
	sup := &Supervisor{
		Runner: f,
		Verify: StaticVerify(map[string]bool{"good": true, "bad": false}),
		Emit:   sink.emit,
	}
	transits := []config.Transit{
		{Name: "good", ProbeSource: "192.0.2.1", ProbeTarget: "203.0.113.5", EgressInterface: "eth0"},
		{Name: "bad", ProbeSource: "192.0.2.2", ProbeTarget: "203.0.113.6", EgressInterface: "eth1"},
	}
	good, err := NewLoop(transits[0], f)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	good.Variant = VariantIputils

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.StartWithLoops(ctx, transits, map[string]*Loop{"good": good, "bad": good}); err != nil {
		t.Fatalf("StartWithLoops: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // let one cycle emit

	fams := gatherMetrics(t)
	pin := fams["transitd_pin_verified"]
	if v, ok := seriesValue(t, pin, "bad"); !ok || v != 0 {
		t.Errorf("bad pin_verified = %v (present=%t), want a present 0", v, ok)
	}
	if _, ok := seriesValue(t, fams["transitd_probe_loss_pct"], "bad"); ok {
		t.Error("unverified transit exported a probe_loss_pct series, want none")
	}
	if _, ok := seriesValue(t, fams["transitd_probe_latency_ms"], "bad"); ok {
		t.Error("unverified transit exported a probe_latency_ms series, want none")
	}
	if _, ok := seriesValue(t, fams["transitd_probe_latency_ms"], "good"); !ok {
		t.Error("verified transit did not export a probe_latency_ms series")
	}
}

// gatherMetrics returns the current samples of the transitd metric registry,
// keyed by metric name. It mirrors the helper in internal/metrics; duplicated
// here so this package's test does not depend on metrics' test-only helpers.
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

// seriesValue returns the gauge value carrying transit in its `transit` label.
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

// TestSupervisorResultsCopied checks Results returns a copy, so a caller cannot
// mutate the supervisor's state through the map.
func TestSupervisorResultsCopied(t *testing.T) {
	sup := &Supervisor{
		Runner: &fakePing{},
		Verify: func(_ context.Context, tr config.Transit) pinning.Result {
			return pinning.Result{Transit: tr.Name, Verified: true, EgressIf: tr.EgressInterface, Reason: "ok"}
		},
	}
	if err := sup.Start(context.Background(), []config.Transit{
		{Name: "a", ProbeSource: "192.0.2.1", ProbeTarget: "198.51.100.5", EgressInterface: "eth0", ProbeInterval: time.Hour},
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m := sup.Results()
	m["a"] = pinning.Result{Verified: false}
	if !sup.Verified("a") {
		t.Error("mutating the returned map changed the supervisor's state")
	}
}
