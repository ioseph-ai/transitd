package health

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// TestMain registers the transitd collectors once. In the running agent
// metrics.Register is the agent's job; here it is setup, because featureState
// asserts on what a scrape of the shared registry actually contains, and an
// unregistered collector contributes nothing to Gather regardless of what the
// registry object holds.
func TestMain(m *testing.M) {
	if err := metrics.Register(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// --- a slog handler that records what was logged -----------------------------
//
// The card's unit test must assert the log line, not just the state: a registry
// that flipped healthz to degraded but never warned an operator is exactly the
// silent failure issue #5 exists to eliminate, and an assertion on state alone
// would pass it. Recording the records (level + message + attrs) is the only way
// to make that assertion.

type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, rec slog.Record) error {
	attrs := make(map[string]string, rec.NumAttrs())
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, capturedRecord{level: rec.Level, msg: rec.Message, attrs: attrs})
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) snapshot() []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]capturedRecord, len(h.records))
	copy(out, h.records)
	return out
}

func captureLog(t *testing.T) (*slog.Logger, *captureHandler) {
	t.Helper()
	h := &captureHandler{}
	return slog.New(h), h
}

// --- metric assertion --------------------------------------------------------

// featureState reads transitd_feature_state{feature=name} from the shared
// registry. Feature names in these tests are prefixed per test so the
// process-global registry does not let one test's series leak into another's
// assertion.
func featureState(t *testing.T, name string) (int, bool) {
	t.Helper()
	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "transitd_feature_state" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == metrics.LabelFeature && lp.GetValue() == name {
					return int(m.GetGauge().GetValue()), true
				}
			}
		}
	}
	return 0, false
}

// --- the card's unit test ----------------------------------------------------

// TestBrokenFeatureFlipsHealthToDegradedMetricAndLog is the card's unit test,
// stated as its three obligations: a capability that breaks must (1) take the
// overall status to degraded, (2) export transitd_feature_state=2 with its
// reason visible, and (3) emit exactly one WARN naming it. The hook is how the
// test proves the warning path ran rather than merely computing a state.
func TestBrokenFeatureFlipsHealthToDegradedMetricAndLog(t *testing.T) {
	const feat = "ut-broken-probes"
	log, logh := captureLog(t)
	var transitions []Transition
	r := New(Options{Log: log, Hook: func(tr Transition) { transitions = append(transitions, tr) }})

	// A healthy capability first, so the transition into failure is a real one
	// and the status is "ok" before the break.
	r.Register(feat, Enabled, "")
	if got := r.Status(); got != StatusOK {
		t.Fatalf("status after registering an enabled feature = %q, want %q", got, StatusOK)
	}

	// Now break it.
	const reason = "ping(8) binary not found in PATH"
	r.Set(feat, Disabled, reason)

	if got := r.Status(); got != StatusDegraded {
		t.Errorf("status = %q, want %q after a feature was disabled", got, StatusDegraded)
	}

	// Health payload carries the state AND the reason: a state with no reason
	// leaves an operator knowing something is wrong but not what to fix.
	f, ok := r.Get(feat)
	if !ok {
		t.Fatalf("feature %q not registered", feat)
	}
	if f.State != Disabled {
		t.Errorf("feature state = %q, want %q", f.State, Disabled)
	}
	if f.Reason != reason {
		t.Errorf("feature reason = %q, want %q", f.Reason, reason)
	}

	// Metric: disabled is 2, not 1.
	if v, present := featureState(t, feat); !present || v != metrics.FeatureStateDisabled {
		t.Errorf("transitd_feature_state{%s}=%d (present=%t), want %d", feat, v, present, metrics.FeatureStateDisabled)
	}

	// Log: exactly one line, at WARN, naming the feature and the reason.
	recs := logh.snapshot()
	if len(recs) != 1 {
		t.Fatalf("logged %d records for one state change, want exactly 1: %+v", len(recs), recs)
	}
	rec := recs[0]
	if rec.level != slog.LevelWarn {
		t.Errorf("log level = %v, want WARN", rec.level)
	}
	if rec.attrs["feature"] != feat {
		t.Errorf("log attrs[feature] = %q, want %q", rec.attrs["feature"], feat)
	}
	if rec.attrs["reason"] != reason {
		t.Errorf("log attrs[reason] = %q, want %q", rec.attrs["reason"], reason)
	}

	// Hook fired once, with the transition recorded.
	if len(transitions) != 1 {
		t.Fatalf("hook fired %d times, want 1", len(transitions))
	}
	if transitions[0].Prev != Enabled || transitions[0].Feature.State != Disabled {
		t.Errorf("transition = %+v, want Enabled -> Disabled", transitions[0])
	}
}

// TestMetricContract pins the three numeric values issue #5 fixes: 0 enabled,
// 1 degraded, 2 disabled. A dashboard or alert rule keys on these, so they are a
// contract, not an implementation detail.
func TestMetricContract(t *testing.T) {
	cases := []struct {
		state State
		want  int
	}{
		{Enabled, metrics.FeatureStateEnabled},
		{Degraded, metrics.FeatureStateDegraded},
		{Disabled, metrics.FeatureStateDisabled},
	}
	for _, tc := range cases {
		name := "ut-contract-" + string(tc.state)
		r := New(Options{Log: slog.New(slog.NewTextHandler(discard{}, nil))})
		r.Register(name, Enabled, "")
		r.Set(name, tc.state, "why")
		if v, ok := featureState(t, name); !ok || v != tc.want {
			t.Errorf("state %q exported %d (present=%t), want %d", tc.state, v, ok, tc.want)
		}
	}
}

// TestDegradedIsNotDisabled checks "degraded" is a distinct state that still
// takes the status down: a capability that is impaired but running must be
// visible, and must not be confused with one that stopped.
func TestDegradedIsNotDisabled(t *testing.T) {
	const feat = "ut-degraded"
	log, logh := captureLog(t)
	r := New(Options{Log: log})
	r.Register(feat, Enabled, "")
	r.Set(feat, Degraded, "gossip join failing, mesh incomplete")

	if got := r.Status(); got != StatusDegraded {
		t.Errorf("status = %q, want degraded", got)
	}
	if recs := logh.snapshot(); len(recs) != 1 || recs[0].level != slog.LevelWarn {
		t.Errorf("degraded transition should warn once, got %+v", recs)
	}
}

// TestFirstRegistrationInFailedStateWarns is the "no silent self-disable"
// guarantee at its sharpest: a feature that is ALREADY broken when the process
// starts must warn. If registration were exempt from the transition check, a
// build that boots straight into a missing ping binary would say nothing.
func TestFirstRegistrationInFailedStateWarns(t *testing.T) {
	const feat = "ut-boot-broken"
	log, logh := captureLog(t)
	var transitions []Transition
	r := New(Options{Log: log, Hook: func(tr Transition) { transitions = append(transitions, tr) }})

	r.Register(feat, Disabled, "ping(8) binary missing in image")

	if got := r.Status(); got != StatusDegraded {
		t.Errorf("status = %q, want degraded for a feature broken at startup", got)
	}
	recs := logh.snapshot()
	if len(recs) != 1 || recs[0].level != slog.LevelWarn {
		t.Fatalf("registering a broken feature must warn once, got %+v", recs)
	}
	if len(transitions) != 1 || transitions[0].Prev != Enabled {
		t.Errorf("transition = %+v, want an implied Enabled -> Disabled", transitions)
	}
}

// TestRepeatedSameStateLogsOnce is the anti-flood half of the design: a probe
// loop re-asserts the same missing binary every cycle, and one warning per cycle
// is noise an operator filters out. The state may be reported many times; the
// warning fires once. The metric, however, is refreshed every time.
func TestRepeatedSameStateLogsOnce(t *testing.T) {
	const feat = "ut-repeat"
	log, logh := captureLog(t)
	r := New(Options{Log: log})

	for i := 0; i < 5; i++ {
		r.Set(feat, Disabled, "still no ping")
	}
	if recs := logh.snapshot(); len(recs) != 1 {
		t.Errorf("logged %d times for five identical reports, want 1", len(recs))
	}
	if v, ok := featureState(t, feat); !ok || v != metrics.FeatureStateDisabled {
		t.Errorf("metric = %d (present=%t), want disabled", v, ok)
	}
	// A changed reason at the same state updates silently — useful detail in
	// the payload, still no second warning.
	r.Set(feat, Disabled, "still no ping (checked again)")
	if recs := logh.snapshot(); len(recs) != 1 {
		t.Errorf("a reason-only change logged again, want still 1 record")
	}
	if f, _ := r.Get(feat); f.Reason != "still no ping (checked again)" {
		t.Errorf("reason = %q, want the latest", f.Reason)
	}
}

// TestRecoveryLogsInfo covers the return path: a feature that starts working
// again must be visible, logged at INFO (recovery is good news, not a warning),
// and must restore the overall status to ok once nothing is broken.
func TestRecoveryLogsInfo(t *testing.T) {
	const feat = "ut-recover"
	log, logh := captureLog(t)
	r := New(Options{Log: log})

	r.Register(feat, Enabled, "")
	r.Set(feat, Disabled, "ping gone")
	r.Set(feat, Enabled, "")

	recs := logh.snapshot()
	if len(recs) != 2 {
		t.Fatalf("logged %d records, want 2 (break + recover)", len(recs))
	}
	if recs[0].level != slog.LevelWarn {
		t.Errorf("break logged at %v, want WARN", recs[0].level)
	}
	if recs[1].level != slog.LevelInfo {
		t.Errorf("recovery logged at %v, want INFO", recs[1].level)
	}
	if got := r.Status(); got != StatusOK {
		t.Errorf("status = %q, want ok after recovery", got)
	}
	if v, _ := featureState(t, feat); v != metrics.FeatureStateEnabled {
		t.Errorf("metric = %d after recovery, want enabled", v)
	}
}

// TestUnregisteredFeatureDoesNotDegradeStatus pins the boundary that keeps
// "degraded" actionable: the registry lists capabilities this build HAS and can
// self-disable, not roadmap items. A feature that was never registered (a
// planned subsystem, a build without the gossip mesh) must not drag the status
// down, or the endpoint is permanently degraded and meaningless.
func TestUnregisteredFeatureDoesNotDegradeStatus(t *testing.T) {
	r := New(Options{Log: slog.New(slog.NewTextHandler(discard{}, nil))})
	r.Register("ut-present", Enabled, "")
	if got := r.Status(); got != StatusOK {
		t.Errorf("status = %q, want ok when the only registered feature is enabled", got)
	}
	if _, ok := r.Get("w4-not-in-this-build"); ok {
		t.Error("an unregistered feature reported as present")
	}
}

// TestSnapshotIsSortedAndMapIsKeyed checks the two read shapes the agent embeds
// in its payload: a sorted slice (deterministic, diffable) and a name-keyed map.
func TestSnapshotIsSortedAndMapIsKeyed(t *testing.T) {
	log := slog.New(slog.NewTextHandler(discard{}, nil))
	r := New(Options{Log: log})
	r.Register("ut-zeta", Enabled, "")
	r.Register("ut-alpha", Degraded, "impaired")
	r.Register("ut-mid", Enabled, "")

	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot has %d entries, want 3", len(snap))
	}
	if snap[0].Name != "ut-alpha" || snap[2].Name != "ut-zeta" {
		t.Errorf("snapshot is not name-sorted: %s ... %s", snap[0].Name, snap[2].Name)
	}
	m := r.Map()
	if m["ut-alpha"].State != Degraded || m["ut-zeta"].State != Enabled {
		t.Errorf("map = %+v", m)
	}
}

// discard is an io.Writer that drops everything, for tests whose concern is the
// state and not the log.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// TestRegistryUpdatesAllThreeSurfacesTogether makes the "one Set, three
// surfaces" property concrete: healthz state, metric and log all move on a
// single call, so no code path can update one without the others.
func TestRegistryUpdatesAllThreeSurfacesTogether(t *testing.T) {
	const feat = "ut-together"
	log, logh := captureLog(t)
	var seen []State
	r := New(Options{Log: log, Hook: func(tr Transition) { seen = append(seen, tr.Feature.State) }})
	r.Set(feat, Disabled, "probes disabled")

	if _, ok := r.Get(feat); !ok {
		t.Error("state not recorded")
	}
	if _, ok := featureState(t, feat); !ok {
		t.Error("metric not exported")
	}
	if len(logh.snapshot()) == 0 {
		t.Error("no log line")
	}
	if len(seen) != 1 {
		t.Errorf("hook fired %d times, want 1", len(seen))
	}
	if !strings.Contains(logh.snapshot()[0].attrs["reason"], "probes disabled") {
		t.Error("log line does not carry the reason")
	}
}
