package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gather collects the current samples from Registry, so tests assert on what an
// operator's scrape would actually see rather than on the in-process objects.
func gather(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(fams))
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

// gaugeValue returns the value of the single series with the given transit label.
func gaugeValue(t *testing.T, fam *dto.MetricFamily, transit string) (float64, bool) {
	t.Helper()
	if fam == nil {
		return 0, false
	}
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == LabelTransit && lp.GetValue() == transit {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// featureValue returns the value of the series with the given feature label.
func featureValue(t *testing.T, fam *dto.MetricFamily, feature string) (float64, bool) {
	t.Helper()
	if fam == nil {
		return 0, false
	}
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == LabelFeature && lp.GetValue() == feature {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestRegisterIsIdempotent asserts Register can be called any number of times —
// the agent's startup path and a test both call it — without a duplicate
// registration error.
func TestRegisterIsIdempotent(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := Register(); err != nil {
		t.Fatalf("second Register: %v", err)
	}
}

// TestPinVerifiedGauge checks the pin_verified gauge reflects both outcomes, and
// that a transit is present at 0 (not absent) when verification fails: an
// operator has to be able to tell "mis-pinned" from "not configured".
func TestPinVerifiedGauge(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	SetPinVerified("main", true)
	SetPinVerified("backup", false)

	fams := gather(t)
	fam := fams["transitd_pin_verified"]
	if fam == nil {
		t.Fatal("transitd_pin_verified not exported")
	}

	if v, ok := gaugeValue(t, fam, "main"); !ok || v != 1 {
		t.Errorf("main pin_verified = %v (present=%t), want 1", v, ok)
	}
	if v, ok := gaugeValue(t, fam, "backup"); !ok || v != 0 {
		t.Errorf("backup pin_verified = %v (present=%t), want a present 0", v, ok)
	}
}

// TestProbeGaugesAndSuppression is the metrics half of issue #1's suppression
// rule: an unverified transit's probe series must be DELETED, which is
// distinguishable from a healthy 0% series. A consumer seeing 0 would treat the
// transit as fine; a missing series forces the "no data" path.
func TestProbeGaugesAndSuppression(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	SetProbe("main", 12.5, 0)
	SetProbe("gone", 99, 100)

	fams := gather(t)
	lat := fams["transitd_probe_latency_ms"]
	loss := fams["transitd_probe_loss_pct"]
	if lat == nil || loss == nil {
		t.Fatal("probe gauges not exported")
	}
	if v, _ := gaugeValue(t, lat, "main"); v != 12.5 {
		t.Errorf("main latency = %v, want 12.5", v)
	}
	if v, _ := gaugeValue(t, loss, "gone"); v != 100 {
		t.Errorf("gone loss = %v, want 100", v)
	}

	// Suppress: delete the series, then assert it is GONE, not zero.
	ClearProbe("gone")
	fams = gather(t)
	for name, fam := range map[string]*dto.MetricFamily{
		"latency": fams["transitd_probe_latency_ms"],
		"loss":    fams["transitd_probe_loss_pct"],
	} {
		if _, ok := gaugeValue(t, fam, "gone"); ok {
			t.Errorf("%s still exports a series for the suppressed transit", name)
		}
	}
	// The verified transit must be untouched.
	if _, ok := gaugeValue(t, fams["transitd_probe_latency_ms"], "main"); !ok {
		t.Error("suppressing one transit removed another's series")
	}
}

// TestDecisionsCounterAuditTriple pins the decision counter's label contract from
// docs/design.md: transitd_decisions_total carries the from/to/reason triple, so
// the audit trail can answer "why did preference move". The from label renders a
// first adoption as "-" rather than an empty string, which would be awkward to
// query and easy to confuse with a missing label.
func TestDecisionsCounterAuditTriple(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	DecisionsTotal.WithLabelValues("-", "main", "initial adoption").Inc()
	DecisionsTotal.WithLabelValues("main", "backup", "challenger won margin for required cycles").Inc()

	fams := gather(t)
	fam := fams["transitd_decisions_total"]
	if fam == nil {
		t.Fatal("transitd_decisions_total not exported")
	}
	var sawAdoption bool
	for _, m := range fam.GetMetric() {
		labels := map[string]string{}
		for _, lp := range m.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels[LabelFrom] == "-" && labels[LabelTo] == "main" && labels[LabelReason] == "initial adoption" {
			sawAdoption = m.GetCounter().GetValue() > 0
		}
	}
	if !sawAdoption {
		t.Error("decisions_total does not carry the from/to/reason audit triple")
	}
}

// TestFeatureStateGauge is the metrics half of issue #5: feature_state carries
// the numeric contract (0 enabled, 1 degraded, 2 disabled) under the feature
// label, and is a gauge so a recovered feature can go back to 0 — a counter
// could only ever climb and would make "is it broken right now" unanswerable.
func TestFeatureStateGauge(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	SetFeatureState("probes", FeatureStateEnabled)
	SetFeatureState("gossip", FeatureStateDegraded)
	SetFeatureState("act", FeatureStateDisabled)

	fam := gather(t)["transitd_feature_state"]
	if fam == nil {
		t.Fatal("transitd_feature_state not exported")
	}
	if fam.GetType().String() != "GAUGE" {
		t.Errorf("transitd_feature_state type = %s, want GAUGE", fam.GetType())
	}
	for name, want := range map[string]float64{
		"probes": FeatureStateEnabled,
		"gossip": FeatureStateDegraded,
		"act":    FeatureStateDisabled,
	} {
		if v, ok := featureValue(t, fam, name); !ok || v != want {
			t.Errorf("feature_state{%s} = %v (present=%t), want %v", name, v, ok, want)
		}
	}
	// A feature can recover, and the gauge must follow. Re-gather: a gathered
	// family is a snapshot, so a stale value would be indistinguishable from a
	// gauge that never moved.
	SetFeatureState("gossip", FeatureStateEnabled)
	if v, _ := featureValue(t, gather(t)["transitd_feature_state"], "gossip"); v != FeatureStateEnabled {
		t.Errorf("feature_state{gossip} = %v after recovery, want %v", v, FeatureStateEnabled)
	}
}

// TestMetricNamesAreNamespaced is a cheap regression guard on the operator-facing
// contract: every metric this package registers is under the transitd_ prefix.
func TestMetricNamesAreNamespaced(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for _, c := range []prometheus.Collector{PinVerified, ProbeLatencyMs, ProbeLossPct, DecisionsTotal, FeatureState} {
		desc := make(chan *prometheus.Desc, 1)
		c.Describe(desc)
		close(desc)
		for d := range desc {
			if !strings.HasPrefix(d.String(), `Desc{fqName: "transitd_`) {
				t.Errorf("metric is not transitd_-namespaced: %s", d.String())
			}
		}
	}
}
