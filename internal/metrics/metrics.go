// Package metrics owns transitd's Prometheus instrumentation. It is
// deliberately small: one gauge per observable, no counters or histograms
// until a feature needs them. The metric names and label sets are the
// contract the operator dashboards read, so they are declared here once and
// never constructed ad hoc at a call site.
package metrics

import (
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace for every transitd metric.
const namespace = "transitd"

// LabelTransit is the single label every probe/pin metric carries: the
// configured transit name, not an interface or address. An operator reads
// dashboards per transit; the interface behind a transit can change without
// the series identity changing.
const LabelTransit = "transit"

// Decision counter labels. They mirror docs/design.md's audit contract
// (transitd_decisions_total{from,to,reason}): the audit trail an operator reads
// to answer "why did preference move, and when".
const (
	LabelFrom   = "from"
	LabelTo     = "to"
	LabelReason = "reason"
)

// Registry is the collector registry transitd exports. It is separate from
// prometheus.DefaultRegisterer so tests can construct an isolated registry and
// so the agent can add Go/process collectors explicitly rather than inheriting
// whatever a linked-in dependency registered.
var Registry = prometheus.NewRegistry()

var (
	// PinVerified is 1 when the startup route-lookup verification agreed with
	// the transit's configured egress interface, 0 when it did not. A transit
	// at 0 exports no probe samples (issue #1).
	PinVerified = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "pin_verified",
		Help:      "1 when a transit's probes were verified to egress the expected interface at startup, 0 otherwise.",
	}, []string{LabelTransit})

	// ProbeLatencyMs is the EWMA of successful ICMP probe round-trip times in
	// milliseconds. Absent for a transit that exports no samples.
	//
	// The `_ms` suffix deviates from the Prometheus base-unit convention (which
	// prefers milliseconds expressed as `_seconds`); the metric name is fixed by
	// issue #1's operator contract and the dashboards key on it, so the deviation
	// is deliberate and documented rather than accidental.
	ProbeLatencyMs = prometheus.NewGaugeVec(prometheus.GaugeOpts{ //nolint:promlinter // name fixed by issue #1's metric contract
		Namespace: namespace,
		Name:      "probe_latency_ms",
		Help:      "EWMA of ICMP probe round-trip time in milliseconds per transit.",
	}, []string{LabelTransit})

	// ProbeLossPct is the packet loss percentage over the rolling probe window.
	ProbeLossPct = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "probe_loss_pct",
		Help:      "ICMP probe packet loss over the rolling window, percent, per transit.",
	}, []string{LabelTransit})

	// DecisionsTotal counts decisions that WOULD change the rank-1 transit,
	// labeled by the from/to/reason audit triple from docs/design.md. It is a
	// counter, not a gauge, because the question it answers is "how often and
	// why", which a gauge cannot. In observe-only builds nothing acts on these
	// decisions (issue #4); the counter is the durable record that the agent
	// reached a verdict, whether or not a future act package can apply it.
	DecisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "decisions_total",
		Help:      "Decisions that would change the rank-1 transit, by from/to/reason. Observe-only: not applied.",
	}, []string{LabelFrom, LabelTo, LabelReason})
)

var registerOnce sync.Once

// Register installs every metric into Registry. It is idempotent, so it is
// safe to call from both the agent and a test. It returns the first error that
// is not an already-registered collision.
func Register() error {
	var err error
	registerOnce.Do(func() {
		for _, c := range []prometheus.Collector{PinVerified, ProbeLatencyMs, ProbeLossPct, DecisionsTotal} {
			rerr := Registry.Register(c)
			if rerr == nil {
				continue
			}
			var already prometheus.AlreadyRegisteredError
			if errors.As(rerr, &already) {
				continue
			}
			err = fmt.Errorf("registering %T: %w", c, rerr)
			return
		}
	})
	return err
}

// SetPinVerified records the outcome of a pin verification for one transit.
func SetPinVerified(transit string, verified bool) {
	if verified {
		PinVerified.WithLabelValues(transit).Set(1)
		return
	}
	PinVerified.WithLabelValues(transit).Set(0)
}

// SetProbe records one transit's latest latency/loss observation.
func SetProbe(transit string, latencyMs, lossPct float64) {
	ProbeLatencyMs.WithLabelValues(transit).Set(latencyMs)
	ProbeLossPct.WithLabelValues(transit).Set(lossPct)
}

// SetProbeLossOnly records loss without a latency sample. It is used while a
// transit has not yet produced a single reply: latency is unknown, and exporting
// it as 0 would make a dead transit look infinitely fast to a dashboard.
func SetProbeLossOnly(transit string, lossPct float64) {
	ProbeLossPct.WithLabelValues(transit).Set(lossPct)
}

// ClearProbe deletes a transit's probe series. It is the suppression primitive
// from issue #1: a transit that is unverified (or goes away) exports no probe
// samples at all, which is distinguishable from a transit that reports 0% loss
// — a deleted series is missing, a zeroed series would look healthy.
func ClearProbe(transit string) {
	ProbeLatencyMs.DeleteLabelValues(transit)
	ProbeLossPct.DeleteLabelValues(transit)
}
