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

// LabelSchemaVersion labels the schema-version receive counter. Its value is the
// schema_version of the gossiped envelope, as a decimal string. It is a label
// rather than a per-version metric family because the point an operator reads is
// "which versions are still on the wire", and a single series with one label
// answers it directly — including for versions this build does not know, which
// is exactly the rollout signal the append-only schema exists to make visible.
const LabelSchemaVersion = "version"

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

	// GossipMembers is the number of alive nodes in the gossip mesh, including
	// this router. A value of 1 is a healthy single-agent mesh, not an error;
	// the mesh growing past 1 is what makes the merged health view useful, and
	// the number falling back to 1 is the partition signal an operator watches.
	GossipMembers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "gossip_members",
		Help:      "Number of alive nodes in the gossip mesh, including this router.",
	})

	// GossipRx counts every message that reaches the delegate's receive path,
	// including frames that fail to decode. It is incremented before Decode so a
	// peer streaming garbage is visible as rx traffic rather than silently
	// disappearing; the per-version counter below is what breaks the rate down by
	// schema, and only increments once the envelope decoded.
	GossipRx = prometheus.NewCounter(prometheus.CounterOpts{ //nolint:promlinter // name fixed by issue #3's metric contract
		Namespace: namespace,
		Name:      "gossip_rx",
		Help:      "Gossip messages received from the mesh, including frames that failed to decode.",
	})

	// GossipTx counts gossip health messages this router broadcast onto the mesh.
	GossipTx = prometheus.NewCounter(prometheus.CounterOpts{ //nolint:promlinter // name fixed by issue #3's metric contract
		Namespace: namespace,
		Name:      "gossip_tx",
		Help:      "Gossip health messages broadcast by this router.",
	})

	// GossipSchemaRx counts received health messages by the schema_version of
	// their envelope. A series for a version this build does not know is the
	// rollout signal the append-only policy is built around: it proves a newer
	// peer is on the wire and that this node is ignoring, not erroring on, its
	// unknown fields.
	GossipSchemaRx = prometheus.NewCounterVec(prometheus.CounterOpts{ //nolint:promlinter // name fixed by issue #3's metric contract
		Namespace: namespace,
		Name:      "gossip_schema_rx",
		Help:      "Gossip health messages received, by envelope schema_version.",
	}, []string{LabelSchemaVersion})

	// CtrlAuthFail counts control-channel requests rejected for a missing or
	// wrong shared key. It is the security signal an operator watches: a steady
	// trickle is a misconfigured local client, a burst is something else probing
	// the socket. It is a counter, not a gauge, because "how many" is the
	// question; every failure is also audit-logged with the peer's identity.
	CtrlAuthFail = prometheus.NewCounter(prometheus.CounterOpts{ //nolint:promlinter // name fixed by issue #2's metric contract
		Namespace: namespace,
		Name:      "ctrl_auth_fail",
		Help:      "Control-channel requests rejected for a missing or wrong shared key.",
	})

	// CtrlRateLimited counts control-channel requests shed by the per-method
	// token bucket. A client that sees this is retrying too fast; it is not an
	// auth failure and must be distinguishable from one.
	CtrlRateLimited = prometheus.NewCounter(prometheus.CounterOpts{ //nolint:promlinter // name fixed by issue #2's metric contract
		Namespace: namespace,
		Name:      "ctrl_rate_limited",
		Help:      "Control-channel requests rejected by the per-method rate limit (not an auth failure).",
	})

	// CtrlSetPrimary records the last desired-primary preference requested over
	// the control channel, as a gauge holding the desired rank: 1 for the transit
	// the operator named, 0 for every other configured transit. Observe-only in
	// this MVP — the agent records and logs the preference but applies nothing
	// (issue #4), so this metric is the durable record that the request arrived.
	CtrlSetPrimary = prometheus.NewGaugeVec(prometheus.GaugeOpts{ //nolint:promlinter // name fixed by issue #2's metric contract
		Namespace: namespace,
		Name:      "ctrl_set_primary",
		Help:      "Desired primary preference set over the control channel: 1 for the requested transit, 0 otherwise. Observe-only: not applied.",
	}, []string{LabelTransit})
)

var registerOnce sync.Once

// Register installs every metric into Registry. It is idempotent, so it is
// safe to call from both the agent and a test. It returns the first error that
// is not an already-registered collision.
func Register() error {
	var err error
	registerOnce.Do(func() {
		for _, c := range []prometheus.Collector{
			PinVerified, ProbeLatencyMs, ProbeLossPct, DecisionsTotal,
			GossipMembers, GossipRx, GossipTx, GossipSchemaRx,
			CtrlAuthFail, CtrlRateLimited, CtrlSetPrimary,
		} {
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
