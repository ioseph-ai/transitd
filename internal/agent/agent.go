// Package agent wires transitd's observation pipeline: a validated config, the
// startup pin-verification preflight, one probe loop per VERIFIED transit, probe
// samples into decide.Evaluate, and the metrics/healthz surface.
//
// It is OBSERVE-ONLY. Nothing in this package writes to vtysh, and nothing
// reachable from it applies anything to the router: a decision is computed by
// an existing, unchanged decide.Engine, then logged and counted — never
// applied. The act package that would apply one is future work (issue #4), and
// TestAgentIsObserveOnly enforces the "no vtysh" half of that constraint
// structurally rather than by convention.
//
// The wiring order is the safety order from issue #1: verify every transit's
// pin first, then start a loop only for the ones that verified. An unverified
// transit therefore has no loop, emits no sample, appears in no decision, and
// is visible only as transitd_pin_verified{transit}=0 plus a degraded healthz.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/decide"
	"github.com/ioseph-ai/transitd/internal/metrics"
	"github.com/ioseph-ai/transitd/internal/pinning"
	"github.com/ioseph-ai/transitd/internal/probes"
)

// DefaultInterval is the decision-evaluation cadence used when Options.Interval
// is unset. It matches the default probe interval: deciding faster than samples
// arrive only re-decides on unchanged data.
const DefaultInterval = 30 * time.Second

// Health status values.
const (
	statusOK       = "ok"
	statusDegraded = "degraded"
)

// Feature capability values. Issue #5 formalises both the vocabulary and the
// per-failure-mode table this skeleton is the first user of.
const (
	featureOK          = "ok"
	featureUnavailable = "unavailable"
)

// Health is the /healthz payload. It is the early form of issue #5's
// capability/health surfacing: the point is that a feature which cannot work
// says so, rather than going quiet.
type Health struct {
	// Status is "degraded" when any configured transit's pin is unverified.
	Status string `json:"status"`
	// PinVerified has one entry per configured transit — never a missing key
	// for an unverified one. A transit that is present but false is
	// "mis-pinned"; a transit that is absent from the config is a different
	// thing, and the map keeps them distinguishable.
	PinVerified map[string]bool `json:"pin_verified"`
	// Features reports the agent's capability surface: "ok" or "unavailable"
	// per capability.
	Features map[string]string `json:"features"`
}

// Options is the agent's configuration. Every field is optional except Config,
// and every seam has a production default, so cmd/transitd constructs
// Options{Config: cfg} and the unit tier injects fakes.
type Options struct {
	// Config is the agent configuration. It is validated by New, so a caller
	// may pass a config document straight from config.Load (already validated)
	// or a hand-built literal (validated for it).
	Config *config.Config

	// Verifier verifies each transit's pin. Nil means pinning.New() — the real
	// `ip route get` preflight.
	Verifier pinning.Verifier

	// Runner executes ping for every probe loop. Nil means probes.ExecRunner{}.
	Runner probes.Runner

	// Interval is the decision-evaluation cadence. Zero means DefaultInterval.
	Interval time.Duration

	// Log receives startup, decision and shutdown lines. Nil means
	// slog.Default().
	Log *slog.Logger
}

// Agent owns the probe supervisor and the decision engine, and is the driver
// that folds a switched decision back into the decision state.
//
// decide.Engine.Evaluate is a pure ranking primitive: it reads State.Primary as
// the incumbent and reports a switch in Decision.Primary without persisting it
// (the golden harness in internal/decide replays it the same way). Something has
// to be the driver, and that is this loop.
type Agent struct {
	cfg      *config.Config
	log      *slog.Logger
	interval time.Duration

	sup    *probes.Supervisor
	engine *decide.Engine

	// samples carries probe samples from the supervisor's emit callback to the
	// Run goroutine. Buffered and drop-on-full: see onSample.
	samples chan probes.Sample
	// obs is the latest sample per transit. It is read and written only by the
	// Run goroutine, so it needs no lock.
	obs map[string]probes.Sample

	// probed is true once any verified transit has produced a sample; running
	// is true once Run has entered its loop. Both are read by HTTP handlers.
	probed  atomic.Bool
	running atomic.Bool
}

// New validates cfg and wires the observe-only pipeline. It registers the
// transitd metric collectors, so a /metrics scrape is meaningful from the first
// request.
func New(opts Options) (*Agent, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("agent: Options.Config is required")
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	if err := metrics.Register(); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}

	a := &Agent{
		cfg:      opts.Config,
		log:      opts.Log,
		interval: opts.Interval,
		engine:   decide.NewEngine(opts.Config, &decide.State{WinStreak: map[string]int{}}),
		samples:  make(chan probes.Sample, 64),
		obs:      make(map[string]probes.Sample, len(opts.Config.Transits)),
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.interval <= 0 {
		a.interval = DefaultInterval
	}

	verifier := opts.Verifier
	if verifier == nil {
		verifier = pinning.New()
	}
	a.sup = &probes.Supervisor{
		Runner: opts.Runner,
		Verify: verifier.Verify,
		Emit:   a.onSample,
	}
	return a, nil
}

// Start runs the startup preflight — verify every transit's pin — and starts one
// probe loop per verified transit. It returns immediately; the loops stop when
// ctx is cancelled. A failed pin is not an error: it is a suppression. The one
// error case is a transit that verified but whose probe config cannot build a
// loop, which is a startup error rather than a silent gap.
func (a *Agent) Start(ctx context.Context) error {
	if err := a.sup.Start(ctx, a.cfg.Transits); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	res := a.sup.Results()
	for _, t := range a.cfg.Transits {
		// Log every outcome with its reason, verified or not: an operator has to
		// be able to tell a mis-pinned transit from an unreachable one without
		// guessing from a bare boolean.
		r := res[t.Name]
		if r.Verified {
			a.log.Info("pin verified", "transit", t.Name, "egress", r.EgressIf, "reason", r.Reason)
			continue
		}
		a.log.Error("pin NOT verified — transit suppressed: no probe samples, no decisions",
			"transit", t.Name, "expected_egress", t.EgressInterface, "observed_egress", r.EgressIf, "reason", r.Reason)
	}
	return nil
}

// Run starts the pipeline and blocks until ctx is cancelled, then returns nil.
// It is the whole agent loop: drain probe samples, and on every interval
// evaluate the decision state over the samples seen so far.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Start(ctx); err != nil {
		return err
	}
	a.running.Store(true)
	defer a.running.Store(false)
	a.log.Info("agent loop started (observe-only: decisions are logged and counted, never applied)",
		"router", a.cfg.RouterName, "transits", len(a.cfg.Transits), "interval", a.interval)

	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.log.Info("agent loop stopping: probe loops cancelled with it")
			return nil
		case s := <-a.samples:
			a.observe(s)
		case <-t.C:
			a.evaluate()
		}
	}
}

// observe records the latest sample for a transit, superseding the previous one.
func (a *Agent) observe(s probes.Sample) {
	a.obs[s.Transit] = s
	a.probed.Store(true)
}

// onSample hands a probe sample to the Run goroutine. It is called from the
// probe-loop goroutines, so it must never block: Prometheus has already
// recorded the sample (probes.Supervisor.emit runs before this callback), and
// the observation map is latest-wins, so a dropped sample is superseded by the
// next cycle. Dropping can delay a decision by one interval; it cannot corrupt
// one.
func (a *Agent) onSample(s probes.Sample) {
	a.probed.Store(true)
	select {
	case a.samples <- s:
	default:
	}
}

// evaluate runs one decision cycle over the observations seen so far and is
// where a decision becomes a log line and a counter. It applies nothing.
func (a *Agent) evaluate() {
	health := a.healthView()
	from := a.engine.State.Primary
	d := a.engine.Evaluate(health)

	if !d.Switched {
		a.log.Debug("decision: no switch",
			"primary", a.engine.State.Primary, "reason", d.Reason, "frozen", d.Frozen, "transits", len(health))
		return
	}

	// The driver step: Evaluate reports a switch without persisting it, so the
	// next cycle's incumbent is only correct if we fold it back here.
	a.engine.State.Primary = d.Primary
	metrics.DecisionsTotal.WithLabelValues(labelFrom(from), d.Primary, d.Reason).Inc()
	a.log.Info("decision: transit preference would change (NOT applied — no act package yet, issue #4)",
		"from", labelFrom(from), "to", d.Primary, "reason", d.Reason,
		"local_pref", d.AssignedLP, "frozen", d.Frozen)
}

// labelFrom renders a missing incumbent (first adoption) as "-" so the counter
// label is never an empty string, which is awkward to query and easy to confuse
// with a missing label.
func labelFrom(primary string) string {
	if primary == "" {
		return "-"
	}
	return primary
}

// healthView projects the current observations into the decide health view.
//
// Only VERIFIED transits appear. An unverified transit has no loop, so it has no
// sample, so it is simply absent: the agent must not feed the decision engine a
// fabricated "down" observation about a transit it cannot measure — suppression
// means missing, never guessed. Its existence is reported through
// pin_verified=0 and a degraded healthz instead.
//
// A transit whose probes have never produced a reply has no latency
// measurement. That is passed as +Inf, not 0, so it can never be ranked as the
// fastest path: "no data" and "instant" must not be the same value.
func (a *Agent) healthView() []decide.TransitHealth {
	out := make([]decide.TransitHealth, 0, len(a.obs))
	for name, s := range a.obs {
		h := decide.TransitHealth{
			Name: name,
			// SessionUp is a BGP fact (bgpwatch, not yet implemented), not a
			// probe fact, and the agent has no session source to consult.
			// Reporting a hard-down session it has not observed would be a
			// fabricated input to decide; instead the probe path carries the
			// liveness signal, and a transit whose probes are not getting
			// through is already excluded by decide's loss threshold.
			SessionUp: true,
			LossPct:   s.LossPct,
			EwmaMs:    s.LatencyMs,
		}
		if math.IsNaN(h.EwmaMs) {
			h.EwmaMs = math.Inf(1)
		}
		out = append(out, h)
	}
	// decide is deterministic without this (its comparator is a total order),
	// but a stable input order makes a decision reproducible from a log line.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Health reports the current capability/health state. It is safe to call before
// Start: every configured transit then reads as unverified and the status is
// degraded, which is the truth — nothing has been proven to work yet.
func (a *Agent) Health() Health {
	res := a.sup.Results()
	pin := make(map[string]bool, len(a.cfg.Transits))
	degraded := false
	for _, t := range a.cfg.Transits {
		ok := res[t.Name].Verified
		pin[t.Name] = ok
		if !ok {
			degraded = true
		}
	}
	status := statusOK
	if degraded {
		status = statusDegraded
	}

	features := map[string]string{
		// "probes" is dynamic: it is the capability an operator most needs to
		// know about, because its failure mode (a transit that cannot be
		// measured) is otherwise silent.
		"probes": featureUnavailable,
		// "act" is this build's defining restriction, not a fault: observe-only
		// by construction until issue #4 lands. An operator reading healthz must
		// never have to wonder whether transitd is touching the router.
		"act": featureUnavailable,
		// "bgpwatch" is the session-state input decide wants and does not have.
		"bgpwatch": featureUnavailable,
	}
	if a.probed.Load() {
		features["probes"] = featureOK
	}
	if a.running.Load() {
		features["decisions"] = featureOK
	} else {
		features["decisions"] = featureUnavailable
	}
	return Health{Status: status, PinVerified: pin, Features: features}
}

// Handler returns the agent's HTTP surface: /metrics for the Prometheus registry
// the pinning and probe packages write into, and /healthz for the health payload
// above.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", a.handleHealthz)
	return mux
}

// handleHealthz answers with the health payload. A degraded agent still answers
// 200: this endpoint reports state, it does not gate traffic, and a supervisor
// watching for a hang needs "alive" to be distinguishable from "not listening".
// The status-code contract is issue #5's to formalise.
func (a *Agent) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// The headers are already sent by the time Encode can fail, so there is
	// nothing to recover to; a truncated body is the worst case and the status
	// code still says the endpoint answered.
	_ = json.NewEncoder(w).Encode(a.Health())
}
