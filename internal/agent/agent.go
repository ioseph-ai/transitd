// Package agent wires transitd's observation pipeline: a validated config, the
// startup pin-verification preflight, one probe loop per VERIFIED transit,
// bounded vtysh BGP-state polling (bgpwatch) for transits with a configured
// neighbor, probe samples and BGP session state into decide.Evaluate, and the
// metrics/healthz surface.
//
// It is OBSERVE-ONLY. Nothing in this package reaches a router mutation path:
// bgpwatch issues `show` commands only, and the act package that would apply a
// decision is deliberately NOT wired here (issue #4 wires bgpwatch, not act — no
// auto-mutations until a later review card). The observe-only constraint is
// enforced structurally by TestAgentIsObserveOnly rather than by convention.
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

	"github.com/ioseph-ai/transitd/internal/bgpwatch"
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

	// BGPWatch executes vtysh `show` queries for the BGP session view. Nil means
	// bgpwatch.ExecRunner{}. It is only used when config.BGPWatch.Enabled is set.
	BGPWatch bgpwatch.Runner

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

	// bgp polls BGP session state (bgpwatch), and is nil when bgpwatch is not
	// enabled or no transit names a neighbor. It is the only vtysh seam
	// reachable from this package, and it issues read-only `show` queries.
	bgp *bgpwatch.Poller
	// sessions is the latest BGP session observation per neighbor address. It is
	// read and written only by the Run goroutine, so it needs no lock; the
	// poller's goroutine hands observations over through sessionCh.
	sessions map[string]bgpwatch.Session
	// sessionCh carries BGP session observations from the bgpwatch poller to the
	// Run goroutine. Buffered and drop-on-full, exactly like samples: an
	// observation is latest-wins, so a dropped one is superseded, never lost in a
	// way that corrupts state.
	sessionCh chan bgpwatch.Session

	// samples carries probe samples from the supervisor's emit callback to the
	// Run goroutine. Buffered and drop-on-full: see onSample.
	samples chan probes.Sample
	// obs is the latest sample per transit. It is read and written only by the
	// Run goroutine, so it needs no lock.
	obs map[string]probes.Sample

	// probed is true once any verified transit has produced a sample; running
	// is true once Run has entered its loop; bgpUp is true once a BGP session
	// observation has arrived. All three are read by HTTP handlers.
	probed  atomic.Bool
	running atomic.Bool
	bgpUp   atomic.Bool
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
		cfg:       opts.Config,
		log:       opts.Log,
		interval:  opts.Interval,
		engine:    decide.NewEngine(opts.Config, &decide.State{WinStreak: map[string]int{}}),
		samples:   make(chan probes.Sample, 64),
		obs:       make(map[string]probes.Sample, len(opts.Config.Transits)),
		sessions:  make(map[string]bgpwatch.Session),
		sessionCh: make(chan bgpwatch.Session, 64),
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
	// bgpwatch is wired only when enabled AND at least one transit names a
	// neighbor: a poller with nothing to attribute its sessions to would exec
	// vtysh every cadence for no observation. It is read-only, so the only
	// reason to not start it is cost.
	if opts.Config.BGPWatch.Enabled && anyBGPNeighbor(opts.Config.Transits) {
		poller := bgpwatch.New(opts.Config.BGPWatch, opts.BGPWatch)
		poller.Emit = a.onSession
		a.bgp = poller
	}
	return a, nil
}

// anyBGPNeighbor reports whether any transit names a BGP neighbor, i.e. whether a
// bgpwatch poll can produce an observation the decision engine will consume.
func anyBGPNeighbor(transits []config.Transit) bool {
	for _, t := range transits {
		if t.BGPNeighbor != "" {
			return true
		}
	}
	return false
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
	// bgpwatch starts after the preflight: it is independent of pinning (a
	// session view is read-only and needs no pin), but starting it here keeps all
	// vtysh access in one place and one order.
	if a.bgp != nil {
		a.log.Info("bgpwatch started (read-only vtysh `show` polling; 1 Hz cap)",
			"interval", a.bgp.Interval, "max_prefixes", a.bgp.MaxPrefixes)
		go a.bgp.Run(ctx, a.cfg.Transits, func(err error) {
			a.log.Warn("bgpwatch poll failed", "err", err.Error())
		})
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
		case s := <-a.sessionCh:
			a.observeSession(s)
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

// observeSession records the latest BGP session observation for a neighbor. It
// runs on the Run goroutine, like observe.
func (a *Agent) observeSession(s bgpwatch.Session) {
	a.sessions[s.Neighbor] = s
	a.bgpUp.Store(true)
}

// onSession hands a BGP session observation to the Run goroutine. It is the
// bgpwatch poller's emit callback, so it must never block: the map is
// latest-wins and the poller records nothing else here.
func (a *Agent) onSession(s bgpwatch.Session) {
	a.bgpUp.Store(true)
	select {
	case a.sessionCh <- s:
	default:
	}
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
// SessionUp comes from bgpwatch when the transit names a BGP neighbor AND a
// session observation for it has arrived; otherwise the transit keeps the
// probe-only view and reads as up. The distinction matters: "no BGP observation"
// is not "session down", and reporting a hard-down session the agent has not
// observed would be a fabricated input to decide. A transit whose probes are not
// getting through is already excluded by decide's loss threshold, so the
// probe-only path still carries a liveness signal.
//
// A transit whose probes have never produced a reply has no latency
// measurement. That is passed as +Inf, not 0, so it can never be ranked as the
// fastest path: "no data" and "instant" must not be the same value.
func (a *Agent) healthView() []decide.TransitHealth {
	out := make([]decide.TransitHealth, 0, len(a.obs))
	for name, s := range a.obs {
		h := decide.TransitHealth{
			Name:      name,
			SessionUp: a.sessionUp(name),
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

// sessionUp reports whether a named transit's BGP session is up, per bgpwatch. It
// returns true when the transit names no neighbor or no observation has arrived
// yet: an unobserved session is not a down session, and the probe path carries the
// liveness signal until bgpwatch has something to say. A configured neighbor with
// an observation that says down returns false.
func (a *Agent) sessionUp(transit string) bool {
	neighbor := a.neighborFor(transit)
	if neighbor == "" {
		return true
	}
	s, ok := a.sessions[neighbor]
	if !ok {
		return true
	}
	return s.Up
}

// neighborFor returns the configured BGP neighbor for a transit, or "".
func (a *Agent) neighborFor(transit string) string {
	for i := range a.cfg.Transits {
		if a.cfg.Transits[i].Name == transit {
			return a.cfg.Transits[i].BGPNeighbor
		}
	}
	return ""
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
		// "act" is this build's defining restriction, not a fault: act exists
		// but is deliberately NOT wired to decide (issue #4 — observe-only until
		// a later review card). An operator reading healthz must never have to
		// wonder whether transitd is touching the router.
		"act": featureUnavailable,
		// "bgpwatch" is the session-state input decide consumes. It is "ok" when
		// the poller is wired AND has produced at least one observation;
		// "unavailable" otherwise, so an operator can tell "not enabled" from
		// "enabled but not answering".
		"bgpwatch": featureUnavailable,
	}
	if a.probed.Load() {
		features["probes"] = featureOK
	}
	if a.bgp != nil && a.bgpUp.Load() {
		features["bgpwatch"] = featureOK
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
