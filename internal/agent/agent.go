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
	"github.com/ioseph-ai/transitd/internal/gossip"
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
	// Gossip reports the health mesh's state (issue #3). It is a pointer so that a
	// router with no mesh configured omits the field entirely, which is
	// distinguishable from a mesh that is configured and failing to join.
	Gossip *GossipHealth `json:"gossip,omitempty"`
}

// GossipHealth is the mesh's entry in the healthz payload. It mirrors
// gossip.Status but is a distinct type so this package's JSON contract does not
// change every time the mesh adds an internal field.
type GossipHealth struct {
	// Enabled is whether a mesh is configured. It is always true when this object
	// is present, and is carried explicitly so a consumer can read one object
	// without also checking for its absence.
	Enabled bool `json:"enabled"`
	// Joined is whether the startup join reached a peer. A mesh with no peers is
	// joined by definition.
	Joined bool `json:"joined"`
	// Members is the alive node count, including this router.
	Members int `json:"members"`
	// JoinErr is the startup join failure, empty on success.
	JoinErr string `json:"join_error,omitempty"`
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

	// OnPeer, when set, receives each health message this router decodes from the
	// mesh. It is the seam the merged-health view (and, later, the visibility
	// monitor) reads from. Nil means the agent records nothing — the mesh still
	// runs, so peers see this router and the member count is right, but nothing
	// is merged locally.
	OnPeer func(gossip.Message)

	// Mesh is an override for the gossip mesh, for tests. Nil means the agent
	// builds one from Config.Gossip when that is enabled.
	Mesh *gossip.Mesh
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

	// mesh is the gossip health mesh, nil when gossip is not configured (or an
	// override was not supplied).
	mesh *gossip.Mesh
	// onPeer is the caller's peer-message hook, kept so Start can hand it to a
	// mesh it builds itself.
	onPeer func(gossip.Message)
	// snap is the latest payload for the mesh to broadcast. It is written by the
	// Run goroutine — which owns obs — and read by the mesh's broadcast goroutine,
	// so it is the one place the two need an atomic hand-off. Storing the whole
	// immutable payload keeps the mesh from ever reading a half-updated view.
	snap atomic.Pointer[gossip.HealthPayload]
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
		mesh:     opts.Mesh,
		onPeer:   opts.OnPeer,
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
	if err := a.startMesh(ctx); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}

// startMesh brings up the gossip health mesh, if one is configured or was
// supplied. A disabled mesh is the normal single-router case and is not an error.
//
// A failed JOIN is also not an error: the mesh is up and a peer can still join
// this node, so the agent keeps measuring its own transits. The failure is carried
// in gossip.Status, which healthz reports (issue #5).
//
// The snapshot closure is what makes the mesh carry THIS router's view without the
// mesh needing a reference to the agent's internals: it reads the atomically
// published payload, so a broadcast tick can never observe a half-updated obs map.
func (a *Agent) startMesh(ctx context.Context) error {
	if a.mesh == nil {
		if !a.cfg.Gossip.Enabled() {
			return nil
		}
		m, err := gossip.New(gossip.Options{
			Config:    a.cfg,
			Snapshot:  a.currentSnapshot,
			OnMessage: a.onPeer,
			Log:       a.log,
		})
		if err != nil {
			return err
		}
		a.mesh = m
	}
	// Publish an initial (empty) snapshot so a broadcast before the first probe
	// sample sends "nothing measured yet" rather than a stale value.
	a.publishSnapshot()
	if err := a.mesh.Start(ctx); err != nil {
		return err
	}
	st := a.mesh.Status()
	a.log.Info("gossip mesh started",
		"router", a.cfg.RouterName, "members", st.Members, "joined", st.Joined, "local", a.mesh.Local())
	return nil
}

// currentSnapshot returns the payload the mesh should broadcast. It is the
// SnapshotFunc the mesh calls, and it is safe to call from the mesh's goroutine:
// it only reads the atomically published value.
func (a *Agent) currentSnapshot() gossip.HealthPayload {
	if p := a.snap.Load(); p != nil {
		return *p
	}
	return gossip.HealthPayload{}
}

// publishSnapshot folds the current observations and decision state into an
// immutable payload and publishes it for the mesh. It runs on the Run goroutine,
// which owns obs, so the read needs no lock — only the publication does.
func (a *Agent) publishSnapshot() {
	p := gossip.HealthPayload{Transits: make([]gossip.TransitSummary, 0, len(a.obs))}
	for name, s := range a.obs {
		p.Transits = append(p.Transits, gossip.TransitSummary{
			Name:      name,
			SessionUp: true, // probe-derived liveness; see healthView's note
			LossPct:   s.LossPct,
			// FloatPtr turns "no reply yet" (NaN) into an absent field, so a
			// peer cannot read a silent transit as a 0 ms path.
			EwmaMs: gossip.FloatPtr(s.LatencyMs),
		})
	}
	sort.Slice(p.Transits, func(i, j int) bool { return p.Transits[i].Name < p.Transits[j].Name })
	if primary := a.engine.State.Primary; primary != "" {
		p.Decide = &gossip.DecideView{
			Primary:  primary,
			Switched: true, // this router has adopted a primary; the reason is local
			Reason:   "local decision state (observe-only)",
			Frozen:   a.engine.State.Frozen,
		}
	}
	a.snap.Store(&p)
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
			// Stop the mesh with the loop: it is the loop that publishes the view
			// it broadcasts, so a mesh outliving the loop would gossip a frozen
			// snapshot.
			if a.mesh != nil {
				a.mesh.Shutdown()
			}
			return nil
		case s := <-a.samples:
			a.observe(s)
		case <-t.C:
			a.evaluate()
			// Publish after evaluating, so the view on the wire matches the
			// decision state it was derived from.
			a.publishSnapshot()
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
	// "gossip" is dynamic in the same spirit as "probes": its failure mode — a
	// configured mesh that never reached a peer — would otherwise be silent.
	features["gossip"] = featureUnavailable

	var gh *GossipHealth
	if a.mesh != nil {
		st := a.mesh.Status()
		gh = &GossipHealth{Enabled: st.Enabled, Joined: st.Joined, Members: st.Members, JoinErr: st.JoinErr}
		if st.Enabled && st.Joined {
			features["gossip"] = featureOK
		}
		// A configured mesh that is running but never joined a peer is a degraded
		// router: it measures and decides locally, but it is not contributing to
		// or reading the merged view. Saying so is the whole point of healthz.
		if st.Enabled && !st.Joined {
			status = statusDegraded
		}
	}
	return Health{Status: status, PinVerified: pin, Features: features, Gossip: gh}
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
