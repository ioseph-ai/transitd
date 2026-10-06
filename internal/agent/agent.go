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
	"os/exec"
	"sort"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/decide"
	"github.com/ioseph-ai/transitd/internal/health"
	"github.com/ioseph-ai/transitd/internal/metrics"
	"github.com/ioseph-ai/transitd/internal/pinning"
	"github.com/ioseph-ai/transitd/internal/probes"
)

// DefaultInterval is the decision-evaluation cadence used when Options.Interval
// is unset. It matches the default probe interval: deciding faster than samples
// arrive only re-decides on unchanged data.
const DefaultInterval = 30 * time.Second

// Feature names this build registers. They are the registry keys an operator
// reads in healthz and the label values on transitd_feature_state; a name is
// stable once shipped, because a dashboard or an alert rule keys on it.
const (
	// featureProbes is the ICMP probe capability. Its failure modes are a
	// missing/incompatible ping(8) binary and an unverified transit, both of
	// which are surfaced with a reason.
	featureProbes = "probes"
	// featurePinning is the startup pin-verification preflight. A transit that
	// fails it is suppressed (issue #1), which is exactly the kind of quiet
	// degradation this registry exists to make loud.
	featurePinning = "pinning"
	// featureDecisions is the observe-only decision loop.
	featureDecisions = "decisions"
	// featureGossip is the memberlist mesh (issue #3). It is not part of this
	// build, so it is reported disabled with a reason rather than omitted: an
	// operator asking "are my routers gossiping?" gets an answer.
	featureGossip = "gossip"
)

// Health is the /healthz payload. Status is the overall verdict; Features
// carries one entry per registered capability, each with its state and the
// reason for it, so an operator can see which subsystem is responsible for a
// degraded status without reading the logs (issue #5).
type Health struct {
	// Status is "ok" when every registered feature is enabled, "degraded"
	// otherwise. It is derived from the registry, never set by hand, so it
	// cannot disagree with the feature map below.
	Status string `json:"status"`
	// PinVerified has one entry per configured transit — never a missing key
	// for an unverified one. A transit that is present but false is
	// "mis-pinned"; a transit that is absent from the config is a different
	// thing, and the map keeps them distinguishable.
	PinVerified map[string]bool `json:"pin_verified"`
	// Features reports each capability's state (enabled|degraded|disabled) and
	// the reason it is not enabled. It is the same registry that writes the
	// transitd_feature_state metric, so the two can never disagree.
	Features map[string]health.Feature `json:"features"`
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

	// ProbeBinary is the ping program the probe capability is checked against
	// at startup. Empty means "ping". It exists so a deployment that puts ping
	// somewhere unusual can be checked for it, and so the unit tier can force
	// the "no ping in the image" path deterministically.
	ProbeBinary string

	// LookPath checks that the probe binary exists before it is used. Nil means
	// exec.LookPath. It is a seam because the startup probe-capability check
	// must be deterministic in the unit tier: whether "ping" is on PATH depends
	// on the image, and a test that flipped a feature based on the CI image
	// would be flaky in exactly the way this feature exists to catch.
	LookPath func(file string) (string, error)

	// Health, when set, is the feature registry to use. Nil means New builds a
	// fresh one over Log, which is what production wants. A test injects one to
	// observe transitions or to prepopulate a broken capability.
	Health *health.Registry

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

	// reg is the feature capability registry (issue #5). It is the single
	// writer of the healthz feature map and the transitd_feature_state metric;
	// its status is the healthz top-level status, so the two cannot disagree.
	reg *health.Registry

	// probeBinary is the ping program the probe capability was checked against.
	probeBinary string
	// lookPath resolves the probe binary. It is a field so the startup check is
	// deterministic in the unit tier (see Options.LookPath).
	lookPath func(file string) (string, error)
	// probeBinaryOK records that the ping binary passed the startup check. It
	// gates the later pin-driven updates to the probes feature: a missing binary
	// is the harder failure and must not be overwritten by "all transits
	// verified" — pin verification uses `ip route get`, which works fine with no
	// ping binary at all, so without this the two would disagree.
	probeBinaryOK bool

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
		cfg:         opts.Config,
		log:         opts.Log,
		interval:    opts.Interval,
		engine:      decide.NewEngine(opts.Config, &decide.State{WinStreak: map[string]int{}}),
		samples:     make(chan probes.Sample, 64),
		obs:         make(map[string]probes.Sample, len(opts.Config.Transits)),
		probeBinary: opts.ProbeBinary,
		lookPath:    opts.LookPath,
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.interval <= 0 {
		a.interval = DefaultInterval
	}
	if a.probeBinary == "" {
		a.probeBinary = "ping"
	}
	if a.lookPath == nil {
		a.lookPath = exec.LookPath
	}
	a.reg = opts.Health
	if a.reg == nil {
		a.reg = health.New(health.Options{Log: a.log})
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

	// Capability preflight at construction time, so a build that cannot probe
	// says so before it ever claims to be observing. The decision loop is
	// registered enabled here as well and does not flip until Start/Run report
	// otherwise: reporting it disabled merely because nothing has started yet
	// would make a freshly constructed (and perfectly healthy) agent look broken.
	a.reg.Register(featureDecisions, health.Enabled, "")
	a.checkProbeCapability()
	a.reg.Register(featurePinning, health.Enabled, "startup pin verification pending")
	if len(opts.Config.Join) > 0 {
		// The operator configured a gossip mesh, but this binary has none built
		// in (issue #3). Reporting that as a disabled capability is the whole
		// point: the config asked for a thing that is not happening, and the
		// failure is otherwise perfectly silent — the agent would look healthy
		// while never joining, and every peer-view assumption would be wrong.
		//
		// With no join list there is nothing to fail, so nothing is registered:
		// a capability this build does not have must not drag the status down.
		//
		// This is the wiring point issue #3 replaces with a real join outcome:
		// a memberlist join failure becomes a Degraded set with the join error
		// as the reason, and nothing else in this file changes.
		a.reg.Register(featureGossip, health.Disabled, "gossip mesh not built into this binary (issue #3), but join is configured")
	}
	return a, nil
}

// checkProbeCapability probes whether the ICMP probe can work at all in this
// image, and registers the outcome with a reason.
//
// The failure mode issue #5 names as the headline consumer is a distroless
// image with no ping(8): every probe would then fail, silently, and the agent
// would look like it had simply measured a quiet network. Detecting it once at
// startup, and saying so on all three surfaces, is the difference between "no
// probes configured" and "probes are broken".
func (a *Agent) checkProbeCapability() {
	if _, err := a.lookPath(a.probeBinary); err != nil {
		a.probeBinaryOK = false
		a.reg.Register(featureProbes, health.Disabled,
			fmt.Sprintf("%s binary not found in PATH: %v", a.probeBinary, err))
		return
	}
	variant := probes.DetectVariant(context.Background(), probes.ExecRunner{Binary: a.probeBinary})
	switch variant {
	case probes.VariantIputils, probes.VariantBusybox:
		// A recognised implementation. The probe is enabled; a later pin
		// failure degrades it with its own reason.
		//
		// Register with an empty reason and let the registry decide: an
		// Enabled state never logs, and pinning (below) is the one that can
		// still take the status down.
		a.probeBinaryOK = true
		a.reg.Register(featureProbes, health.Enabled, "")
	default:
		// DetectVariant only ever returns one of the two known variants, or
		// busybox as its conservative fallback, so this is unreachable today.
		// If a future implementation is added the conservative reading stands:
		// an unrecognised ping is not a working probe.
		a.probeBinaryOK = false
		a.reg.Register(featureProbes, health.Degraded,
			fmt.Sprintf("unrecognised ping implementation %q", variant))
	}
}

// setPinFeature records the pinning capability's state after the preflight and
// folds the outcome into the probes capability.
//
// The two interact deliberately: a transit whose pin failed produces no probe
// samples at all (issue #1), so "probes are working" is not true in the sense an
// operator cares about while any transit is unverified — the agent is observing
// a strict subset of what was configured. The probes feature is therefore
// degraded (not disabled: the verified transits still probe) whenever pinning is,
// unless the binary check already found a harder failure.
func (a *Agent) setPinFeature(unverified int, total int) {
	if unverified == 0 {
		a.reg.Set(featurePinning, health.Enabled, "")
		if a.probeBinaryOK {
			a.reg.Set(featureProbes, health.Enabled, "")
		}
		return
	}
	reason := fmt.Sprintf("%d of %d transits unverified at startup: their probes are suppressed (no samples, no decisions)",
		unverified, total)
	a.reg.Set(featurePinning, health.Degraded, reason)
	if a.probeBinaryOK {
		a.reg.Set(featureProbes, health.Degraded, reason)
	}
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
	unverified := 0
	for _, t := range a.cfg.Transits {
		// Log every outcome with its reason, verified or not: an operator has to
		// be able to tell a mis-pinned transit from an unreachable one without
		// guessing from a bare boolean.
		r := res[t.Name]
		if r.Verified {
			a.log.Info("pin verified", "transit", t.Name, "egress", r.EgressIf, "reason", r.Reason)
			continue
		}
		unverified++
		a.log.Error("pin NOT verified — transit suppressed: no probe samples, no decisions",
			"transit", t.Name, "expected_egress", t.EgressInterface, "observed_egress", r.EgressIf, "reason", r.Reason)
	}
	// The capability surface follows the preflight: unverified transits degrade
	// pinning and probes, all-verified keeps both enabled.
	a.setPinFeature(unverified, len(a.cfg.Transits))
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
// Start: the registry holds whatever capabilities have self-reported so far and
// the status is derived from them, so a half-started agent reports only the
// features it has actually resolved rather than asserting a capability works.
//
// The status is the registry's, not recomputed here, which is what makes the
// healthz status and the transitd_feature_state metric two views of one fact.
func (a *Agent) Health() Health {
	res := a.sup.Results()
	pin := make(map[string]bool, len(a.cfg.Transits))
	for _, t := range a.cfg.Transits {
		// One entry per configured transit, present even when false: an
		// operator distinguishes "mis-pinned" (present, false) from "not
		// configured" (absent) only if the key is always there.
		pin[t.Name] = res[t.Name].Verified
	}
	return Health{
		Status:      a.reg.Status(),
		PinVerified: pin,
		Features:    a.reg.Map(),
	}
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
// The body's `status` field is the machine-readable verdict; the HTTP code stays
// 200 by design.
func (a *Agent) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// The headers are already sent by the time Encode can fail, so there is
	// nothing to recover to; a truncated body is the worst case and the status
	// code still says the endpoint answered.
	_ = json.NewEncoder(w).Encode(a.Health())
}
