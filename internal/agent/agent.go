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
	"os/exec"
	"sort"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ioseph-ai/transitd/internal/bgpwatch"
	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/decide"
	"github.com/ioseph-ai/transitd/internal/gossip"
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
	// featureGossip is the memberlist mesh (issue #3).
	featureGossip = "gossip"
	// featureBgpwatch is the read-only vtysh BGP session poller. It is only
	// registered when the poller is actually wired (enabled AND a transit
	// names a neighbor): a capability the deployment does not use must not
	// appear as broken. Once wired it is degraded until the first session
	// observation arrives, so "enabled but not answering" stays visible.
	featureBgpwatch = "bgpwatch"
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

	// BGPWatch executes vtysh `show` queries for the BGP session view. Nil means
	// bgpwatch.ExecRunner{}. It is only used when config.BGPWatch.Enabled is set.
	BGPWatch bgpwatch.Runner

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
	// is true once Run has entered its loop; bgpUp is true once a BGP session
	// observation has arrived. All three are read by HTTP handlers.
	probed  atomic.Bool
	running atomic.Bool
	bgpUp   atomic.Bool

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
		cfg:         opts.Config,
		log:         opts.Log,
		interval:    opts.Interval,
		engine:      decide.NewEngine(opts.Config, &decide.State{WinStreak: map[string]int{}}),
		samples:     make(chan probes.Sample, 64),
		obs:         make(map[string]probes.Sample, len(opts.Config.Transits)),
		sessions:    make(map[string]bgpwatch.Session),
		sessionCh:   make(chan bgpwatch.Session, 64),
		probeBinary: opts.ProbeBinary,
		lookPath:    opts.LookPath,
		mesh:        opts.Mesh,
		onPeer:      opts.OnPeer,
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
	// bgpwatch is wired only when enabled AND at least one transit names a
	// neighbor: a poller with nothing to attribute its sessions to would exec
	// vtysh every cadence for no observation. It is read-only, so the only
	// reason to not start it is cost.
	if opts.Config.BGPWatch.Enabled && anyBGPNeighbor(opts.Config.Transits) {
		poller := bgpwatch.New(opts.Config.BGPWatch, opts.BGPWatch)
		poller.Emit = a.onSession
		a.bgp = poller
		// Register the capability as soon as the poller exists, in the same
		// spirit as the gossip pre-registration: a wired poller that never
		// produces an observation is a degraded capability, not an absent one,
		// and the gap must be visible before Start runs.
		a.reg.Register(featureBgpwatch, health.Degraded, "bgpwatch poller wired but no session observation yet")
	}

	// Capability preflight at construction time, so a build that cannot probe
	// says so before it ever claims to be observing. The decision loop is
	// registered enabled here as well and does not flip until Start/Run report
	// otherwise: reporting it disabled merely because nothing has started yet
	// would make a freshly constructed (and perfectly healthy) agent look broken.
	a.reg.Register(featureDecisions, health.Enabled, "")
	a.checkProbeCapability()
	a.reg.Register(featurePinning, health.Enabled, "startup pin verification pending")
	if a.cfg.Gossip.Enabled() {
		// The operator configured a gossip mesh. At construction time it has
		// not started, let alone joined: registering it degraded-with-reason
		// makes that gap visible on all three surfaces instead of an agent
		// that looks healthy while never joining. Start reports the real join
		// outcome and Health keeps the feature current (refreshGossipFeature).
		//
		// With no key configured there is nothing to fail, so nothing is
		// registered: a capability this deployment does not use must not drag
		// the status down.
		a.reg.Register(featureGossip, health.Degraded, "gossip mesh configured but not started yet")
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
	// The capability surface follows the preflight: unverified transits degrade
	// pinning and probes, all-verified keeps both enabled.
	a.setPinFeature(unverified, len(a.cfg.Transits))
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
	// Fold the startup join outcome into the capability registry immediately:
	// Health refreshes it on read, but the transition itself belongs to the
	// moment it happens, so the WARN/INFO line lands with the mesh log lines
	// an operator reads together.
	a.refreshGossipFeature()
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
		case s := <-a.sessionCh:
			a.observeSession(s)
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
// Start: the registry holds whatever capabilities have self-reported so far and
// the status is derived from them, so a half-started agent reports only the
// features it has actually resolved rather than asserting a capability works.
//
// The status is the registry's, not recomputed here, which is what makes the
// healthz status and the transitd_feature_state metric two views of one fact.
func (a *Agent) Health() Health {
	// The gossip and bgpwatch features are refreshed on read so a mesh that
	// joins or a poller that starts answering after Start is reflected without
	// waiting for another Start: there is no periodic tick that owns these
	// updates, and healthz is the natural one.
	a.refreshGossipFeature()
	a.refreshBgpwatchFeature()
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
		Gossip:      a.gossipHealth(),
	}
}

// gossipHealth returns the mesh's entry for the healthz payload, nil when no
// mesh exists (not configured and none supplied). The distinction is load-
// bearing: "no gossip object" means the operator never asked for a mesh, while
// an object with joined=false is a configured mesh that has not reached a peer.
func (a *Agent) gossipHealth() *GossipHealth {
	if a.mesh == nil {
		return nil
	}
	st := a.mesh.Status()
	return &GossipHealth{Enabled: st.Enabled, Joined: st.Joined, Members: st.Members, JoinErr: st.JoinErr}
}

// refreshGossipFeature folds the mesh's live state into the feature registry so
// the gossip capability cannot go stale between Start calls. It runs on every
// Health read; Set only logs on a state change, so a mesh stuck in one state
// does not flood the log, while the metric is republished on every read.
//
// A configured mesh that is up but has not joined a peer is degraded, not
// disabled: it measures and decides locally, but it is neither contributing to
// nor reading the merged view — exactly the "no silent self-disable" case the
// registry exists for.
func (a *Agent) refreshGossipFeature() {
	if a.mesh == nil {
		return
	}
	st := a.mesh.Status()
	switch {
	case st.Joined:
		a.reg.Set(featureGossip, health.Enabled, "")
	case st.JoinErr != "":
		a.reg.Set(featureGossip, health.Degraded, "gossip join not established: "+st.JoinErr)
	default:
		a.reg.Set(featureGossip, health.Degraded, "gossip join still in progress; no peer reached yet")
	}
}

// refreshBgpwatchFeature folds the bgpwatch poller's state into the feature
// registry, on the same read-refresh pattern as the gossip feature. A wired
// poller is degraded until its first session observation arrives: the poller
// runs on its own goroutine and a vtysh that never answers is exactly the
// silent failure the registry exists to surface. Once an observation has
// arrived the feature is enabled — a poll that later fails outright degrades
// it again through the poller's error path.
func (a *Agent) refreshBgpwatchFeature() {
	if a.bgp == nil {
		return
	}
	if a.bgpUp.Load() {
		a.reg.Set(featureBgpwatch, health.Enabled, "")
	} else {
		a.reg.Set(featureBgpwatch, health.Degraded, "bgpwatch poller wired but no session observation yet")
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
