// Package health is transitd's single feature capability registry (issue #5).
//
// A transitd build has capabilities that can stop working without the process
// dying: probe pinning can go unverified, the ICMP probe needs a `ping` binary
// the distroless image does not ship, the gossip mesh can fail to join, a
// visibility monitor's provider can go down. Every one of those is a feature
// that silently self-disables unless something says so — and a counter nobody
// alerts on is not "saying so".
//
// This package is that something. Each capability registers once and reports its
// state through one call. The registry is then the only writer of three surfaces:
//
//   - the /healthz JSON the agent serves (per-feature state and reason),
//   - the transitd_feature_state{feature} gauge (0 enabled, 1 degraded,
//     2 disabled), and
//   - one log line per state change (WARN when a capability stops working in
//     full, INFO when it recovers).
//
// Writing the three from one call, under one lock and from one state value, is
// the point: a feature cannot be visible on a dashboard while healthz still
// says ok, because no code path can update one without the others.
//
// The registry is deliberately generic. It knows nothing about pinning, probes
// or gossip beyond the name a caller gives it, so a new subsystem adds a feature
// without this package changing.
package health

import (
	"log/slog"
	"sort"
	"sync"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// State is a feature's capability state (issue #5).
type State string

const (
	// Enabled: the capability is working.
	Enabled State = "enabled"
	// Degraded: the capability is impaired but still doing its job, or has not
	// had the chance to prove itself yet.
	Degraded State = "degraded"
	// Disabled: the capability cannot work at all in this build. This is the
	// state the whole mechanism exists for — it is the alternative to a feature
	// that has quietly stopped running.
	Disabled State = "disabled"
)

// Overall status values. They are the strings the agent's /healthz reports.
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
)

// metricValue maps a state onto the transitd_feature_state contract from issue
// #5. Anything unrecognised is reported as disabled: a state this code does not
// know is not evidence of a working feature.
func (s State) metricValue() int {
	switch s {
	case Enabled:
		return metrics.FeatureStateEnabled
	case Degraded:
		return metrics.FeatureStateDegraded
	default:
		return metrics.FeatureStateDisabled
	}
}

// Feature is one registered capability's current state and the reason it is in
// that state. Name is carried in the registry but omitted from the JSON value,
// where the map key is already the name.
type Feature struct {
	Name   string `json:"-"`
	State  State  `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Transition is one observed state change, handed to a Hook after the metric
// and the log line have been written.
type Transition struct {
	// Feature is the capability after the change.
	Feature Feature
	// Prev is the state before the change. A feature that is registering for
	// the first time is treated as coming from Enabled, see Registry.Set.
	Prev State
}

// Hook observes every state change. It exists so a test can assert that the
// warning path actually ran: asserting the resulting state alone would also
// pass a registry that never logged anything, which is exactly the failure this
// package is supposed to prevent.
type Hook func(Transition)

// Options configures a Registry.
type Options struct {
	// Log receives the state-change lines. Nil means slog.Default().
	Log *slog.Logger
	// Hook, when set, is called on every state change.
	Hook Hook
}

// Registry is the single place a transitd capability registers its state.
type Registry struct {
	mu       sync.Mutex
	features map[string]Feature
	log      *slog.Logger
	hook     Hook
}

// New returns an empty registry. Every feature is assumed enabled until it says
// otherwise, and "enabled" is not reported as a change (see Set), so a healthy
// build starts without a warning about anything.
func New(opts Options) *Registry {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Registry{
		features: make(map[string]Feature),
		log:      log,
		hook:     opts.Hook,
	}
}

// Register records a feature's initial state. It is Set under another name, kept
// distinct so a caller's intent reads clearly at the call site.
func (r *Registry) Register(name string, state State, reason string) {
	r.set(name, state, reason)
}

// Set records a feature's current state and reason, registering the feature if
// it is new, and updates all three surfaces.
//
// A feature that has never been seen is treated as coming FROM Enabled: a
// capability is assumed to work until it reports otherwise. Registering a
// feature directly in a degraded or disabled state is therefore a real
// transition and warns — that is the "no silent self-disable" guarantee.
//
// Only a STATE change logs and fires the hook. A repeated call with the same
// state updates the reason silently, which is what lets a per-cycle caller (a
// probe loop reporting the same missing binary every 30 seconds) re-assert a
// failure without flooding the log: the operator learns of a failure once, not
// once per cycle. The metric, by contrast, is written on every call, so a scrape
// always sees the current value.
func (r *Registry) Set(name string, state State, reason string) {
	r.set(name, state, reason)
}

func (r *Registry) set(name string, state State, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	prev, existed := r.features[name]
	prevState := prev.State
	if !existed {
		prevState = Enabled
	}
	next := Feature{Name: name, State: state, Reason: reason}
	r.features[name] = next

	metrics.SetFeatureState(name, state.metricValue())

	if prevState == state {
		return
	}
	// The alarming direction is a capability that is no longer fully working;
	// the recovery direction is worth one line but not a warning.
	if state == Enabled {
		r.log.Info("feature recovered", "feature", name, "from", string(prevState), "state", string(state))
	} else {
		r.log.Warn("feature not fully working", "feature", name, "from", string(prevState), "state", string(state), "reason", reason)
	}
	if r.hook != nil {
		r.hook(Transition{Feature: next, Prev: prevState})
	}
}

// Get returns a copy of a feature's current state and whether it is registered.
func (r *Registry) Get(name string) (Feature, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.features[name]
	return f, ok
}

// Snapshot returns every registered feature, sorted by name so a health read is
// deterministic and diffable.
func (r *Registry) Snapshot() []Feature {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Feature, 0, len(r.features))
	for _, f := range r.features {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Map returns every feature keyed by name, ready to be embedded in a payload.
func (r *Registry) Map() map[string]Feature {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]Feature, len(r.features))
	for name, f := range r.features {
		out[name] = f
	}
	return out
}

// Status is "ok" when every registered feature is enabled, "degraded"
// otherwise.
//
// A capability this build does not include is simply not registered, so it
// cannot drag the status down: the registry lists capabilities that exist and
// can self-disable, not roadmap items. "degraded" then means something a
// watchdog or an alert can act on — a thing this build is supposed to do is not
// working — rather than a permanent condition that trains operators to ignore
// the endpoint.
func (r *Registry) Status() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.features {
		if f.State != Enabled {
			return StatusDegraded
		}
	}
	return StatusOK
}
