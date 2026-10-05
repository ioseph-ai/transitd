// Package decide implements the deterministic transit-ranking state machine.
package decide

import (
	"sort"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
)

// TransitHealth is one transit's observed state on this router (or gossiped
// from a peer; the decision function only sees merged health).
type TransitHealth struct {
	Name      string
	SessionUp bool
	LossPct   float64 // recent probe loss, 0..100
	EwmaMs    float64 // EWMA latency in milliseconds
}

// State is the persisted decision state (rebuilt after restart from an
// on-disk snapshot; see act.Store).
type State struct {
	Primary       string    // current rank-1 transit name
	LastSwitch    time.Time // last time Primary changed
	SwitchHourWnd int       // switches in the rolling hour window
	Frozen        bool      // rate-limit tripped; no switches until window drains
	WinStreak     map[string]int
}

// Decision is the outcome of one decide cycle.
type Decision struct {
	Primary    string
	Switched   bool
	Reason     string // human-readable, logged + exported
	Frozen     bool
	AssignedLP map[string]int // transit -> local-pref to apply
}

// Engine holds tuning + state.
type Engine struct {
	Cfg   *config.Config
	State *State
	now   func() time.Time
}

func NewEngine(cfg *config.Config, st *State) *Engine {
	if st.WinStreak == nil {
		st.WinStreak = map[string]int{}
	}
	return &Engine{Cfg: cfg, State: st, now: time.Now}
}

// rank orders eligible transits: hard-down and high-loss excluded, then
// ascending EWMA latency, then name for total order.
func (e *Engine) rank(health []TransitHealth) []TransitHealth {
	eligible := make([]TransitHealth, 0, len(health))
	for _, h := range health {
		if !h.SessionUp || h.LossPct >= e.Cfg.LossDropPct {
			continue
		}
		eligible = append(eligible, h)
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].EwmaMs != eligible[j].EwmaMs {
			return eligible[i].EwmaMs < eligible[j].EwmaMs
		}
		return eligible[i].Name < eligible[j].Name
	})
	return eligible
}

// Evaluate runs one cycle and returns the decision (no side effects).
func (e *Engine) Evaluate(health []TransitHealth) Decision {
	d := Decision{Primary: e.State.Primary, AssignedLP: map[string]int{}}
	now := e.now()

	ranked := e.rank(health)

	if e.State.Primary == "" {
		// first boot: adopt the best without counting a switch
		if len(ranked) > 0 {
			d.Primary = ranked[0].Name
			d.Switched = true
			d.Reason = "initial adoption"
			e.State.LastSwitch = now
			e.applyLP(ranked, &d)
		}
		return d
	}

	incumbentUp := false
	for _, h := range health {
		if h.Name == e.State.Primary {
			incumbentUp = h.SessionUp && h.LossPct < e.Cfg.LossDropPct
		}
	}

	switchCandidate := ""
	reason := ""

	if len(ranked) > 0 {
		best := ranked[0]
		switch {
		case !incumbentUp:
			switchCandidate = best.Name
			reason = "incumbent hard-down or loss-excluded"
		case best.Name != e.State.Primary && best.EwmaMs+e.Cfg.MarginMs <= incumbentEwma(health, e.State.Primary):
			e.State.WinStreak[best.Name]++
			if e.State.WinStreak[best.Name] >= e.Cfg.WinCycles {
				switchCandidate = best.Name
				reason = "challenger won margin for required cycles"
			}
		}
	}

	if switchCandidate != "" {
		switch {
		case e.State.Frozen:
			d.Frozen = true
			d.Reason = "switch suppressed: rate-limit freeze"
		case now.Sub(e.State.LastSwitch) < e.Cfg.Dwell:
			d.Reason = "switch suppressed: dwell"
		case e.State.SwitchHourWnd >= e.Cfg.MaxSwitches:
			e.State.Frozen = true
			d.Frozen = true
			d.Reason = "switch suppressed: rate-limit freeze"
		default:
			d.Primary = switchCandidate
			d.Switched = true
			d.Reason = reason
			e.State.LastSwitch = now
			e.State.SwitchHourWnd++
			if e.State.SwitchHourWnd > e.Cfg.MaxSwitches {
				e.State.Frozen = true
			}
		}
	}
	// reset streaks except the current challenger's
	for name := range e.State.WinStreak {
		if len(ranked) == 0 || name != ranked[0].Name {
			e.State.WinStreak[name] = 0
		}
	}

	// LP assignment follows the ranking around the chosen primary.
	if len(ranked) > 0 {
		e.applyLP(ranked, &d)
	} else {
		d.Reason = "no eligible transit"
	}
	return d
}

func (e *Engine) applyLP(ranked []TransitHealth, d *Decision) {
	for i, h := range ranked {
		d.AssignedLP[h.Name] = e.Cfg.BaseLP - i*e.Cfg.LPStep
	}
}

func incumbentEwma(health []TransitHealth, name string) float64 {
	for _, h := range health {
		if h.Name == name {
			return h.EwmaMs
		}
	}
	return 1 << 60
}
