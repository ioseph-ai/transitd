// Package goldenjson defines the on-disk JSON schema shared by the decide
// golden files (internal/decide/testdata/golden/decide/*.json) and the
// TestGoldenDecide harness that enforces them.
//
// A golden file contains a full scenario: the decision tuning, the persisted
// decision state at scenario start, and an ordered list of steps. Each step
// carries the observed TransitHealth input and the Decision the engine is
// expected to return for that input, byte-exact.
//
// The package is deliberately dependency-free: it only holds the wire shape.
// The harness in package decide maps these types onto config.Config and
// decide.TransitHealth, so this schema never imports the engine.
package goldenjson

// Config is the decision tuning needed to reproduce a scenario. It is a
// deliberate subset of config.Config restricted to the fields Evaluate reads,
// so a golden file stays independent of unrelated configuration surface.
type Config struct {
	BaseLP       int     `json:"base_lp"`
	LPStep       int     `json:"lp_step"`
	MarginMs     float64 `json:"margin_ms"`
	WinCycles    int     `json:"win_cycles"`
	DwellSeconds int     `json:"dwell_seconds"`
	MaxSwitches  int     `json:"max_switches"`
	LossDropPct  float64 `json:"loss_drop_pct"`
}

// Transit is one observed transit-health sample fed to Evaluate.
type Transit struct {
	Name      string  `json:"name"`
	SessionUp bool    `json:"session_up"`
	LossPct   float64 `json:"loss_pct"`
	EwmaMs    float64 `json:"ewma_ms"`
}

// State is the persisted decision state at scenario start.
type State struct {
	Primary string `json:"primary"`
	// LastSwitchAgoSeconds models the persisted LastSwitch as "this many
	// seconds before the scenario clock starts". Only the elapsed-time
	// comparison matters to Evaluate, so an absolute timestamp would make the
	// goldens non-portable across runs.
	LastSwitchAgoSeconds int64          `json:"last_switch_ago_seconds"`
	SwitchHourWnd        int            `json:"switch_hour_wnd"`
	Frozen               bool           `json:"frozen"`
	WinStreak            map[string]int `json:"win_streak,omitempty"`
}

// Step is one Evaluate call: the health snapshot plus the expected Decision.
type Step struct {
	Health []Transit `json:"health"`
	// AdvanceSeconds moves the scenario clock forward before this step runs, so
	// a scenario can sit inside or past the dwell window across steps.
	AdvanceSeconds int64 `json:"advance_seconds,omitempty"`
	// Expect is the Decision the engine must return for this step.
	Expect Decision `json:"expect"`
}

// Decision mirrors decide.Decision with a stable JSON shape. AssignedLP is a
// map, so encoding/json emits its keys sorted, keeping goldens byte-stable.
type Decision struct {
	Primary    string         `json:"primary"`
	Switched   bool           `json:"switched"`
	Reason     string         `json:"reason"`
	Frozen     bool           `json:"frozen"`
	AssignedLP map[string]int `json:"assigned_lp"`
}

// Golden is one scenario file.
type Golden struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Config      Config `json:"config"`
	State       State  `json:"state"`
	Steps       []Step `json:"steps"`
}
