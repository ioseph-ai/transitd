package decide

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/decide/goldenjson"
)

// goldenDir holds the decide regression baseline. Each *.json file is a full
// scenario: tuning + starting state + ordered steps of (health input, expected
// Decision). TestGoldenDecide walks the directory, replays every scenario
// through Engine.Evaluate, and compares the produced decisions against the
// committed expectations.
//
// Regenerate deliberately with `make golden-update` (UPDATE_GOLDEN=1). During
// regeneration the harness rewrites each file from the engine's actual output;
// it never loosens the comparison in normal mode, so an unexpected behavior
// change fails CI rather than silently rewriting the baseline.
const goldenDir = "testdata/golden/decide"

// scenarioClockBase is a fixed instant so goldens are reproducible on any
// machine and timezone. Only elapsed durations matter to Evaluate, but a fixed
// base keeps the encoded expectations byte-stable.
var scenarioClockBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestGoldenDecide(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") == "1"

	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read golden dir %q: %v", goldenDir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, e.Name())
	}
	if len(files) == 0 {
		t.Fatalf("no golden scenarios in %q; the decide baseline must not be empty", goldenDir)
	}
	sort.Strings(files)

	if update {
		t.Logf("UPDATE_GOLDEN=1: regenerating %d decide golden scenario(s)", len(files))
	}

	for _, name := range files {
		name := name
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(goldenDir, name)
			// The path is built from a constant dir and entries returned by
			// os.ReadDir one level deep, so there is no variable traversal.
			raw, err := os.ReadFile(path) //nolint:gosec // fixed golden dir, no user input
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			var g goldenjson.Golden
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&g); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if g.Name == "" {
				t.Fatalf("%s: scenario is missing a \"name\"", path)
			}
			if len(g.Steps) == 0 {
				t.Fatalf("%s: scenario has no steps", path)
			}

			got := replayScenario(t, g)

			if update {
				updated, err := encodeGolden(g, got)
				if err != nil {
					t.Fatalf("encode %s: %v", path, err)
				}
				if bytes.Equal(updated, raw) {
					return
				}
				if err := os.WriteFile(path, updated, 0o644); err != nil { //nolint:gosec // committed fixtures are world-readable
					t.Fatalf("write %s: %v", path, err)
				}
				t.Logf("updated %s", path)
				return
			}

			want, err := encodeGolden(g, got)
			if err != nil {
				t.Fatalf("encode %s: %v", path, err)
			}
			if !bytes.Equal(raw, want) {
				t.Errorf("golden mismatch in %s\n%s", path, firstDiff(raw, want))
			}
		})
	}
}

// replayScenario builds a fresh engine from the scenario header, pins its
// clock, and runs each step in order, returning the decisions the engine
// actually produced.
//
// Evaluate is a pure ranking primitive: it mutates State (win streaks,
// LastSwitch, switch window, freeze) but deliberately does not write the
// chosen Primary back. The driver loop (internal/agent, future work) persists
// it, so the harness models exactly that: after each cycle, a switched
// decision is folded into State.Primary before the next step runs. Without
// this, every steady-state cycle would look like a fresh "initial adoption",
// which is not how the agent behaves.
func replayScenario(t *testing.T, g goldenjson.Golden) []goldenjson.Decision {
	t.Helper()

	cfg := configFromGolden(g.Config)
	st := &State{
		Primary:       g.State.Primary,
		LastSwitch:    scenarioClockBase.Add(-time.Duration(g.State.LastSwitchAgoSeconds) * time.Second),
		SwitchHourWnd: g.State.SwitchHourWnd,
		Frozen:        g.State.Frozen,
		WinStreak:     cloneStreak(g.State.WinStreak),
	}

	now := scenarioClockBase
	e := NewEngine(cfg, st)
	e.now = func() time.Time { return now }

	out := make([]goldenjson.Decision, 0, len(g.Steps))
	for _, step := range g.Steps {
		now = now.Add(time.Duration(step.AdvanceSeconds) * time.Second)

		health := make([]TransitHealth, 0, len(step.Health))
		for _, h := range step.Health {
			health = append(health, TransitHealth{
				Name:      h.Name,
				SessionUp: h.SessionUp,
				LossPct:   h.LossPct,
				EwmaMs:    h.EwmaMs,
			})
		}

		d := e.Evaluate(health)
		out = append(out, goldenjson.Decision{
			Primary:    d.Primary,
			Switched:   d.Switched,
			Reason:     d.Reason,
			Frozen:     d.Frozen,
			AssignedLP: nonNilLP(d.AssignedLP),
		})

		// Driver step: persist the decision the way the agent loop does.
		if d.Switched {
			e.State.Primary = d.Primary
		}
	}
	return out
}

// configFromGolden materializes the scenario's tuning subset as a
// config.Config for NewEngine. The golden files are trusted fixtures, so the
// subset is copied verbatim without running Validate.
func configFromGolden(g goldenjson.Config) *config.Config {
	return &config.Config{
		BaseLP:      g.BaseLP,
		LPStep:      g.LPStep,
		MarginMs:    g.MarginMs,
		WinCycles:   g.WinCycles,
		Dwell:       time.Duration(g.DwellSeconds) * time.Second,
		MaxSwitches: g.MaxSwitches,
		LossDropPct: g.LossDropPct,
	}
}

// encodeGolden serializes a scenario with the given decisions substituted for
// each step's expectations, using the exact layout the committed goldens use.
// The trailing newline matches POSIX text-file convention and gofumpt's view.
func encodeGolden(g goldenjson.Golden, decisions []goldenjson.Decision) ([]byte, error) {
	out := g
	out.Steps = make([]goldenjson.Step, len(g.Steps))
	copy(out.Steps, g.Steps)
	for i := range out.Steps {
		if i < len(decisions) {
			out.Steps[i].Expect = decisions[i]
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// nonNilLP keeps an empty assignment encoded as {} rather than null, so the
// golden for "no eligible transit" is explicit about producing no LP changes.
func nonNilLP(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func cloneStreak(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	c := make(map[string]int, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// firstDiff renders the first differing line between the committed golden and
// the freshly encoded expectation, with a little context, so a failure names
// the offending field instead of dumping both documents.
func firstDiff(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	n := len(gotLines)
	if len(wantLines) < n {
		n = len(wantLines)
	}
	for i := 0; i < n; i++ {
		if gotLines[i] != wantLines[i] {
			return fmt.Sprintf("first difference at line %d:\n  committed: %s\n  produced:  %s",
				i+1, gotLines[i], wantLines[i])
		}
	}
	if len(gotLines) != len(wantLines) {
		return fmt.Sprintf("documents differ in length: committed %d lines, produced %d lines",
			len(gotLines), len(wantLines))
	}
	return "documents are identical"
}
