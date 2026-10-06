package decide

import (
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
)

// The scenario behaviors that used to live here (initial adoption, margin
// hysteresis, challenger win cycles, dwell suppression, hard-down failover,
// loss exclusion, freeze-after-max-switches, no-eligible-transit) are now the
// byte-exact golden baseline in testdata/golden/decide, enforced by
// TestGoldenDecide. This file keeps the shared fixtures plus the small unit
// invariants that read more clearly as code than as a golden document: the
// ranking tie-break, the exclusive loss boundary, LP ladder arithmetic, and
// the first-boot no-op.

func testCfg() *config.Config {
	c := &config.Config{
		RouterName:  "r-test",
		BindAddr:    "10.0.0.1",
		BaseLP:      200,
		LPStep:      50,
		MarginMs:    10,
		WinCycles:   2,
		Dwell:       time.Minute,
		MaxSwitches: 2,
		LossDropPct: 5,
	}
	_ = c.Validate()
	return c
}

func health(name string, up bool, loss float64, ewma float64) TransitHealth {
	return TransitHealth{Name: name, SessionUp: up, LossPct: loss, EwmaMs: ewma}
}

// TestRankTieBreakByName pins the total order: equal EWMA sorts by name so the
// ranking is deterministic regardless of input order.
func TestRankTieBreakByName(t *testing.T) {
	e := NewEngine(testCfg(), &State{})
	ranked := e.rank([]TransitHealth{
		health("zebra", true, 0, 20),
		health("alpha", true, 0, 20),
		health("mid", true, 0, 20),
	})
	want := []string{"alpha", "mid", "zebra"}
	if got := names(ranked); !equalStrings(got, want) {
		t.Fatalf("rank order = %v, want %v", got, want)
	}
}

// TestLossBoundaryIsExclusive documents the loss_drop_pct contract: the
// threshold is inclusive on the drop side, so a transit exactly at the limit
// is excluded and only strictly-lower loss stays eligible.
func TestLossBoundaryIsExclusive(t *testing.T) {
	cfg := testCfg()
	e := NewEngine(cfg, &State{})
	ranked := e.rank([]TransitHealth{
		health("at-limit", true, cfg.LossDropPct, 10),
		health("over", true, cfg.LossDropPct+0.1, 10),
		health("under", true, cfg.LossDropPct-0.1, 10),
	})
	got := names(ranked)
	if len(got) != 1 || got[0] != "under" {
		t.Fatalf("eligible = %v, want only [under] (>= loss_drop_pct is excluded)", got)
	}
}

// TestLPLadderDescendsByStep checks the LP assignment arithmetic across a
// ranking longer than the two-transit goldens exercise.
func TestLPLadderDescendsByStep(t *testing.T) {
	e := NewEngine(testCfg(), &State{})
	d := e.Evaluate([]TransitHealth{
		health("first", true, 0, 10),
		health("second", true, 0, 20),
		health("third", true, 0, 30),
	})
	if d.Primary != "first" {
		t.Fatalf("primary = %q, want first", d.Primary)
	}
	want := map[string]int{"first": 200, "second": 150, "third": 100}
	for name, lp := range want {
		if d.AssignedLP[name] != lp {
			t.Fatalf("LP[%q] = %d, want %d (full %v)", name, d.AssignedLP[name], lp, d.AssignedLP)
		}
	}
}

// TestInitialAdoptionNoEligibleTransit covers first boot with every transit
// down: nothing is adopted, no LP is emitted, and no reason is raised because
// there was no incumbent to defend.
func TestInitialAdoptionNoEligibleTransit(t *testing.T) {
	e := NewEngine(testCfg(), &State{})
	d := e.Evaluate([]TransitHealth{health("a", false, 0, 0), health("b", false, 0, 0)})
	if d.Primary != "" || d.Switched || len(d.AssignedLP) != 0 {
		t.Fatalf("first boot with no eligible transit must be a no-op: %+v", d)
	}
}

func names(hs []TransitHealth) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.Name
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
