package decide

import (
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
)

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

func TestInitialAdoption(t *testing.T) {
	e := NewEngine(testCfg(), &State{})
	d := e.Evaluate([]TransitHealth{
		health("a", true, 0, 40),
		health("b", true, 0, 20),
	})
	if !d.Switched || d.Primary != "b" {
		t.Fatalf("want initial adoption of b, got %+v", d)
	}
	if d.AssignedLP["b"] != 200 || d.AssignedLP["a"] != 150 {
		t.Fatalf("LP ladder wrong: %+v", d.AssignedLP)
	}
}

func TestIncumbentMarginHysteresis(t *testing.T) {
	cfg := testCfg()
	e := NewEngine(cfg, &State{Primary: "a", LastSwitch: time.Now().Add(-10 * time.Minute)})
	// b beats a by less than margin: no switch even after many cycles
	for i := 0; i < 5; i++ {
		d := e.Evaluate([]TransitHealth{
			health("a", true, 0, 30),
			health("b", true, 0, 25), // margin 5 < 10
		})
		if d.Switched {
			t.Fatalf("switched without margin on cycle %d", i)
		}
	}
}

func TestChallengerWinCycles(t *testing.T) {
	cfg := testCfg()
	e := NewEngine(cfg, &State{Primary: "a", LastSwitch: time.Now().Add(-10 * time.Minute)})
	var d Decision
	for i := 0; i < cfg.WinCycles; i++ {
		d = e.Evaluate([]TransitHealth{
			health("a", true, 0, 50),
			health("b", true, 0, 10), // margin 40 >= 10
		})
	}
	if !d.Switched || d.Primary != "b" {
		t.Fatalf("want switch to b after %d cycles, got %+v", cfg.WinCycles, d)
	}
}

func TestDwellBlocksSwitch(t *testing.T) {
	cfg := testCfg()
	e := NewEngine(cfg, &State{Primary: "a", LastSwitch: time.Now()}) // just switched
	d := e.Evaluate([]TransitHealth{
		health("a", false, 0, 0), // incumbent hard down
		health("b", true, 0, 10),
	})
	if d.Switched {
		t.Fatalf("dwell violated: %+v", d)
	}
}

func TestHardDownForcesSwitchAfterDwell(t *testing.T) {
	cfg := testCfg()
	e := NewEngine(cfg, &State{Primary: "a", LastSwitch: time.Now().Add(-time.Hour)})
	d := e.Evaluate([]TransitHealth{
		health("a", false, 0, 0),
		health("b", true, 0, 10),
	})
	if !d.Switched || d.Primary != "b" {
		t.Fatalf("hard-down must switch immediately past dwell: %+v", d)
	}
}

func TestLossExclusion(t *testing.T) {
	e := NewEngine(testCfg(), &State{Primary: "a", LastSwitch: time.Now().Add(-time.Hour)})
	d := e.Evaluate([]TransitHealth{
		health("a", true, 30, 5), // high loss -> excluded
		health("b", true, 0, 100),
	})
	if !d.Switched || d.Primary != "b" {
		t.Fatalf("loss-excluded incumbent must lose: %+v", d)
	}
}

func TestFreezeAfterMaxSwitches(t *testing.T) {
	cfg := testCfg()
	st := &State{Primary: "a", LastSwitch: time.Now().Add(-time.Hour), SwitchHourWnd: cfg.MaxSwitches}
	e := NewEngine(cfg, st)
	d := e.Evaluate([]TransitHealth{
		health("a", false, 0, 0),
		health("b", true, 0, 10),
	})
	if d.Switched || !d.Frozen {
		t.Fatalf("must freeze above max switches: %+v", d)
	}
}

func TestNoEligibleTransit(t *testing.T) {
	e := NewEngine(testCfg(), &State{Primary: "a", LastSwitch: time.Now().Add(-time.Hour)})
	d := e.Evaluate([]TransitHealth{health("a", false, 0, 0), health("b", false, 0, 0)})
	if len(d.AssignedLP) != 0 {
		t.Fatalf("no LP changes expected: %+v", d.AssignedLP)
	}
}
