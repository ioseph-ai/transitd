package config

import (
	"strings"
	"testing"
	"time"
)

func base() *Config {
	return &Config{
		RouterName: "r-alpha",
		BindAddr:   "10.0.0.1",
		Transits: []Transit{
			{Name: "a", ImportMap: "A-LOCAL-IN", ProbeTargets: []string{"2001:db8::1"}},
			{Name: "b", ImportMap: "B-LOCAL-IN", ProbeTargets: []string{"2001:db8::2"}},
		},
	}
}

func TestValidateOK(t *testing.T) {
	c := base()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.BaseLP != 200 || c.LPStep != 50 || c.WinCycles != 3 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Dwell != 5*time.Minute || c.MaxSwitches != 4 || c.Settle != 60*time.Second {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.ListenMetrics != ":9414" || c.LossDropPct != 5.0 || c.MarginMs != 10.0 {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"no router name", func(c *Config) { c.RouterName = "" }, "router_name"},
		{"no bind", func(c *Config) { c.BindAddr = "" }, "bind_addr"},
		{"bad bind", func(c *Config) { c.BindAddr = "not-an-ip" }, "not an IP"},
		{"no transits", func(c *Config) { c.Transits = nil }, "at least one transit"},
		{"dup names", func(c *Config) {
			c.Transits = append(c.Transits, Transit{Name: "a", ImportMap: "X"})
		}, "duplicate name"},
		{"missing import map", func(c *Config) { c.Transits[0].ImportMap = "" }, "import_map is required"},
		{"bad probe target", func(c *Config) { c.Transits[0].ProbeTargets = []string{"nope"} }, "not an IP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mut(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}
