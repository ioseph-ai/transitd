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
			{
				Name: "a", ImportMap: "A-LOCAL-IN",
				ProbeSource: "192.0.2.1", ProbeTarget: "203.0.113.5", EgressInterface: "eth0",
				ProbeTargets: []string{"2001:db8::1"},
			},
			{
				Name: "b", ImportMap: "B-LOCAL-IN",
				ProbeSource: "192.0.2.2", ProbeTarget: "203.0.113.6", EgressInterface: "eth1",
				ProbeTargets: []string{"2001:db8::2"},
			},
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
		{"missing probe source", func(c *Config) { c.Transits[0].ProbeSource = "" }, "probe_source is required"},
		{"bad probe source", func(c *Config) { c.Transits[0].ProbeSource = "eth0" }, "probe_source \"eth0\" is not an IP"},
		{"missing probe target", func(c *Config) { c.Transits[0].ProbeTarget = "" }, "probe_target is required"},
		{"bad probe target", func(c *Config) { c.Transits[0].ProbeTarget = "not-an-ip" }, "probe_target \"not-an-ip\" is not an IP"},
		{"missing egress interface", func(c *Config) { c.Transits[0].EgressInterface = "" }, "egress_interface is required"},
		{"bad egress interface", func(c *Config) { c.Transits[0].EgressInterface = "eth 0" }, "not a valid interface name"},
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

// TestProbeDefaultsAreApplied pins the per-transit defaults Validate fills in:
// an unset probe_interval must become 30s, and a set one must survive.
func TestProbeDefaultsAreApplied(t *testing.T) {
	c := base()
	c.Transits[1].ProbeInterval = 90 * time.Second
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c.Transits[0].ProbeInterval; got != 30*time.Second {
		t.Errorf("transit a probe_interval = %v, want default 30s", got)
	}
	if got := c.Transits[1].ProbeInterval; got != 90*time.Second {
		t.Errorf("transit b probe_interval = %v, want preserved 90s", got)
	}
}

// TestBothAddressFamiliesAccepted keeps the pinning fields AF-agnostic: the v4
// and v6 paths are structurally identical, so a v6 source/target pair must
// validate exactly like the v4 one in base().
func TestBothAddressFamiliesAccepted(t *testing.T) {
	c := base()
	c.Transits[0].ProbeSource = "2001:db8::1"
	c.Transits[0].ProbeTarget = "2001:db8:dead::5"
	if err := c.Validate(); err != nil {
		t.Fatalf("v6 pinning rejected: %v", err)
	}
}
