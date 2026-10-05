// Package config defines transitd's on-disk configuration and validates it.
package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Transit describes one upstream transit as seen from this router.
type Transit struct {
	Name          string        `yaml:"name"`
	ImportMap     string        `yaml:"import_map"`     // route-map applied inbound from this transit
	ProbeTargets  []string      `yaml:"probe_targets"`  // IPs pinged via this transit
	ProbeInterval time.Duration `yaml:"probe_interval"` // default 30s
}

// Config is the full agent configuration.
type Config struct {
	RouterName string `yaml:"router_name"`

	// Gossip mesh (memberlist). BindAddr is typically the router's mesh
	// interface address; Key is the 32-byte shared secret (base64).
	BindAddr string   `yaml:"bind_addr"`
	Join     []string `yaml:"join"`
	KeyB64   string   `yaml:"key_b64"`

	// Decision tuning.
	BaseLP      int           `yaml:"base_lp"`               // LP for rank 1 (default 200)
	LPStep      int           `yaml:"lp_step"`               // LP decrement per rank (default 50)
	MarginMs    float64       `yaml:"margin_ms"`             // winner must beat incumbent by this EWMA latency margin
	WinCycles   int           `yaml:"win_cycles"`            // consecutive winning cycles required
	Dwell       time.Duration `yaml:"dwell"`                 // min time between switches
	MaxSwitches int           `yaml:"max_switches_per_hour"` // above this: freeze + alert
	Settle      time.Duration `yaml:"settle"`                // observe-only time after startup
	LossDropPct float64       `yaml:"loss_drop_pct"`         // exclude transit from ranking above this loss

	Transits []Transit `yaml:"transits"`

	ListenMetrics string `yaml:"listen_metrics"` // default :9414
}

// Validate checks structural invariants. It deliberately rejects anything
// the agent cannot apply safely at runtime.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.RouterName) == "" {
		return fmt.Errorf("router_name is required")
	}
	if c.BindAddr == "" {
		return fmt.Errorf("bind_addr is required")
	}
	if ip := net.ParseIP(c.BindAddr); ip == nil {
		return fmt.Errorf("bind_addr %q is not an IP", c.BindAddr)
	}
	if len(c.Transits) < 1 {
		return fmt.Errorf("at least one transit is required")
	}
	names := map[string]bool{}
	for i, t := range c.Transits {
		if t.Name == "" {
			return fmt.Errorf("transit[%d]: name is required", i)
		}
		if names[t.Name] {
			return fmt.Errorf("transit[%d]: duplicate name %q", i, t.Name)
		}
		names[t.Name] = true
		if t.ImportMap == "" {
			return fmt.Errorf("transit %q: import_map is required (runtime LP is written into it)", t.Name)
		}
		for _, tgt := range t.ProbeTargets {
			if net.ParseIP(tgt) == nil {
				return fmt.Errorf("transit %q: probe target %q is not an IP", t.Name, tgt)
			}
		}
	}
	// Defaults for optional tuning.
	if c.BaseLP == 0 {
		c.BaseLP = 200
	}
	if c.LPStep == 0 {
		c.LPStep = 50
	}
	if c.WinCycles == 0 {
		c.WinCycles = 3
	}
	if c.Dwell == 0 {
		c.Dwell = 5 * time.Minute
	}
	if c.MaxSwitches == 0 {
		c.MaxSwitches = 4
	}
	if c.Settle == 0 {
		c.Settle = 60 * time.Second
	}
	if c.ListenMetrics == "" {
		c.ListenMetrics = ":9414"
	}
	if c.LossDropPct == 0 {
		c.LossDropPct = 5.0
	}
	if c.MarginMs <= 0 {
		c.MarginMs = 10.0
	}
	return nil
}

// ProbeIntervalDefault returns the default probe interval.
func (c *Config) ProbeIntervalDefault() time.Duration { return 30 * time.Second }
