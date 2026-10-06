// Package config defines transitd's on-disk configuration and validates it.
package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Transit describes one upstream transit as seen from this router.
type Transit struct {
	Name      string `yaml:"name"`
	ImportMap string `yaml:"import_map"` // route-map applied inbound from this transit

	// Probe pinning (issue #1). A probe's source address selects the source
	// IP, not the egress path: without policy routing the probe can leave
	// through the default/ECMP path with a foreign source. ProbeSource is the
	// transit's own interface address — it is the `from` selector of the
	// startup `ip route get` verification and the `-I` pin of the ICMP probe.
	// ProbeTarget is the canary destination used for both. EgressInterface is
	// the interface the probes must actually leave through; a transit whose
	// resolved egress does not match it is unverified and exports no samples.
	ProbeSource     string `yaml:"probe_source"`
	ProbeTarget     string `yaml:"probe_target"`
	EgressInterface string `yaml:"egress_interface"`

	// ProbeTargets is the anycast target set carried over from the first
	// scaffold. The MVP probes ProbeTarget only; this stays for the later
	// multi-target probe work and is validated when set.
	ProbeTargets []string `yaml:"probe_targets"`

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

// egressInterfaceRe is the accepted shape of an egress interface name. The
// value is passed as a single argv element to `ip route get` (never through a
// shell), but a transit whose "interface" contains whitespace, slashes or
// control characters is a configuration bug we refuse at startup rather than
// discover as a confusing exec failure later.
var egressInterfaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]*$`)

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
	for i := range c.Transits {
		t := &c.Transits[i]
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
		// Probe pinning fields. These are required: a transit that cannot be
		// pinned cannot be verified, and an unverified transit must export no
		// probe samples (issue #1). Refusing them at config time turns a
		// silent mis-measurement into a startup error.
		if t.ProbeSource == "" {
			return fmt.Errorf("transit %q: probe_source is required (the transit's own interface address)", t.Name)
		}
		if net.ParseIP(t.ProbeSource) == nil {
			return fmt.Errorf("transit %q: probe_source %q is not an IP", t.Name, t.ProbeSource)
		}
		if t.ProbeTarget == "" {
			return fmt.Errorf("transit %q: probe_target is required", t.Name)
		}
		if net.ParseIP(t.ProbeTarget) == nil {
			return fmt.Errorf("transit %q: probe_target %q is not an IP", t.Name, t.ProbeTarget)
		}
		if t.EgressInterface == "" {
			return fmt.Errorf("transit %q: egress_interface is required (expected egress for pin verification)", t.Name)
		}
		if !egressInterfaceRe.MatchString(t.EgressInterface) {
			return fmt.Errorf("transit %q: egress_interface %q is not a valid interface name", t.Name, t.EgressInterface)
		}
		for _, tgt := range t.ProbeTargets {
			if net.ParseIP(tgt) == nil {
				return fmt.Errorf("transit %q: probe target %q is not an IP", t.Name, tgt)
			}
		}
		if t.ProbeInterval == 0 {
			t.ProbeInterval = c.ProbeIntervalDefault()
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
