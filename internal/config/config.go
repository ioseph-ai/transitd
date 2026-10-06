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

	// ProbeInterval bounds one transit's probe cadence; default 30s.
	ProbeInterval time.Duration `yaml:"probe_interval"` // default 30s

	// BGPNeighbor is the BGP peer address of this transit's upstream, as it
	// appears in `show bgp summary json` on this router. It is what lets
	// bgpwatch attribute a session state to a transit (issue #4): without it the
	// agent can measure a transit's latency but cannot say whether its session
	// is up. Empty means "not BGP-observed" and the transit keeps its probe-only
	// health view.
	BGPNeighbor string `yaml:"bgp_neighbor"`
}

// BGPWatchConfig configures vtysh JSON polling of BGP session and prefix state
// (issue #4). Polling is bounded and read-only: it issues `show` commands only,
// so it can never be the thing that changes a router.
type BGPWatchConfig struct {
	// Enabled turns the poller on. Off by default, like every other capability.
	Enabled bool `yaml:"enabled"`

	// MaxPrefixes caps how many prefixes a prefix-level view will parse. A table
	// larger than this is an ERROR, never a silent truncation: a truncated RIB
	// would make "does peer X see prefix P" answer a confident no about a prefix
	// it simply did not read. Default 1000.
	MaxPrefixes int `yaml:"max_prefixes"`

	// Interval is the poll cadence. It is floored at 1s — bgpwatch may never poll
	// faster than 1 Hz, because `show bgp ... json` on a full table is a
	// non-trivial CPU and memory cost on a 1 vCPU router.
	Interval time.Duration `yaml:"interval"`
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

	// BGPWatch controls vtysh JSON polling of BGP session + prefix state
	// (issue #4).
	BGPWatch BGPWatchConfig `yaml:"bgpwatch"`

	ListenMetrics string `yaml:"listen_metrics"` // default :9414
}

// egressInterfaceRe is the accepted shape of an egress interface name. The
// value is passed as a single argv element to `ip route get` (never through a
// shell), but a transit whose "interface" contains whitespace, slashes or
// control characters is a configuration bug we refuse at startup rather than
// discover as a confusing exec failure later.
var egressInterfaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]*$`)

// Defaults and floors for bgpwatch (issue #4). They live here, next to the
// struct they default, so the poller and the validator cannot disagree.
const (
	// DefaultBGPWatchInterval is the default BGP JSON poll cadence.
	DefaultBGPWatchInterval = 5 * time.Second
	// MinBGPWatchInterval is the hard 1 Hz poll floor. Nothing may poll BGP
	// faster than this, whatever the config says.
	MinBGPWatchInterval = 1 * time.Second
	// DefaultMaxPrefixes is the default cap on parsed prefixes per view.
	DefaultMaxPrefixes = 1000
)

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
		if ip := net.ParseIP(t.ProbeTarget); ip == nil {
			return fmt.Errorf("transit %q: probe_target %q is not an IP", t.Name, t.ProbeTarget)
		} else if src := net.ParseIP(t.ProbeSource); (src.To4() != nil) != (ip.To4() != nil) {
			// A v4 source with a v6 target (or the reverse) cannot be pinned:
			// the source selects a policy route within its own family, and the
			// kernel would refuse `ip route get <v6> from <v4>`. Rejecting it
			// here turns a per-cycle exec failure into a startup error.
			return fmt.Errorf("transit %q: probe_source %q and probe_target %q are from different address families", t.Name, t.ProbeSource, t.ProbeTarget)
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
		// bgp_neighbor is optional, but a set one must be an address: it is the
		// key bgpwatch matches against `show bgp summary json`, so a hostname or a
		// typo would silently never match and the transit would report no session
		// state rather than a startup error naming the bad value.
		if t.BGPNeighbor != "" && net.ParseIP(t.BGPNeighbor) == nil {
			return fmt.Errorf("transit %q: bgp_neighbor %q is not an IP", t.Name, t.BGPNeighbor)
		}
	}
	// Defaults for per-transit optional tuning. Applied only after every transit
	// has passed validation, so a rejected config is never partially mutated.
	for i := range c.Transits {
		if c.Transits[i].ProbeInterval == 0 {
			c.Transits[i].ProbeInterval = c.ProbeIntervalDefault()
		}
	}
	// bgpwatch (issue #4). A prefix cap of 0 means "unspecified" -> default. A
	// negative cap is refused rather than interpreted: it can only come from a
	// typo, and treating it as "unlimited" would remove the bound that stops a
	// full-table parse from hammering a 1 vCPU router.
	if c.BGPWatch.MaxPrefixes < 0 {
		return fmt.Errorf("bgpwatch.max_prefixes: %d is negative — a prefix cap is a positive bound", c.BGPWatch.MaxPrefixes)
	}
	if c.BGPWatch.MaxPrefixes == 0 {
		c.BGPWatch.MaxPrefixes = DefaultMaxPrefixes
	}
	// The 1 Hz floor is a property of the poller, not a preference: `show bgp
	// ... json` on a full table is expensive, and a sub-second cadence multiplies
	// that cost by an integer factor without adding resolution anyone reads. A
	// configured interval below the floor is clamped, and an unset one takes the
	// default. Clamping (rather than rejecting) keeps an operator who writes
	// `interval: 100ms` from getting a config error for asking for "as fast as
	// allowed".
	if c.BGPWatch.Interval == 0 {
		c.BGPWatch.Interval = DefaultBGPWatchInterval
	}
	if c.BGPWatch.Interval < MinBGPWatchInterval {
		c.BGPWatch.Interval = MinBGPWatchInterval
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
