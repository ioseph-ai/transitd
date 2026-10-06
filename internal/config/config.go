// Package config defines transitd's on-disk configuration and validates it.
package config

import (
	"encoding/base64"
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

// Gossip configures the memberlist health mesh (issue #3). The mesh is assumed
// to run on a trusted transport (wireguard or an IXP/LAN under the operator's
// control); the key authenticates and encrypts it but is not a privilege
// boundary — anyone holding it can inject health state, so it is treated like
// an SSH key.
//
// The block is opt-in: an empty Key disables the mesh entirely, which is the
// right default for a single-router deployment and lets the unit tier run
// without opening a socket. Because the block is opt-in, `join` without a `key`
// is a configuration error rather than a silent no-op: an operator who wrote a
// peer list meant to have a mesh.
type Gossip struct {
	// Key is the shared mesh secret, base64, decoded to a 16, 24 or 32 byte
	// AES key (the lengths memberlist accepts). Empty disables the mesh.
	Key string `yaml:"key"`

	// BindPort is the mesh UDP+TCP port. Zero means the default, 7946. Zero is
	// also what tests use to mean "any free port", which is why a literal 0 is
	// not rejected here — Validate only refuses an explicitly impossible port.
	BindPort int `yaml:"bind_port"`

	// Join lists peers to contact at startup, each "host" or "host:port". A
	// failed join is not fatal: the mesh keeps retrying and reports the state
	// through healthz, because a router that cannot reach its peers must still
	// measure and act on its own transits.
	Join []string `yaml:"join"`
}

// GossipBindPortDefault is the memberlist default mesh port.
const GossipBindPortDefault = 7946

// Enabled reports whether the operator configured a mesh. An empty key means no
// mesh: the agent then runs with no peers rather than joining with a zero key
// (which memberlist would treat as no encryption at all).
func (g *Gossip) Enabled() bool { return strings.TrimSpace(g.Key) != "" }

// KeyBytes decodes the configured shared key and checks it against the lengths
// memberlist's AES cipher accepts. It is the one place the key is decoded, so
// every consumer (the mesh, and the control channel that reuses the key for
// local authentication) sees the same validation.
func (g *Gossip) KeyBytes() ([]byte, error) {
	if !g.Enabled() {
		return nil, nil
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(g.Key))
	if err != nil {
		return nil, fmt.Errorf("gossip.key is not valid base64: %w", err)
	}
	switch len(k) {
	case 16, 24, 32:
		return k, nil
	default:
		return nil, fmt.Errorf("gossip.key decodes to %d bytes; memberlist accepts a 16, 24 or 32 byte key", len(k))
	}
}

// Port returns the effective mesh port with the default applied.
func (g *Gossip) Port() int {
	if g.BindPort == 0 {
		return GossipBindPortDefault
	}
	return g.BindPort
}

// validate checks the mesh block's structural invariants. The mesh is opt-in,
// so an empty block is valid and means "no mesh"; every other check only applies
// once a key is present.
func (g *Gossip) validate() error {
	if !g.Enabled() {
		// A join list without a key is a half-configured mesh: the operator
		// wrote peers expecting to join them, and a silent no-op would leave
		// the agent alone on the network with no error to explain it.
		if len(g.Join) > 0 {
			return fmt.Errorf("gossip.join is set but gossip.key is empty — set the shared mesh key, or remove the peer list to run with no mesh")
		}
		return nil
	}
	if _, err := g.KeyBytes(); err != nil {
		return err
	}
	if g.BindPort < 0 || g.BindPort > 65535 {
		return fmt.Errorf("gossip.bind_port %d is not a valid port", g.BindPort)
	}
	for i, peer := range g.Join {
		if strings.TrimSpace(peer) == "" {
			return fmt.Errorf("gossip.join[%d] is empty", i)
		}
	}
	return nil
}

// Config is the full agent configuration.
type Config struct {
	RouterName string `yaml:"router_name"`

	// BindAddr is the router's mesh interface address: the local address the
	// memberlist transport binds and advertises. It stays top-level because it
	// is a per-host fact (like router_name), not a mesh protocol setting.
	BindAddr string `yaml:"bind_addr"`

	// Gossip groups the mesh protocol settings.
	Gossip Gossip `yaml:"gossip"`

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
	if err := c.Gossip.validate(); err != nil {
		return err
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
	}
	// Defaults for per-transit optional tuning. Applied only after every transit
	// has passed validation, so a rejected config is never partially mutated.
	for i := range c.Transits {
		if c.Transits[i].ProbeInterval == 0 {
			c.Transits[i].ProbeInterval = c.ProbeIntervalDefault()
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
