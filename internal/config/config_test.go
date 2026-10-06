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
		{"cross-family source/target", func(c *Config) {
			c.Transits[0].ProbeSource = "192.0.2.1"
			c.Transits[0].ProbeTarget = "2001:db8::5"
		}, "different address families"},
		{"cross-family source/target (reverse)", func(c *Config) {
			c.Transits[0].ProbeSource = "2001:db8::1"
			c.Transits[0].ProbeTarget = "192.0.2.5"
		}, "different address families"},
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

// TestValidateRejectsWithoutPartialMutation pins that a config which fails
// validation is not left half-defaulted: per-transit defaults are applied only
// once every transit has passed. A caller that logs a rejected config must not
// see it look partly valid.
func TestValidateRejectsWithoutPartialMutation(t *testing.T) {
	c := base()
	// The first transit is valid and has no interval; the second is broken.
	c.Transits[1].ProbeTarget = "not-an-ip"
	if err := c.Validate(); err == nil {
		t.Fatal("expected a validation error")
	}
	if got := c.Transits[0].ProbeInterval; got != 0 {
		t.Errorf("rejected config was mutated: transit a probe_interval = %v, want 0", got)
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

// gossipKey is the base64 of 32 documentation bytes, for the mesh tests.
const gossipKey = "ZXhhbXBsZS1rZXktbm90LWEtc2VjcmV0LTMyYnl0ZXM="

// TestGossipDisabledByDefault pins the opt-in default: a config with no gossip
// block runs with no mesh, and that is valid — single-router deployments exist.
func TestGossipDisabledByDefault(t *testing.T) {
	c := base()
	if err := c.Validate(); err != nil {
		t.Fatalf("mesh-less config rejected: %v", err)
	}
	if c.Gossip.Enabled() {
		t.Error("Gossip.Enabled() = true with no key")
	}
	if got, err := c.Gossip.KeyBytes(); err != nil || got != nil {
		t.Errorf("KeyBytes() = %v/%v, want nil/nil for a disabled mesh", got, err)
	}
}

// TestGossipJoinWithoutKeyRejected is the half-configured-mesh guard: an operator
// who wrote peers meant to have a mesh, and a silent no-op would leave the router
// alone with no error to explain it.
func TestGossipJoinWithoutKeyRejected(t *testing.T) {
	c := base()
	c.Gossip.Join = []string{"192.0.2.11"}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error for gossip.join with no gossip.key")
	}
	if !strings.Contains(err.Error(), "gossip.key") {
		t.Errorf("error %q does not name gossip.key", err)
	}
}

// TestGossipKeyValidation covers the key shapes memberlist accepts (16/24/32
// bytes) and the two ways a key can be wrong: not base64, and the wrong length.
func TestGossipKeyValidation(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr string
	}{
		{"32 bytes", gossipKey, ""},
		{"16 bytes", "MDEyMzQ1Njc4OWFiY2RlZg==", ""},
		{"24 bytes", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3", ""},
		{"not base64", "not base64!!!", "not valid base64"},
		{"wrong length", "c2hvcnQ=", "16, 24 or 32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			c.Gossip.Key = tc.key
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestGossipPortDefault checks the port default: an unset bind_port is 7946, an
// explicit one is honoured, and an impossible one is rejected.
func TestGossipPortDefault(t *testing.T) {
	c := base()
	c.Gossip.Key = gossipKey
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := c.Gossip.Port(); got != GossipBindPortDefault {
		t.Errorf("default port = %d, want %d", got, GossipBindPortDefault)
	}

	c.Gossip.BindPort = 9100
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := c.Gossip.Port(); got != 9100 {
		t.Errorf("explicit port = %d, want 9100", got)
	}

	c.Gossip.BindPort = 70000
	if err := c.Validate(); err == nil {
		t.Error("expected an error for an out-of-range gossip.bind_port")
	}
}

// TestGossipEmptyJoinEntryRejected catches a trailing YAML dash, which yields an
// empty string peer that memberlist would try to resolve.
func TestGossipEmptyJoinEntryRejected(t *testing.T) {
	c := base()
	c.Gossip.Key = gossipKey
	c.Gossip.Join = []string{"192.0.2.11", "  "}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for an empty gossip.join entry")
	}
}

// TestControlSocketPathDefault checks the default path and that an explicit one is
// honoured.
func TestControlSocketPathDefault(t *testing.T) {
	c := &Control{}
	if got := c.SocketPathOrDefault(); got != DefaultControlSocket {
		t.Errorf("default socket path = %q, want %q", got, DefaultControlSocket)
	}
	c.SocketPath = "  /run/transitd/other.sock  "
	if got := c.SocketPathOrDefault(); got != "/run/transitd/other.sock" {
		t.Errorf("explicit socket path = %q, want the trimmed value", got)
	}
}

// TestControlSocketValidation pins the structural checks: a relative path and an
// over-long one are both refused at startup rather than discovered as a bind
// failure.
func TestControlSocketValidation(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{"relative path", "run/ctrl.sock", "not an absolute path"},
		{"over the unix limit", "/" + strings.Repeat("a", 120), "unix socket path must fit"},
		{"the root directory", "/", "is a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			c.Gossip.Key = gossipKey // a key, so the half-configured check does not mask the path check
			c.Control.SocketPath = tc.path
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected an error for socket_path %q", tc.path)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// TestControlSocketWithoutKeyRejected is the half-configured-control-plane guard,
// mirroring gossip.join-without-key: the channel authenticates with the mesh key,
// so a socket_path with no key is refused rather than served unauthenticated.
func TestControlSocketWithoutKeyRejected(t *testing.T) {
	c := base()
	c.Control.SocketPath = "/run/transitd/ctrl.sock"
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error for control.socket_path with no gossip.key")
	}
	if !strings.Contains(err.Error(), "gossip.key") {
		t.Errorf("error %q does not name gossip.key", err)
	}
	// With a key the same config is fine.
	c.Gossip.Key = gossipKey
	if err := c.Validate(); err != nil {
		t.Errorf("Validate with a key: %v", err)
	}
}
