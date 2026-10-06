package config

import (
	"strings"
	"testing"
	"time"
)

// TestBGPWatchDefaults pins the bgpwatch defaults Validate fills in: an unset block
// takes the default cadence and prefix cap, and a block that only sets a neighbor
// still gets them.
func TestBGPWatchDefaults(t *testing.T) {
	c := base()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.BGPWatch.MaxPrefixes != DefaultMaxPrefixes {
		t.Errorf("max_prefixes = %d, want %d", c.BGPWatch.MaxPrefixes, DefaultMaxPrefixes)
	}
	if c.BGPWatch.Interval != DefaultBGPWatchInterval {
		t.Errorf("interval = %v, want %v", c.BGPWatch.Interval, DefaultBGPWatchInterval)
	}
}

// TestBGPWatchIntervalFloorIsApplied is the 1 Hz cap in config: a sub-second
// interval is clamped to the floor, not honoured. The floor is a property of the
// poller (a full-table JSON dump is expensive on a 1 vCPU router), and the config
// layer must not be a way around it.
func TestBGPWatchIntervalFloorIsApplied(t *testing.T) {
	c := base()
	c.BGPWatch.Interval = 100 * time.Millisecond
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.BGPWatch.Interval != MinBGPWatchInterval {
		t.Errorf("interval = %v, want the %v floor", c.BGPWatch.Interval, MinBGPWatchInterval)
	}
	// An interval above the floor is preserved.
	c2 := base()
	c2.BGPWatch.Interval = 30 * time.Second
	if err := c2.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c2.BGPWatch.Interval != 30*time.Second {
		t.Errorf("interval = %v, want 30s preserved", c2.BGPWatch.Interval)
	}
}

// TestBGPWatchRejectsNegativePrefixCap checks a negative cap is refused rather than
// read as "unlimited": the bound is what stops a full-table parse, so silently
// removing it is the wrong direction to guess.
func TestBGPWatchRejectsNegativePrefixCap(t *testing.T) {
	c := base()
	c.BGPWatch.MaxPrefixes = -1
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for a negative max_prefixes")
	}
}

// TestBGPWatchNeighborIsValidated checks bgp_neighbor is validated when set: it is
// the key bgpwatch matches in the summary, so a hostname or typo must fail startup
// rather than silently never match.
func TestBGPWatchNeighborIsValidated(t *testing.T) {
	c := base()
	c.Transits[0].BGPNeighbor = "198.51.100.1"
	if err := c.Validate(); err != nil {
		t.Fatalf("a valid neighbor was rejected: %v", err)
	}

	bad := base()
	bad.Transits[0].BGPNeighbor = "not-an-ip"
	err := bad.Validate()
	if err == nil {
		t.Fatal("expected an error for a non-IP bgp_neighbor")
	}
	if !strings.Contains(err.Error(), "bgp_neighbor") {
		t.Errorf("error %q does not name the offending field", err)
	}

	// Unset stays valid: bgp_neighbor is optional.
	empty := base()
	if err := empty.Validate(); err != nil {
		t.Fatalf("an unset bgp_neighbor was rejected: %v", err)
	}
}

// TestBGPWatchParsesFromYAML pins the YAML surface: the block keys decode onto the
// struct and the neighbor key decodes on the transit.
func TestBGPWatchParsesFromYAML(t *testing.T) {
	doc := []byte(`
router_name: r-example
bind_addr: 192.0.2.10
bgpwatch:
  enabled: true
  max_prefixes: 250
  interval: 2s
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
    bgp_neighbor: 198.51.100.5
`)
	c, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.BGPWatch.Enabled || c.BGPWatch.MaxPrefixes != 250 || c.BGPWatch.Interval != 2*time.Second {
		t.Errorf("bgpwatch = %+v, want enabled/250/2s", c.BGPWatch)
	}
	if c.Transits[0].BGPNeighbor != "198.51.100.5" {
		t.Errorf("bgp_neighbor = %q", c.Transits[0].BGPNeighbor)
	}
}

// TestBGPWatchRejectsUnknownKey keeps the strict decoder honest for the new block:
// a misspelled bgpwatch key must fail startup rather than silently disable the
// bound it was meant to set.
func TestBGPWatchRejectsUnknownKey(t *testing.T) {
	doc := []byte(`
router_name: r-example
bind_addr: 192.0.2.10
bgpwatch:
  enabled: true
  max_prefix: 250
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
`)
	_, err := Parse(doc)
	if err == nil {
		t.Fatal("expected an error for the unknown bgpwatch key max_prefix")
	}
	if !strings.Contains(err.Error(), "max_prefix") {
		t.Errorf("error %q does not name the offending key", err)
	}
}
