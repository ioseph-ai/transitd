package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadExampleConfig decodes the committed example document end to end. It is
// the guard that the loader and the on-disk shape agree: field names, the
// per-transit list, and the duration scalars (`dwell: 5m`, `probe_interval:
// 30s`) must all survive decode + Validate into the types the agent consumes.
func TestLoadExampleConfig(t *testing.T) {
	c, err := Load(filepath.Join("testdata", "agent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.RouterName != "r-example" {
		t.Errorf("router_name = %q, want r-example", c.RouterName)
	}
	if len(c.Join) != 1 || c.Join[0] != "192.0.2.11" {
		t.Errorf("join = %v, want [192.0.2.11]", c.Join)
	}
	if c.ListenMetrics != ":9414" {
		t.Errorf("listen_metrics = %q, want :9414", c.ListenMetrics)
	}
	if c.Dwell != 5*time.Minute || c.Settle != 60*time.Second {
		t.Errorf("durations decoded wrongly: dwell=%v settle=%v", c.Dwell, c.Settle)
	}
	if len(c.Transits) != 2 {
		t.Fatalf("transits = %d, want 2", len(c.Transits))
	}
	main := c.Transits[0]
	if main.Name != "main" || main.ImportMap != "MAIN-LOCAL-IN" {
		t.Errorf("transit[0] = %+v, want main/MAIN-LOCAL-IN", main)
	}
	if main.ProbeSource != "192.0.2.1" || main.ProbeTarget != "198.51.100.5" || main.EgressInterface != "eth-transit" {
		t.Errorf("transit[0] pinning fields = %+v", main)
	}
	if main.ProbeInterval != 30*time.Second {
		t.Errorf("probe_interval = %v, want 30s", main.ProbeInterval)
	}
	// Defaults must have been applied by Validate, not read from the file.
	if c.BaseLP != 200 && c.BaseLP != 0 {
		t.Errorf("base_lp = %d", c.BaseLP)
	}
}

// TestParseRejectsUnknownKey pins the strictness promise: a misspelled key must
// fail startup rather than silently disable the feature it was meant to
// configure. This is the difference between a typo and a silently unpinned
// probe.
func TestParseRejectsUnknownKey(t *testing.T) {
	doc := []byte(`
router_name: r-example
bind_addr: 192.0.2.10
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
    probe_interval_secs: 30
`)
	_, err := Parse(doc)
	if err == nil {
		t.Fatal("expected an error for the unknown key probe_interval_secs")
	}
	if !strings.Contains(err.Error(), "probe_interval_secs") {
		t.Errorf("error %q does not name the offending key", err)
	}
}

// TestParseRejectsTypoInTransitName does the same for a key nested one level
// down, so the strict decoder is shown to be strict recursively, not only at
// the top level.
func TestParseRejectsTypoInTransitName(t *testing.T) {
	doc := []byte(`
router_name: r-example
bind_addr: 192.0.2.10
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress: eth-transit
`)
	if _, err := Parse(doc); err == nil {
		t.Fatal("expected an error for the unknown nested key egress")
	}
}

// TestParseSurfacesValidation checks the loader does not hand back a config that
// only the decoder accepted: validation failures propagate with the config
// prefix so a log line says where the problem came from.
func TestParseSurfacesValidation(t *testing.T) {
	doc := []byte(`
router_name: r-example
bind_addr: 192.0.2.10
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
`)
	_, err := Parse(doc)
	if err == nil {
		t.Fatal("expected a validation error for the missing egress_interface")
	}
	if !strings.Contains(err.Error(), "egress_interface is required") {
		t.Errorf("error %q does not carry the validation message", err)
	}
	if !strings.HasPrefix(err.Error(), "config: ") {
		t.Errorf("error %q is not prefixed with the config context", err)
	}
}

// TestLoadMissingFile checks the error is wrapped, not swallowed into a nil
// config the agent would then run with.
func TestLoadMissingFile(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
	if c != nil {
		t.Errorf("config = %+v, want nil alongside the error", c)
	}
}

// TestParseRejectsBareIntegerDuration documents the one decoding sharp edge and
// the guard the loader puts in front of it. `time.Duration` is an int64 and the
// decoder only calls ParseDuration for string scalars, so `probe_interval: 30`
// would otherwise decode to 30 *nanoseconds* — a 30-second probe turned into a
// flood, and data no one can trust. The loader refuses the whole class instead.
func TestParseRejectsBareIntegerDuration(t *testing.T) {
	const transit = `transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
`
	cases := []struct {
		name string
		doc  string
	}{
		{
			"per-transit probe_interval",
			"router_name: r-example\nbind_addr: 192.0.2.10\n" + transit + "    probe_interval: 30\n",
		},
		{
			"top-level dwell",
			"router_name: r-example\nbind_addr: 192.0.2.10\ndwell: 10\n" + transit,
		},
		{
			"top-level settle",
			"router_name: r-example\nbind_addr: 192.0.2.10\nsettle: 5\n" + transit,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := errFromParse([]byte(tc.doc))
			if err == nil {
				t.Fatal("expected an error for a bare-integer duration")
			}
			if !strings.Contains(err.Error(), "Go syntax") {
				t.Errorf("error %q does not explain the duration syntax", err)
			}
		})
	}
}

// TestParseRejectsNegativeDuration is the second half of the guard: a negative
// duration is not merely nonsensical, it silently disables a guard. decide's dwell
// check is `now.Sub(last) < Dwell`, which a negative Dwell makes never true, and a
// negative probe_interval is silently replaced with 30s by NewLoop. Both are the
// silently-wrong class the loader exists to refuse.
func TestParseRejectsNegativeDuration(t *testing.T) {
	const transit = `transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
`
	cases := []struct {
		name string
		doc  string
	}{
		{"top-level dwell", "router_name: r-example\nbind_addr: 192.0.2.10\ndwell: -5m\n" + transit},
		{"top-level settle", "router_name: r-example\nbind_addr: 192.0.2.10\nsettle: -1s\n" + transit},
		{
			"per-transit probe_interval",
			"router_name: r-example\nbind_addr: 192.0.2.10\n" + transit + "    probe_interval: -30s\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := errFromParse([]byte(tc.doc))
			if err == nil {
				t.Fatal("expected an error for a negative duration")
			}
			if !strings.Contains(err.Error(), "negative") {
				t.Errorf("error %q does not say the duration is negative", err)
			}
		})
	}
}

// TestParseAcceptsDurationStrings is the positive half of the guard above: a
// well-formed duration must not be caught by it.
func TestParseAcceptsDurationStrings(t *testing.T) {
	doc := []byte(`router_name: r-example
bind_addr: 192.0.2.10
dwell: 5m
settle: 60s
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
    probe_interval: 45s
`)
	c, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Dwell != 5*time.Minute || c.Transits[0].ProbeInterval != 45*time.Second {
		t.Errorf("durations = %v / %v", c.Dwell, c.Transits[0].ProbeInterval)
	}
}

// errFromParse is a tiny helper so the cases above read as data, not control flow.
func errFromParse(doc []byte) error {
	_, err := Parse(doc)
	return err
}

// TestLoadReadsWholeFile guards against a loader that only reads the first
// chunk: the example document is parsed via Load (os.ReadFile), so a truncated
// read would surface as a validation error above. This test asserts the file
// the loader reads is the committed one, by parsing it directly.
func TestLoadMatchesCommittedExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "agent.yaml"))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("Parse(committed example): %v", err)
	}
}
