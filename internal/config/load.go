package config

import (
	"fmt"
	"os"
	"time"

	// go.yaml.in/yaml/v2 is the YAML decoder already in transitd's module
	// graph (pulled in by prometheus/common), so wiring a real config loader
	// needs no new dependency — only a promotion from indirect to direct. Its
	// UnmarshalStrict is the strict-key behaviour the config contract promises:
	// an unknown key is a startup error, not a silently ignored typo.
	yaml "go.yaml.in/yaml/v2"
)

// minPlausibleDuration is the floor below which a duration field that was
// explicitly set is almost certainly a bare integer rather than a Go duration
// string. The YAML decoder maps `probe_interval: 30` to 30 *nanoseconds*
// (time.Duration is an int64, and the decoder only consults time.ParseDuration
// for string scalars), so without this guard a config typo turns a 30-second
// probe into a 30-nanosecond one that hammers the network and produces data no
// one can trust — the silently-wrong failure class issue #1 exists to eliminate.
const minPlausibleDuration = time.Second

// Load reads, decodes and validates the agent configuration at path.
//
// It is strict in three ways, because a config typo in a router agent is a
// production outage with a confusing signature: an unknown YAML key is rejected
// rather than ignored, duration fields must be written in Go duration syntax
// (`30s`, not `30`), and the result must pass Validate before it is returned. A
// caller therefore never holds a Config that has not been checked.
func Load(path string) (*Config, error) {
	// The path is the operator's --config flag, not untrusted input: a daemon
	// reading its own configuration file is the intended use of ReadFile. The
	// file's *contents* are untrusted (and are decoded strictly below); the path
	// is a startup argument.
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path, a startup argument
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(b)
}

// Parse decodes and validates an in-memory configuration document. It is Load
// without the file, so tests and a future `transitd -check` path can exercise
// the decoder without touching the filesystem.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.validateDurations(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

// validateDurations rejects a duration field that was explicitly set below the
// plausible floor. Fields left unset (or explicitly zero, meaning "use the
// default") are untouched: only a nonzero value that is implausibly small is a
// configuration bug. It runs before Validate so the message is about the value
// the operator wrote, not about a downstream default.
func (c *Config) validateDurations() error {
	fields := []struct {
		name string
		val  time.Duration
	}{
		{"dwell", c.Dwell},
		{"settle", c.Settle},
	}
	for _, f := range fields {
		if f.val > 0 && f.val < minPlausibleDuration {
			return fmt.Errorf("%s: %v is implausibly small — durations use Go syntax (e.g. 30s, 5m), and a bare integer is read as nanoseconds", f.name, f.val)
		}
	}
	for i := range c.Transits {
		if v := c.Transits[i].ProbeInterval; v > 0 && v < minPlausibleDuration {
			return fmt.Errorf("transit %q: probe_interval: %v is implausibly small — durations use Go syntax (e.g. 30s), and a bare integer is read as nanoseconds", c.Transits[i].Name, v)
		}
	}
	return nil
}
