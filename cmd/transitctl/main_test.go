package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ioseph-ai/transitd/internal/ctrl"
)

// stubAgent starts a real ctrl.Server on a short temp socket and returns the
// socket path and the key it expects. Driving the CLI against the real server
// (rather than a hand-rolled fake) is the point: the wire format has one
// implementation and this test proves the CLI speaks it.
func stubAgent(t *testing.T, health string, known map[string]bool) (sock, key string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tc-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, "ctrl.sock")
	key = "MDEyMzQ1Njc4OWFiY2RlZg==" // base64 of a 16-byte placeholder key

	kBytes := []byte("0123456789abcdef")
	srv, err := ctrl.New(ctrl.Options{
		SocketPath: sock,
		Key:        kBytes,
		Router:     "r-example",
		Status:     func() (json.RawMessage, error) { return json.RawMessage(health), nil },
		KnownTransit: func(name string) bool {
			if known == nil {
				return true
			}
			return known[name]
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("ctrl.New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	go func() { _ = srv.Serve() }()
	return sock, key
}

// runCLI invokes run with the given args and returns its exit code with captured
// stdout and stderr.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// TestStatusEndToEnd is the card's round-trip requirement on the client side: a
// real server answers, and the CLI prints the agent's health document.
func TestStatusEndToEnd(t *testing.T) {
	const health = `{"status":"ok","pin_verified":{"main":true},"features":{"probes":"ok"}}`
	sock, key := stubAgent(t, health, nil)

	code, out, errOut := runCLI(t, "--socket", sock, "--key", key, "status")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "router=r-example") {
		t.Errorf("stdout does not name the router:\n%s", out)
	}
	if !strings.Contains(out, `"pin_verified"`) || !strings.Contains(out, `"probes": "ok"`) {
		t.Errorf("stdout does not carry the health document:\n%s", out)
	}
}

// TestSetPrimaryEndToEnd: the CLI records a preference and says explicitly that
// it was not applied.
func TestSetPrimaryEndToEnd(t *testing.T) {
	sock, key := stubAgent(t, `{"status":"ok"}`, map[string]bool{"main": true, "backup": true})

	code, out, errOut := runCLI(t, "--socket", sock, "--key", key, "set-primary", "backup")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, `"backup"`) {
		t.Errorf("stdout does not name the transit:\n%s", out)
	}
	if !strings.Contains(out, "applied=false") {
		t.Errorf("stdout does not say the preference was not applied:\n%s", out)
	}
}

// TestUnknownTransitRefused: an unknown transit is a protocol failure, which the
// CLI reports with the "refused" exit code rather than the transport one.
func TestUnknownTransitRefused(t *testing.T) {
	sock, key := stubAgent(t, `{"status":"ok"}`, map[string]bool{"main": true})

	code, _, errOut := runCLI(t, "--socket", sock, "--key", key, "set-primary", "nope")
	if code != exitRefused {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitRefused, errOut)
	}
	if !strings.Contains(errOut, "bad_request") {
		t.Errorf("stderr does not carry the refusal:\n%s", errOut)
	}
}

// TestWrongKeyIsRefusedNotTransport: a wrong key reaches the agent and is refused;
// the CLI must report "refused", not "could not reach".
func TestWrongKeyIsRefusedNotTransport(t *testing.T) {
	sock, _ := stubAgent(t, `{"status":"ok"}`, nil)

	code, _, errOut := runCLI(t, "--socket", sock, "--key", "d3Jvbmcta2V5LXZhbHVl", "status")
	if code != exitRefused {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitRefused, errOut)
	}
	if !strings.Contains(errOut, "unauthorized") {
		t.Errorf("stderr does not carry the auth failure:\n%s", errOut)
	}
}

// TestMissingSocketIsTransportError: an agent that is not there is exit 4, distinct
// from a refusal.
func TestMissingSocketIsTransportError(t *testing.T) {
	dir, err := os.MkdirTemp("", "tc-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	code, _, errOut := runCLI(t, "--socket", filepath.Join(dir, "absent.sock"), "--key", "MDEyMzQ1Njc4OWFiY2RlZg==", "status")
	if code != exitTransport {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitTransport, errOut)
	}
}

// TestConfigSuppliesSocketAndKey is the card's --config path: with a real config
// file the CLI reads control.socket_path and gossip.key and needs no flags for
// them.
func TestConfigSuppliesSocketAndKey(t *testing.T) {
	sock, key := stubAgent(t, `{"status":"ok","pin_verified":{"main":true}}`, nil)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "transitd.yaml")
	cfg := `router_name: r-example
bind_addr: 192.0.2.10
gossip:
  key: "` + key + `"
control:
  socket_path: "` + sock + `"
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 192.0.2.1
    probe_target: 198.51.100.5
    egress_interface: eth-transit
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	code, out, errOut := runCLI(t, "--config", cfgPath, "status")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, `"main": true`) {
		t.Errorf("stdout does not carry the health document:\n%s", out)
	}
}

// TestMissingKeyIsUsage: with no key anywhere the CLI fails on usage, naming the
// flag, rather than dialling and getting a confusing auth failure.
func TestMissingKeyIsUsage(t *testing.T) {
	code, _, errOut := runCLI(t, "--socket", "/run/transitd/ctrl.sock", "status")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUsage, errOut)
	}
	if !strings.Contains(errOut, "no shared key") {
		t.Errorf("stderr does not explain the missing key:\n%s", errOut)
	}
}

// TestBadArgs: a missing or extra subcommand argument is usage, and no request is
// sent.
func TestBadArgs(t *testing.T) {
	sock, key := stubAgent(t, `{"status":"ok"}`, nil)
	cases := [][]string{
		{"--socket", sock, "--key", key},                          // no subcommand
		{"--socket", sock, "--key", key, "set-primary"},           // missing name
		{"--socket", sock, "--key", key, "set-primary", "a", "b"}, // extra arg
		{"--socket", sock, "--key", key, "frobnicate"},            // unknown subcommand
	}
	for _, args := range cases {
		code, _, _ := runCLI(t, args...)
		if code != exitUsage {
			t.Errorf("args %v: exit = %d, want %d", args, code, exitUsage)
		}
	}
}

// TestPingEndToEnd: the liveness subcommand round-trips.
func TestPingEndToEnd(t *testing.T) {
	sock, key := stubAgent(t, `{"status":"ok"}`, nil)
	code, out, errOut := runCLI(t, "--socket", sock, "--key", key, "ping")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "pong from r-example") {
		t.Errorf("stdout = %q", out)
	}
}

// TestVersion: --version prints and exits without touching a socket.
func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "--version")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "transitctl") {
		t.Errorf("stdout = %q", out)
	}
}
