// Command transitctl is the operator's client for a transitd agent's control
// channel (issue #2).
//
// It is a CLIENT, not a daemon: it reads the agent's config for the socket path
// and the gossip shared key, opens the unix socket, sends one request and prints
// the reply. It never talks to FRR and never runs in the background.
//
// This MVP is local-only. `transitctl` talks to an agent on the same host; the
// remote path (over the gossip mesh) is the reserved extension documented in
// internal/ctrl/PROTOCOL.md.
//
// Usage:
//
//	transitctl [--config /etc/transitd.yaml] [--socket PATH] [--key B64] status
//	transitctl ... set-primary <name>
//	transitctl ... ping
//
// The subcommands the card asks for are status and set-primary; the flag set is
// deliberately the same for all three so the socket/key resolution has one
// implementation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/ctrl"
)

// version is set by goreleaser ldflags, so `transitctl --version` and
// `transitd --version` report the same build.
var version = "dev"

// exit codes. A refusal (the agent answered and said no) is distinguishable from
// a transport failure (the agent could not be reached) in a shell script.
const (
	exitOK        = 0
	exitUsage     = 2
	exitRefused   = 3
	exitTransport = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: it returns an exit code so a test can drive
// the command end to end against a stub agent.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("transitctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		cfgPath = fs.String("config", "", "path to the agent config file; supplies control.socket_path and gossip.key")
		socket  = fs.String("socket", "", "control socket path (overrides the config's control.socket_path)")
		key     = fs.String("key", "", "gossip shared key, base64 (overrides the config's gossip.key)")
		timeout = fs.Duration("timeout", 5*time.Second, "overall request timeout")
		showVer = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		pf(stderr, "usage: transitctl [flags] <status|set-primary <name>|ping>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVer {
		pf(stdout, "transitctl %s\n", version)
		return exitOK
	}

	resolved, err := resolve(*cfgPath, *socket, *key)
	if err != nil {
		pf(stderr, "transitctl: %v\n", err)
		return exitUsage
	}
	client := &ctrl.Client{SocketPath: resolved.socket, Key: resolved.key, Timeout: *timeout}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return exitUsage
	}

	switch rest[0] {
	case "status":
		return doStatus(client, stdout, stderr)
	case "set-primary":
		if len(rest) != 2 {
			pf(stderr, "transitctl: set-primary requires exactly one transit name\n")
			return exitUsage
		}
		return doSetPrimary(client, rest[1], stdout, stderr)
	case "ping":
		return doPing(client, stdout, stderr)
	default:
		pf(stderr, "transitctl: unknown subcommand %q\n", rest[0])
		return exitUsage
	}
}

// pf writes a formatted line to a command output stream. A CLI cannot do anything
// useful about a failed write to its own stdout/stderr (the terminal is gone), so
// the error is deliberately dropped here in one place rather than at every call
// site, which keeps the error paths below readable.
func pf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// resolvedConfig is the socket path and key a run will use, after merging the
// flags with the agent's config file.
type resolvedConfig struct {
	socket string
	key    string
}

// resolve merges --socket/--key with the config file's control.socket_path and
// gossip.key. Flags win. When no config is given, the socket defaults to the
// agent's default path and the key must come from --key: there is no default
// secret, so a missing key is a usage error naming the flag, not a connection
// that fails auth with a confusing message.
func resolve(cfgPath, socketFlag, keyFlag string) (resolvedConfig, error) {
	rc := resolvedConfig{socket: socketFlag, key: keyFlag}
	var cfgSocket, cfgKey string
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return resolvedConfig{}, err
		}
		cfgSocket = cfg.Control.SocketPathOrDefault()
		cfgKey = cfg.Gossip.Key
	}
	if rc.socket == "" {
		rc.socket = cfgSocket
	}
	if rc.socket == "" {
		rc.socket = config.DefaultControlSocket
	}
	if rc.key == "" {
		rc.key = cfgKey
	}
	if rc.key == "" {
		return resolvedConfig{}, errors.New("no shared key: pass --key, or --config pointing at the agent's config so control.socket_path and gossip.key are read from it")
	}
	return rc, nil
}

func doStatus(c *ctrl.Client, stdout, stderr io.Writer) int {
	resp, code := call(c, ctrl.MethodStatus, nil, stderr)
	if code != exitOK {
		return code
	}
	var res ctrl.StatusResult
	if err := ctrl.DecodeResult(resp, &res); err != nil {
		pf(stderr, "transitctl: %v\n", err)
		return exitRefused
	}
	// Pretty-print the agent's health document under a small envelope line, so an
	// operator reads it directly; the health payload is passed through verbatim
	// rather than reformatted field by field, so a field the agent adds later
	// shows up here without a change to this command.
	var health any
	if err := json.Unmarshal(res.Health, &health); err != nil {
		// Pass it through as raw text rather than failing: the agent said
		// something, and echoing it is more useful than an error.
		pf(stdout, "router=%s version=%d\n%s\n", res.Router, res.Version, res.Health)
		return exitOK
	}
	out, err := json.MarshalIndent(health, "", "  ")
	if err != nil {
		pf(stderr, "transitctl: %v\n", err)
		return exitRefused
	}
	pf(stdout, "router=%s version=%d\n%s\n", res.Router, res.Version, out)
	return exitOK
}

func doSetPrimary(c *ctrl.Client, transit string, stdout, stderr io.Writer) int {
	resp, code := call(c, ctrl.MethodSetPrimary, ctrl.SetPrimaryParams{Transit: transit}, stderr)
	if code != exitOK {
		return code
	}
	var res ctrl.SetPrimaryResult
	if err := ctrl.DecodeResult(resp, &res); err != nil {
		pf(stderr, "transitctl: %v\n", err)
		return exitRefused
	}
	// Say "recorded, not applied" in the operator's own words: this build is
	// observe-only, and a client that printed a bare "ok" would mislead.
	pf(stdout, "recorded desired primary %q on %s (applied=%t)\n%s\n", res.Transit, res.Router, res.Applied, res.Note)
	return exitOK
}

func doPing(c *ctrl.Client, stdout, stderr io.Writer) int {
	resp, code := call(c, ctrl.MethodPing, nil, stderr)
	if code != exitOK {
		return code
	}
	var res ctrl.PingResult
	if err := ctrl.DecodeResult(resp, &res); err != nil {
		pf(stderr, "transitctl: %v\n", err)
		return exitRefused
	}
	pf(stdout, "pong from %s (version %d)\n", res.Router, res.Version)
	return exitOK
}

// call runs one request and maps its failure mode to an exit code. A transport
// error (the agent is not there) and a refusal (the agent said no) are different
// codes on purpose.
func call(c *ctrl.Client, method string, params any, stderr io.Writer) (*ctrl.Response, int) {
	resp, err := c.Call(method, params)
	if err != nil {
		pf(stderr, "transitctl: %v\n", err)
		return nil, exitTransport
	}
	return resp, exitOK
}
