// Package pinning implements the startup pin-verification preflight for
// per-transit probes (issue #1).
//
// Binding a probe's source address fixes the source IP, not the egress path:
// with only a source pin, a probe can silently leave through the default or
// ECMP path with a foreign source — uRPF-dropped, or worse, still measured as
// if it had traversed the intended transit. Both outcomes are indistinguishable
// from a correct measurement once the numbers land in the decision engine.
//
// The preflight closes that gap by asking the kernel where a packet from the
// transit's probe source would actually go, using the same routing tables the
// probes will hit:
//
//	ip route get <probe_target> from <probe_source>
//
// and comparing the resolved egress interface against the interface the transit
// is configured to use. A mismatch does not raise an alarm on its own: the
// caller suppresses the transit's samples entirely (see the agent loop), so a
// mis-pinned transit contributes nothing rather than contributing wrong data.
package pinning

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
)

// Result is one transit's verification outcome. It is the value the agent both
// logs and exports as the transitd_pin_verified gauge, and the value the
// integration tier asserts on.
type Result struct {
	// Transit is the configured transit name the result belongs to.
	Transit string
	// Verified is true only when the resolved egress interface matched the
	// transit's expected EgressInterface.
	Verified bool
	// Reason is a short human-readable explanation, always populated — on
	// success as well as failure, so logs and the healthz payload never have a
	// bare boolean with no context.
	Reason string
	// EgressIf is the interface the route lookup resolved, or "" when the
	// lookup failed before an interface could be read (e.g. the source address
	// is not present on this host, so the kernel refuses the query).
	EgressIf string
}

// Runner executes the route-lookup tool and returns its raw combined output.
// It is the seam that lets the unit tests run without root, without netlink and
// without touching the host's routing table: production passes the exec-backed
// implementation, tests pass a fake.
//
// name is the program ("ip"); args are the full argv tail. Implementations must
// never invoke a shell — the arguments include a config-derived interface name
// and addresses, and a shell would turn a config typo into command injection.
type Runner interface {
	Lookup(ctx context.Context, name string, args ...string) (output string, err error)
}

// ExecRunner is the production Runner: it execs the system `ip` binary
// directly. Zero new dependencies — `ip` is already a hard requirement of any
// router running transitd.
type ExecRunner struct {
	// Binary is the route-lookup program; defaults to "ip" when empty.
	Binary string
}

// Lookup runs the route-lookup program with args and returns its combined
// stdout+stderr. When Binary is empty the caller-supplied name is used (the
// verifier passes "ip").
func (r ExecRunner) Lookup(ctx context.Context, name string, args ...string) (string, error) {
	bin := r.Binary
	if bin == "" {
		bin = name
	}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput() //nolint:gosec // fixed binary, argv slice, no shell
	return string(out), err
}

// Verifier verifies one transit's pin. It is an interface so the agent can be
// tested against a fake verifier and so a future netlink-based implementation
// can replace the exec one without touching callers.
type Verifier interface {
	Verify(ctx context.Context, t config.Transit) Result
}

// RouteVerifier verifies a transit by asking the kernel which interface a
// packet would leave through. It is the real implementation behind Verifier.
type RouteVerifier struct {
	Runner Runner
}

// New returns a RouteVerifier using the system `ip` binary.
func New() *RouteVerifier { return &RouteVerifier{Runner: ExecRunner{}} }

// Verify runs the preflight for one transit and reports whether its probes
// egress the expected interface. It exports the outcome as the
// transitd_pin_verified{transit} gauge, so pinning is where the pin metric is
// produced.
//
// It never returns an error: a verification failure is a first-class, expected
// outcome (the transit is suppressed from measurement), not a condition a caller
// should branch on. Every path returns a fully populated Result so the caller can
// log a reason and reason about the observed egress without guessing.
func (v *RouteVerifier) Verify(ctx context.Context, t config.Transit) Result {
	res := v.Check(ctx, t)
	metrics.SetPinVerified(res.Transit, res.Verified)
	return res
}

// Check is Verify without the metric side effect. Callers that verify in a
// context where the gauge should not move (tests, dry runs) use Check.
func (v *RouteVerifier) Check(ctx context.Context, t config.Transit) Result {
	res := Result{Transit: t.Name}

	if t.ProbeSource == "" || t.ProbeTarget == "" || t.EgressInterface == "" {
		res.Reason = "incomplete pinning config (probe_source/probe_target/egress_interface)"
		return res
	}

	// `ip route get` is a single-shot query; -4/-6 is unnecessary because the
	// address family follows src/dst, but the output shape is the same either
	// way and we do not rely on it beyond the `dev` token.
	out, err := v.Runner.Lookup(ctx, "ip", "route", "get", t.ProbeTarget, "from", t.ProbeSource)
	if err != nil {
		res.Reason = fmt.Sprintf("route lookup failed: %s", firstLine(out, err))
		return res
	}

	iface, perr := ParseEgressInterface(out)
	if perr != nil {
		res.Reason = fmt.Sprintf("route lookup output not understood: %v", perr)
		return res
	}
	res.EgressIf = iface

	if iface != t.EgressInterface {
		res.Reason = fmt.Sprintf("probes egress %s, expected %s", iface, t.EgressInterface)
		return res
	}
	res.Verified = true
	res.Reason = fmt.Sprintf("egress %s matches expected %s", iface, t.EgressInterface)
	return res
}

// devToken matches the `dev <iface>` token in `ip route get` output. The token
// is always present on a resolved route and is the only field that names the
// egress interface unambiguously (the first token is the destination, and a
// `via ... src ...` route names the next hop and source, not the egress).
var devToken = regexp.MustCompile(`(?:^|\s)dev\s+(\S+)`)

// ParseEgressInterface extracts the egress interface from `ip route get`
// output. It is exported so the integration tier and tests can assert on the
// same parse the verifier uses.
//
// Only the first line is parsed: a successful `ip route get` prints the route
// on one line, and a cached route adds an indented `cache` line that carries no
// `dev` token of its own.
func ParseEgressInterface(out string) (string, error) {
	line := firstLine(out, nil)
	if line == "" {
		return "", fmt.Errorf("empty route lookup output")
	}
	m := devToken.FindStringSubmatch(line)
	if m == nil {
		return "", fmt.Errorf("no `dev` token in %q", line)
	}
	return m[1], nil
}

// firstLine returns the first non-empty line of out, falling back to the error
// text so a failed lookup still yields a diagnosable reason. err may be nil.
func firstLine(out string, err error) string {
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	if err != nil {
		return err.Error()
	}
	return ""
}
