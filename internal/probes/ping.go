// Package probes implements transitd's per-transit ICMP probe (issue #1, MVP).
//
// It is deliberately built on the system `ping(8)` binary rather than raw
// sockets: ICMP needs CAP_NET_RAW either way, ping already handles the
// iputils/busybox output differences and the address-family split, and it keeps
// the "boring tech" property — no new privileges, no new dependency. The cost
// is that we parse text, so the parser is the most heavily tested part of the
// package.
//
// Every probe is pinned with `-I <probe_source>`: the source address is what
// selects the per-transit policy route, so a probe that is not pinned measures
// whatever the default path happens to be. The pin is verified at startup
// (internal/pinning); a transit that fails verification never gets a loop here.
package probes

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Outcome classifies one ping invocation.
type Outcome int

const (
	// OutcomeReply: at least one echo reply came back.
	OutcomeReply Outcome = iota
	// OutcomeTimeout: the probe was sent (or may have been) and nothing came
	// back. This is a loss, not an error.
	OutcomeTimeout
	// OutcomeFragNeeded: the path signalled that the datagram was too large
	// (ICMP "frag needed"/"message too long"). It is NOT a loss: the probe
	// never left, and it is the positive signal the MTU probe will consume.
	OutcomeFragNeeded
	// OutcomeError: the invocation itself failed in a way that is not a
	// network observation (bad flag, unknown host, binary missing). It must
	// never be counted as packet loss.
	OutcomeError
)

func (o Outcome) String() string {
	switch o {
	case OutcomeReply:
		return "reply"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeFragNeeded:
		return "frag-needed"
	case OutcomeError:
		return "error"
	default:
		return "unknown"
	}
}

// PingResult is the parsed outcome of one ping invocation. ExitCode is kept for
// diagnostics; the classification is done on the text, because both iputils and
// busybox return a non-zero exit for timeout AND for a real error.
type PingResult struct {
	Outcome  Outcome
	RttMs    float64 // last echo reply RTT; 0 unless Outcome == OutcomeReply
	Sent     int     // packets transmitted, from the summary line
	Received int     // packets received, from the summary line
	Err      string  // short diagnostic (first error line), "" on success
}

// replyTime matches the RTT field of a reply line. iputils prints `time=0.044 ms`
// and `time<1 ms` (sub-millisecond); busybox prints `time=0.103 ms`. The angle
// form is clamped to 1ms rather than parsed as 0, so a fast transit does not
// look infinitely good.
var (
	replyTimeRe = regexp.MustCompile(`time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms`)
	replyLineRe = regexp.MustCompile(`(?m)^\s*[0-9]+\s+bytes from\s`)
	summaryRe   = regexp.MustCompile(`([0-9]+)\s+packets? transmitted,\s*([0-9]+)\s+(?:packets?\s+)?received`)
	lossRe      = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)%\s+packet loss`)
	fragRe      = regexp.MustCompile(`(?i)(frag(?:mentation)? needed|message too long|packet too big|too big)`)
	errLineRe   = regexp.MustCompile(`(?m)^\s*ping:\s*(.+)$`)
)

// ParsePing classifies one ping invocation's combined output.
//
// Both implementations are handled with the same code path: the reply line is
// the positive signal, the summary line carries the counts, and the
// fragmentation/ICMP-error text is checked before the loss summary so that a
// "message too long" is reported as OutcomeFragNeeded rather than as 100%
// packet loss (the two produce identical summary lines).
func ParsePing(stdout, stderr string) PingResult {
	out := stdout
	if stderr != "" {
		out = stdout + "\n" + stderr
	}
	res := PingResult{Outcome: OutcomeTimeout}

	if m := summaryRe.FindStringSubmatch(out); m != nil {
		res.Sent, _ = strconv.Atoi(m[1])
		res.Received, _ = strconv.Atoi(m[2])
	} else if m := lossRe.FindStringSubmatch(out); m == nil {
		// No summary at all: the invocation never got far enough to print one.
		// That is an error (bad flag, missing binary, unknown host), not a
		// network observation, so it must not be charged as packet loss.
		res.Outcome = OutcomeError
		res.Err = firstErrorLine(out)
		return res
	}

	if fragRe.MatchString(out) {
		res.Outcome = OutcomeFragNeeded
		return res
	}

	if replyLineRe.MatchString(out) && res.Received > 0 {
		if m := replyTimeRe.FindStringSubmatch(out); m != nil {
			rtt, err := strconv.ParseFloat(m[1], 64)
			if err == nil {
				if strings.Contains(m[0], "<") && rtt < 1 {
					rtt = 1 // "time<1 ms" is a bound, not a measurement
				}
				res.RttMs = rtt
			}
		}
		res.Outcome = OutcomeReply
		return res
	}

	// A summary with 100% loss and no reply line is a clean timeout. A summary
	// with a partial loss still means no reply for this single-probe cycle.
	res.Outcome = OutcomeTimeout
	return res
}

// LossPct returns the packet loss percentage of this invocation, or NaN when no
// summary was parsed (an invocation error carries no loss information).
func (r PingResult) LossPct() float64 {
	if r.Sent == 0 {
		return math.NaN()
	}
	return float64(r.Sent-r.Received) / float64(r.Sent) * 100
}

func firstErrorLine(out string) string {
	if m := errLineRe.FindStringSubmatch(out); m != nil {
		return strings.TrimSpace(m[1])
	}
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return "no output"
}

// Runner executes the ping binary and returns its separate stdout/stderr and
// exit code. It is the seam that lets the loop run without ICMP privileges in
// the unit tier.
type Runner interface {
	// Run executes name with args and returns stdout, stderr and the exit
	// code. A non-zero exit is reported through exitCode, not as a Go error:
	// ping returns 1 for a plain timeout, which is a normal measurement.
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, exitCode int, err error)
}

// ExecRunner is the production Runner.
type ExecRunner struct {
	// Binary overrides the program the caller names in Run (the loop passes
	// "ping"). It exists so a host with ping at a nonstandard path — or a test
	// exercising a specific busybox binary — can point the runner at it. Empty
	// means "use the name the caller passed".
	Binary string
}

// Run execs the ping binary directly (never through a shell — the source
// address and target come from config and must not be word-split).
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	bin := r.Binary
	if bin == "" {
		bin = name
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // fixed binary + argv slice, no shell
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
			err = nil // a non-zero exit is a measurement, not a failure
		}
	}
	return stdout.String(), stderr.String(), code, err
}

// Family is an address family, which decides the ping flag.
type Family string

const (
	// FamilyV4 selects ICMPv4 (`-4`).
	FamilyV4 Family = "ipv4"
	// FamilyV6 selects ICMPv6 (`-6`).
	FamilyV6 Family = "ipv6"
)

// FamilyOf classifies an address literal. It returns an error for anything that
// is not a v4 or v6 address, so a config typo fails at construction rather than
// as a mysterious ping error on every cycle.
func FamilyOf(addr string) (Family, error) {
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return "", fmt.Errorf("%q is not an IP address", addr)
	case ip.To4() != nil:
		return FamilyV4, nil
	default:
		return FamilyV6, nil
	}
}

// Variant identifies the ping implementation, which decides argument style.
type Variant string

const (
	// VariantIputils is iputils-ping (the Debian/Ubuntu/Alpine default).
	VariantIputils Variant = "iputils"
	// VariantBusybox is BusyBox's multi-call ping: it has no -V flag and no -n.
	VariantBusybox Variant = "busybox"
)

// DetectVariant identifies the ping implementation behind a Runner by running
// `ping -V`. iputils prints `ping from iputils <date>`; busybox rejects the flag
// with "invalid option -- 'V'" and exits non-zero. Anything else — a missing
// binary, an unrecognised banner — is treated as busybox-compatible, because
// the busybox argument set is the strict subset: assuming iputils and being
// wrong would make every probe fail, while assuming busybox and being wrong
// only costs the -n flag.
func DetectVariant(ctx context.Context, r Runner) Variant {
	out, _, _, err := r.Run(ctx, "ping", "-V")
	if err != nil {
		return VariantBusybox
	}
	if strings.Contains(strings.ToLower(out), "iputils") {
		return VariantIputils
	}
	return VariantBusybox
}

// argsFor builds the argv tail for one probe. The shape is:
//
//	iputils: ping -4|-6 -n -c 1 -W <sec> -I <src> <target>
//	busybox: ping -4|-6    -c 1 -W <sec> -I <src> <target>
//
// busybox omits -n (it has no such flag). Both accept -4/-6 and -I.
func argsFor(v Variant, fam Family, src, target string, timeoutSec int) []string {
	args := []string{string(famFlag(fam))}
	if v == VariantIputils {
		args = append(args, "-n")
	}
	args = append(args,
		"-c", "1",
		"-W", strconv.Itoa(timeoutSec),
		"-I", src,
		target,
	)
	return args
}

// famFlag maps a family to its ping flag ("-4" / "-6").
func famFlag(fam Family) string {
	if fam == FamilyV6 {
		return "-6"
	}
	return "-4"
}
