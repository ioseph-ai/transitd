package probes

import (
	"context"
	"strings"
	"testing"
)

// TestParsePingGolden pins the classifier against the exact output shapes the
// two supported ping implementations produce. Every fixture uses documentation
// addresses (RFC 5737 / RFC 3849) or loopback only.
//
// The shapes covered are the ones that actually change the verdict:
//   - iputils and busybox reply lines (different summary wording, same reply line)
//   - iputils and busybox timeouts (exit 1, 100% loss, no reply)
//   - iputils fragmentation error ("Message too long") — which has the SAME
//     summary as a timeout and must not be classified as loss
//   - a partial-loss line
//   - a bad-flag invocation error with no summary at all
func TestParsePingGolden(t *testing.T) {
	const (
		iputilsReply = `PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.
64 bytes from 198.51.100.5: icmp_seq=1 ttl=63 time=12.4 ms

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 12.410/12.410/12.410/0.000 ms`

		iputilsSubMs = `PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.
64 bytes from 198.51.100.5: icmp_seq=1 ttl=63 time<1 ms

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms`

		iputilsTimeout = `PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms`

		iputilsFrag = `PING 198.51.100.5 (198.51.100.5) 2000(2028) bytes of data.
ping: sendmsg: Message too long

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms`

		busyboxReply = `PING 198.51.100.5 (198.51.100.5): 56 data bytes
64 bytes from 198.51.100.5: seq=0 ttl=63 time=8.9 ms

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 8.900/8.900/8.900 ms`

		busyboxTimeout = `PING 198.51.100.5 (198.51.100.5): 56 data bytes

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss`

		badFlag = `ping: invalid option -- 'n'
BusyBox v1.38.0 (2026-05-13 02:21:49 UTC) multi-call binary.`

		unknownHost = `ping: 198.51.100.5: Name or service not known`
	)

	cases := []struct {
		name       string
		stdout     string
		stderr     string
		wantOut    Outcome
		wantRtt    float64
		wantSent   int
		wantRecv   int
		wantErrSub string
	}{
		{"iputils reply", iputilsReply, "", OutcomeReply, 12.4, 1, 1, ""},
		{"iputils sub-millisecond reply clamps to 1ms", iputilsSubMs, "", OutcomeReply, 1, 1, 1, ""},
		{"iputils timeout", iputilsTimeout, "", OutcomeTimeout, 0, 1, 0, ""},
		{"iputils frag-needed is not loss", iputilsFrag, "", OutcomeFragNeeded, 0, 1, 0, ""},
		{"busybox reply", busyboxReply, "", OutcomeReply, 8.9, 1, 1, ""},
		{"busybox timeout", busyboxTimeout, "", OutcomeTimeout, 0, 1, 0, ""},
		{"bad flag is an error", badFlag, "", OutcomeError, 0, 0, 0, "invalid option"},
		{"unknown host is an error", unknownHost, "", OutcomeError, 0, 0, 0, "Name or service not known"},
		{"stderr-only error", "", "ping: conn: Network is unreachable", OutcomeError, 0, 0, 0, "Network is unreachable"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParsePing(tc.stdout, tc.stderr)
			if got.Outcome != tc.wantOut {
				t.Errorf("Outcome = %v, want %v (err=%q)", got.Outcome, tc.wantOut, got.Err)
			}
			if got.RttMs != tc.wantRtt {
				t.Errorf("RttMs = %v, want %v", got.RttMs, tc.wantRtt)
			}
			if got.Sent != tc.wantSent || got.Received != tc.wantRecv {
				t.Errorf("counts = %d/%d, want %d/%d", got.Sent, got.Received, tc.wantSent, tc.wantRecv)
			}
			if tc.wantErrSub != "" && !contains(got.Err, tc.wantErrSub) {
				t.Errorf("Err = %q, want it to contain %q", got.Err, tc.wantErrSub)
			}
		})
	}
}

// TestParsePingFragNeededIsNotLoss is the safety-critical assertion: an ICMP
// "too long" carries the same summary line as a timeout, so a naive parser
// charges it as 100% loss and the transit looks dead. It must classify as
// OutcomeFragNeeded and its loss must never be counted.
func TestParsePingFragNeededIsNotLoss(t *testing.T) {
	out := `PING 198.51.100.5 (198.51.100.5) 2000(2028) bytes of data.
ping: local error: message too long, mtu=1500

--- 198.51.100.5 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms`

	got := ParsePing(out, "")
	if got.Outcome != OutcomeFragNeeded {
		t.Fatalf("Outcome = %v, want frag-needed", got.Outcome)
	}
}

// TestLossPct checks the rolling-window loss maths and the NaN contract for an
// invocation with no summary.
func TestLossPct(t *testing.T) {
	cases := []struct {
		name string
		res  PingResult
		want float64
		nan  bool
	}{
		{"full loss", PingResult{Sent: 1, Received: 0}, 100, false},
		{"no loss", PingResult{Sent: 4, Received: 4}, 0, false},
		{"partial", PingResult{Sent: 4, Received: 3}, 25, false},
		{"no summary", PingResult{Sent: 0, Received: 0}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.res.LossPct()
			if tc.nan {
				if !isNaN(got) {
					t.Fatalf("LossPct = %v, want NaN", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("LossPct = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFamilyOf pins address-family classification, including the v4-mapped-v6
// case net.ParseIP folds into v4.
func TestFamilyOf(t *testing.T) {
	cases := []struct {
		addr    string
		want    Family
		wantErr bool
	}{
		{"198.51.100.5", FamilyV4, false},
		{"2001:db8::5", FamilyV6, false},
		{"::ffff:198.51.100.5", FamilyV4, false},
		{"not-an-ip", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			got, err := FamilyOf(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("FamilyOf(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestArgsForPinsSource asserts the pin is present in both variants and that the
// busybox variant omits -n (which busybox does not have).
func TestArgsForPinsSource(t *testing.T) {
	iputils := argsFor(VariantIputils, FamilyV4, "192.0.2.1", "203.0.113.5", 2)
	if !hasFlagValue(iputils, "-I", "192.0.2.1") {
		t.Errorf("iputils argv does not pin source with -I: %v", iputils)
	}
	if !hasFlag(iputils, "-n") {
		t.Errorf("iputils argv should carry -n: %v", iputils)
	}

	busybox := argsFor(VariantBusybox, FamilyV4, "192.0.2.1", "203.0.113.5", 2)
	if hasFlag(busybox, "-n") {
		t.Errorf("busybox argv must not carry -n: %v", busybox)
	}
	if !hasFlagValue(busybox, "-I", "192.0.2.1") {
		t.Errorf("busybox argv does not pin source with -I: %v", busybox)
	}

	v6 := argsFor(VariantIputils, FamilyV6, "2001:db8::1", "2001:db8::5", 2)
	if !hasFlag(v6, "-6") {
		t.Errorf("v6 argv should carry -6: %v", v6)
	}
}

// fakePing is a Runner that replays a scripted sequence of outputs, one per
// cycle, so the loop's EWMA and loss window can be stepped deterministically.
type fakePing struct {
	scripts []scriptedRun
	calls   int
	seen    [][]string
}

type scriptedRun struct {
	stdout, stderr string
	exit           int
	err            error
}

func (f *fakePing) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	f.seen = append(f.seen, append([]string{name}, args...))
	if len(f.scripts) == 0 {
		return "", "", 0, nil
	}
	i := f.calls
	if i >= len(f.scripts) {
		i = len(f.scripts) - 1
	}
	f.calls++
	s := f.scripts[i]
	return s.stdout, s.stderr, s.exit, s.err
}

func replyFixture(rtt string) scriptedRun {
	return scriptedRun{stdout: "PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.\n" +
		"64 bytes from 198.51.100.5: icmp_seq=1 ttl=63 time=" + rtt + " ms\n\n" +
		"--- 198.51.100.5 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"}
}

func timeoutFixture() scriptedRun {
	return scriptedRun{
		stdout: "PING 198.51.100.5 (198.51.100.5) 56(84) bytes of data.\n\n" +
			"--- 198.51.100.5 ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n",
		exit: 1,
	}
}

func contains(s, sub string) bool {
	return sub == "" || strings.Contains(s, sub)
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func hasFlagValue(args []string, flag, val string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == val {
			return true
		}
	}
	return false
}

func isNaN(f float64) bool { return f != f }
