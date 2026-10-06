package pinning

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
)

// fakeRunner records the argv it was handed and returns canned output. It is
// the whole reason Verifier is an interface: no root, no netlink, no host
// routing table is touched by the unit tier.
type fakeRunner struct {
	output string
	err    error
	calls  [][]string
}

func (f *fakeRunner) Lookup(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.output, f.err
}

func transit() config.Transit {
	return config.Transit{
		Name:            "main",
		ProbeSource:     "192.0.2.1",
		ProbeTarget:     "203.0.113.5",
		EgressInterface: "eth-transit",
	}
}

// TestVerifyMatchesExpectedEgress is the happy path: the kernel routes the
// probe target out of the configured interface and the transit is verified.
func TestVerifyMatchesExpectedEgress(t *testing.T) {
	r := &fakeRunner{output: "203.0.113.5 from 192.0.2.1 dev eth-transit table 200 uid 0\n    cache\n"}
	v := &RouteVerifier{Runner: r}

	got := v.Check(context.Background(), transit())

	if !got.Verified {
		t.Fatalf("Verified = false, reason %q", got.Reason)
	}
	if got.EgressIf != "eth-transit" {
		t.Errorf("EgressIf = %q, want eth-transit", got.EgressIf)
	}
	if got.Transit != "main" {
		t.Errorf("Transit = %q, want main", got.Transit)
	}
	if got.Reason == "" {
		t.Error("Reason must be populated even on success")
	}
}

// TestVerifyMismatchedEgress is the mis-pinned case the whole feature exists
// for (issue #1): the probe resolves to a different interface than the transit
// expects, so it must be reported unverified with the OBSERVED interface
// surfaced — an operator needs to see where traffic actually went, not just
// that it was wrong.
func TestVerifyMismatchedEgress(t *testing.T) {
	r := &fakeRunner{output: "203.0.113.5 from 192.0.2.1 dev eth-default table 200 uid 0\n"}
	v := &RouteVerifier{Runner: r}

	got := v.Check(context.Background(), transit())

	if got.Verified {
		t.Fatal("Verified = true for a mismatched egress")
	}
	if got.EgressIf != "eth-default" {
		t.Errorf("EgressIf = %q, want the observed eth-default", got.EgressIf)
	}
	for _, want := range []string{"eth-default", "eth-transit"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("Reason %q does not mention %q", got.Reason, want)
		}
	}
}

// TestVerifyBuildsPinnedArgv pins the exact argv the preflight must use. If a
// refactor drops `from <source>`, the lookup silently answers a different
// question — the source pin is what selects the policy route being tested.
func TestVerifyBuildsPinnedArgv(t *testing.T) {
	r := &fakeRunner{output: "203.0.113.5 from 192.0.2.1 dev eth-transit uid 0\n"}
	v := &RouteVerifier{Runner: r}

	v.Check(context.Background(), transit())

	want := []string{"ip", "route", "get", "203.0.113.5", "from", "192.0.2.1"}
	if len(r.calls) != 1 {
		t.Fatalf("runner called %d times, want 1", len(r.calls))
	}
	if strings.Join(r.calls[0], " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", r.calls[0], want)
	}
}

// TestVerifyV6Output proves the parser is address-family agnostic: the v6
// route line carries the same `dev` token, so a v6 transit verifies the same
// way a v4 one does.
func TestVerifyV6Output(t *testing.T) {
	tr := transit()
	tr.ProbeSource = "2001:db8::1"
	tr.ProbeTarget = "2001:db8:dead::5"
	tr.EgressInterface = "eth6"

	r := &fakeRunner{output: "2001:db8:dead::5 from 2001:db8::1 dev eth6 table 201 src 2001:db8::1 metric 1024 pref medium\n"}
	v := &RouteVerifier{Runner: r}

	got := v.Check(context.Background(), tr)
	if !got.Verified || got.EgressIf != "eth6" {
		t.Fatalf("v6 verify: %+v, want verified eth6", got)
	}
}

// TestVerifyFailures covers every non-happy path. None of them may panic, and
// none may return Verified — an unclear answer is never a pass.
func TestVerifyFailures(t *testing.T) {
	cases := []struct {
		name   string
		runner *fakeRunner
		mut    func(*config.Transit)
		wantIn string
	}{
		{
			name:   "lookup error (source not local)",
			runner: &fakeRunner{output: "RTNETLINK answers: Network is unreachable\n", err: errors.New("exit status 2")},
			wantIn: "Network is unreachable",
		},
		{
			name:   "unparseable output",
			runner: &fakeRunner{output: "some unexpected text\n"},
			wantIn: "not understood",
		},
		{
			name:   "empty output",
			runner: &fakeRunner{output: ""},
			wantIn: "not understood",
		},
		{
			name:   "incomplete config",
			runner: &fakeRunner{},
			mut:    func(tr *config.Transit) { tr.EgressInterface = "" },
			wantIn: "incomplete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := transit()
			if tc.mut != nil {
				tc.mut(&tr)
			}
			v := &RouteVerifier{Runner: tc.runner}

			got := v.Check(context.Background(), tr)

			if got.Verified {
				t.Fatalf("Verified = true on failure case %q", tc.name)
			}
			if !strings.Contains(got.Reason, tc.wantIn) {
				t.Errorf("Reason %q does not contain %q", got.Reason, tc.wantIn)
			}
			if got.Transit != "main" {
				t.Errorf("Transit = %q, want main on every path", got.Transit)
			}
		})
	}
}

// TestVerifyExportsPinGauge pins the contract that Verify (unlike Check) records
// the outcome as transitd_pin_verified: the pinning package is where the pin
// metric is produced.
func TestVerifyExportsPinGauge(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("metrics.Register: %v", err)
	}
	r := &fakeRunner{output: "203.0.113.5 from 192.0.2.1 dev eth-transit uid 0\n"}
	v := &RouteVerifier{Runner: r}

	v.Verify(context.Background(), transit())

	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	found := false
	for _, f := range fams {
		if f.GetName() != "transitd_pin_verified" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == metrics.LabelTransit && lp.GetValue() == "main" {
					found = true
					if m.GetGauge().GetValue() != 1 {
						t.Errorf("pin_verified{main} = %v, want 1", m.GetGauge().GetValue())
					}
				}
			}
		}
	}
	if !found {
		t.Error("Verify did not export transitd_pin_verified{main}")
	}
}

// TestParseEgressInterface exercises the parser directly against the output
// shapes `ip route get` produces: a directly-connected route (no `via`), a
// route via a next hop, and a cached route with an indented second line.
func TestParseEgressInterface(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		want    string
		wantErr bool
	}{
		{"direct dev", "203.0.113.5 from 192.0.2.1 dev eth0 table 200 uid 0 \n", "eth0", false},
		{"via next hop", "203.0.113.5 from 192.0.2.1 via 198.51.100.2 dev eth1 uid 0\n", "eth1", false},
		{"cached route", "203.0.113.5 via 198.51.100.2 dev eth2 src 192.0.2.1 uid 0 \n    cache \n", "eth2", false},
		{"v6", "2001:db8:dead::5 from 2001:db8::1 dev eth0 src 2001:db8::1 metric 1024 pref medium\n", "eth0", false},
		{"unreachable", "RTNETLINK answers: Network is unreachable\n", "", true},
		{"blank", "\n\n", "", true},
		{"no dev token", "local 192.0.2.1 dev lo table local\n", "lo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEgressInterface(tc.out)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
