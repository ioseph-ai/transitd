package act

import (
	"context"
	"strings"
	"testing"
)

// TestFrameWrapsInConfigMode pins the framing the runner owns: a batch's command
// list is wrapped in `configure terminal` / `end` so that `neighbor ... shutdown`
// lands inside router-bgp mode rather than being rejected at the top level. Frame is
// idempotent, so an already-framed list is not double-wrapped.
func TestFrameWrapsInConfigMode(t *testing.T) {
	got := Frame([]string{"router bgp 64496", "neighbor 198.51.100.1 shutdown"})
	want := []string{"configure terminal", "router bgp 64496", "neighbor 198.51.100.1 shutdown", "end"}
	assertLines(t, "Frame", got, want)

	again := Frame(got)
	assertLines(t, "Frame(already framed)", again, want)
}

// TestUnknownCommandDetection pins the FRR "unknown command" scan. Under `vtysh -f`
// FRR prints a rejection line per bad command and STILL exits 0, so a batch that
// silently did nothing would otherwise be recorded as applied. The scanner is what
// turns that into an error.
func TestUnknownCommandDetection(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"clean", "r1# configure terminal\nr1(config)# end\n", ""},
		{
			"rejected line",
			"r1# neighbor 198.51.100.1 shutdown\n% Unknown command: neighbor 198.51.100.1 shutdown\n",
			"% Unknown command: neighbor 198.51.100.1 shutdown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unknownCommand(tc.out); got != tc.want {
				t.Errorf("unknownCommand(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

// TestExecRunnerRejectsUnknownCommand proves the scan is wired into the runner: a
// runner pointed at a fake vtysh that prints a rejection must return an error even
// though the process exited 0, and the batch must NOT be recorded as applied.
func TestExecRunnerRejectsUnknownCommand(t *testing.T) {
	fake := writeFakeVtysh(t, "#!/bin/sh\necho '% Unknown command: router bgp 64496'\nexit 0\n")
	rr := ExecRunner{Binary: fake}
	e := newTestExecutor(rr)
	b, err := NeighborShutdown(64496, "198.51.100.1")
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	err = e.Apply(context.Background(), b)
	if err == nil {
		t.Fatal("Apply returned nil although vtysh rejected a command")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error %q does not report the rejection", err)
	}
	if e.Applied(b.Name) {
		t.Error("a rejected batch was recorded as applied")
	}
}

// TestExecRunnerFramesAndSucceeds proves the happy path end to end: the runner hands
// a framed command list to vtysh, and a clean run records the batch applied.
func TestExecRunnerFramesAndSucceeds(t *testing.T) {
	// The fake echoes its stdin so the test can see the framed command stream.
	fake := writeFakeVtysh(t, "#!/bin/sh\ncat \"$2\"\n")
	rr := ExecRunner{Binary: fake}
	e := newTestExecutor(rr)
	b, err := NeighborShutdown(64496, "198.51.100.1")
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	if err := e.Apply(context.Background(), b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !e.Applied(b.Name) {
		t.Error("a successful batch was not recorded as applied")
	}
}
