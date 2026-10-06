package probes

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestExecRunnerBinaryOverride checks that ExecRunner.Binary is honoured: the
// documented field must not be decorative. It points Binary at /bin/echo and
// asserts the named program (which would not exist) is not what ran.
func TestExecRunnerBinaryOverride(t *testing.T) {
	if _, err := exec.LookPath("echo"); err != nil {
		t.Skip("no echo binary on PATH")
	}
	r := ExecRunner{Binary: "echo"}
	// The loop names "ping"; with Binary set, "echo" must run instead and the
	// args are echoed back as stdout.
	stdout, _, code, err := r.Run(context.Background(), "ping", "hello-arg")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "hello-arg") {
		t.Errorf("stdout = %q, want the echoed arg (Binary override not honoured)", stdout)
	}
}

// TestExecRunnerAgainstSystemPing exercises the real production path — the system
// ping binary, pinned with -I — against loopback. It exists because the golden
// parser tests replay text: they would keep passing if the argv we build were
// rejected by the actual binary. This test proves the argv is accepted and that
// a real reply parses back to OutcomeReply.
//
// It skips (not fails) when no ping binary is on PATH, so the unit tier still runs
// on a minimal image. It uses loopback only: no external traffic, no privileges
// beyond what ping already has.
func TestExecRunnerAgainstSystemPing(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("no ping binary on PATH")
	}

	r := ExecRunner{}
	variant := DetectVariant(context.Background(), r)
	if variant != VariantIputils && variant != VariantBusybox {
		t.Fatalf("DetectVariant returned an unknown variant %q", variant)
	}
	t.Logf("detected ping variant: %s", variant)

	stdout, stderr, code, err := r.Run(context.Background(),
		"ping", argsFor(variant, FamilyV4, "127.0.0.1", "127.0.0.1", 2)...)
	if err != nil {
		t.Fatalf("ping exec error: %v", err)
	}
	if code != 0 {
		t.Fatalf("ping to loopback exited %d: %s", code, stderr)
	}

	got := ParsePing(stdout, stderr)
	if got.Outcome != OutcomeReply {
		t.Fatalf("Outcome = %v, want reply (stdout=%q stderr=%q)", got.Outcome, stdout, stderr)
	}
	if got.RttMs <= 0 {
		t.Errorf("RttMs = %v, want > 0", got.RttMs)
	}
	if got.Received != 1 {
		t.Errorf("Received = %d, want 1", got.Received)
	}
}
