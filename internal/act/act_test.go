package act

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// recordingRunner is the unit tier's stand-in for vtysh. It records every batch it
// is asked to run — so a test can assert exactly which command lists were issued,
// and how many times — and can be made to fail, to exercise the error path.
type recordingRunner struct {
	mu      sync.Mutex
	batches [][]string
	err     error
}

func (r *recordingRunner) RunBatch(_ context.Context, cmds []string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, append([]string(nil), cmds...))
	if r.err != nil {
		return "", r.err
	}
	return "", nil
}

// calls returns the number of batches issued.
func (r *recordingRunner) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

// issued returns the batches issued so far.
func (r *recordingRunner) issued() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.batches))
	for i, b := range r.batches {
		out[i] = append([]string(nil), b...)
	}
	return out
}

// newTestExecutor builds an executor over the recording fake with a discarding log.
func newTestExecutor(r Runner) *Executor {
	e := New(r)
	e.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return e
}

// golden reads a committed golden batch file and splits it into command lines. The
// goldens are the command lists WITHOUT the `configure terminal` / `end` framing,
// which the executor owns; storing the bare list keeps the golden about the
// mutation, not about the transport.
func golden(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // committed fixture, fixed dir
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// TestGoldenBatches pins the two golden batches issue #4 names — neighbor shutdown
// and tcp-mss clamp — against their committed golden files, byte-exact, on both
// the apply and the rollback side. A change to either side is a behavior change
// and must show up as a golden diff.
func TestGoldenBatches(t *testing.T) {
	const (
		asn      = 64496
		neighbor = "198.51.100.1"
	)
	cases := []struct {
		name     string
		batch    func(t *testing.T) Batch
		apply    string
		rollback string
	}{
		{
			name: "neighbor-shutdown",
			batch: func(t *testing.T) Batch {
				b, err := NeighborShutdown(asn, neighbor)
				if err != nil {
					t.Fatalf("NeighborShutdown: %v", err)
				}
				return b
			},
			apply:    "neighbor-shutdown.apply.golden",
			rollback: "neighbor-shutdown.rollback.golden",
		},
		{
			name: "tcp-mss-clamp",
			batch: func(t *testing.T) Batch {
				b, err := TCPMSSClamp(asn, neighbor, 1400)
				if err != nil {
					t.Fatalf("TCPMSSClamp: %v", err)
				}
				return b
			},
			apply:    "tcp-mss-clamp.apply.golden",
			rollback: "tcp-mss-clamp.rollback.golden",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.batch(t)
			if err := b.Validate(); err != nil {
				t.Fatalf("batch does not validate: %v", err)
			}
			assertLines(t, "Apply", b.Apply, golden(t, tc.apply))
			assertLines(t, "Rollback", b.Rollback, golden(t, tc.rollback))
		})
	}
}

// TestRollbackTwiceIsNoOp is issue #4's idempotency requirement, enforced by the
// recording fake: apply once, then roll back twice, and the inverse must be issued
// exactly once. The second rollback is a no-op — no vtysh call at all.
func TestRollbackTwiceIsNoOp(t *testing.T) {
	rr := &recordingRunner{}
	e := newTestExecutor(rr)
	b, err := NeighborShutdown(64496, "198.51.100.1")
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	ctx := context.Background()

	if err := e.Apply(ctx, b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := e.Rollback(ctx, b); err != nil {
		t.Fatalf("first Rollback: %v", err)
	}
	if err := e.Rollback(ctx, b); err != nil {
		t.Fatalf("second Rollback: %v", err)
	}

	// Exactly two batches were issued: the apply and the ONE rollback. The second
	// rollback reached no runner.
	if got := rr.calls(); got != 2 {
		t.Fatalf("batches issued = %d, want 2 (apply + one rollback); the second rollback must be a no-op", got)
	}
	issued := rr.issued()
	assertLines(t, "issued Apply", issued[0], golden(t, "neighbor-shutdown.apply.golden"))
	assertLines(t, "issued Rollback", issued[1], golden(t, "neighbor-shutdown.rollback.golden"))

	if e.Applied(b.Name) {
		t.Error("batch still reads as applied after a rollback")
	}
}

// TestApplyTwiceIsNoOp is the mirror: a second Apply of an already-applied batch
// issues nothing. Together with the rollback test this is the "safe to re-run"
// property the drill's defer-restore depends on.
func TestApplyTwiceIsNoOp(t *testing.T) {
	rr := &recordingRunner{}
	e := newTestExecutor(rr)
	b, err := TCPMSSClamp(64496, "198.51.100.1", 1400)
	if err != nil {
		t.Fatalf("TCPMSSClamp: %v", err)
	}
	ctx := context.Background()

	if err := e.Apply(ctx, b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := e.Apply(ctx, b); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if got := rr.calls(); got != 1 {
		t.Fatalf("batches issued = %d, want 1 (the second apply is a no-op)", got)
	}
	if !e.Applied(b.Name) {
		t.Error("batch does not read as applied")
	}
}

// TestRollbackWithoutApplyIsNoOp covers restore-before-inject: a rollback of a
// batch that was never applied must issue nothing. That is the crash-window case
// from the drill design — a state file written but no injection performed, so
// restore runs against nothing.
func TestRollbackWithoutApplyIsNoOp(t *testing.T) {
	rr := &recordingRunner{}
	e := newTestExecutor(rr)
	b, err := NeighborShutdown(64496, "198.51.100.1")
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	if err := e.Rollback(context.Background(), b); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := rr.calls(); got != 0 {
		t.Fatalf("batches issued = %d, want 0 for a rollback of an unapplied batch", got)
	}
}

// TestApplyAuditsToLogAndCounter checks the audit contract: every attempt records
// a transitd_act_ops{op,result} series. Idempotent no-ops record result="skipped",
// real execs record "applied".
func TestApplyAuditsToLogAndCounter(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	rr := &recordingRunner{}
	e := newTestExecutor(rr)
	b, err := NeighborShutdown(64496, "198.51.100.1")
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	ctx := context.Background()
	if err := e.Apply(ctx, b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := e.Apply(ctx, b); err != nil { // skipped
		t.Fatalf("second Apply: %v", err)
	}

	applied := counterValue(t, metrics.ActOpApply, metrics.ActResultApplied)
	skipped := counterValue(t, metrics.ActOpApply, metrics.ActResultSkipped)
	if applied < 1 {
		t.Errorf("act_ops{op=apply,result=applied} = %v, want >= 1", applied)
	}
	if skipped < 1 {
		t.Errorf("act_ops{op=apply,result=skipped} = %v, want >= 1 (the no-op must be audited)", skipped)
	}
}

// TestApplyErrorIsAuditedAndRetryable checks a failed exec: the error is returned,
// the batch does NOT read as applied, the result="error" series is incremented, and
// a later Apply with a working runner succeeds (so a transient vtysh failure is
// retryable rather than sticky).
func TestApplyErrorIsAuditedAndRetryable(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	rr := &recordingRunner{err: errors.New("vtysh: socket unavailable")}
	e := newTestExecutor(rr)
	b, err := NeighborShutdown(64496, "198.51.100.1")
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	if err := e.Apply(context.Background(), b); err == nil {
		t.Fatal("Apply returned nil for a failing runner")
	}
	if e.Applied(b.Name) {
		t.Error("a failed apply left the batch reading as applied")
	}
	if v := counterValue(t, metrics.ActOpApply, metrics.ActResultError); v < 1 {
		t.Errorf("act_ops{op=apply,result=error} = %v, want >= 1", v)
	}

	rr.mu.Lock()
	rr.err = nil
	rr.mu.Unlock()
	if err := e.Apply(context.Background(), b); err != nil {
		t.Fatalf("Apply after the runner recovered: %v", err)
	}
	if !e.Applied(b.Name) {
		t.Error("a successful retry did not mark the batch applied")
	}
}

// TestBatchValidateRejectsIrreversibleAndPersistent pins the batch validator: an
// empty side, a persistence verb (`write file` and friends), and a command that
// smuggles a second command through a newline are all refused BEFORE anything is
// exec'd.
func TestBatchValidateRejectsIrreversibleAndPersistent(t *testing.T) {
	const okCmd = "no neighbor 198.51.100.1 shutdown"
	cases := []struct {
		name  string
		batch Batch
		want  string
	}{
		{
			"no name",
			Batch{Apply: []string{okCmd}, Rollback: []string{okCmd}},
			"name is required",
		},
		{
			"empty apply",
			Batch{Name: "x", Rollback: []string{okCmd}},
			"Apply is empty",
		},
		{
			"empty rollback",
			Batch{Name: "x", Apply: []string{okCmd}},
			"irreversible",
		},
		{
			"write file",
			Batch{Name: "x", Apply: []string{"write file"}, Rollback: []string{okCmd}},
			"runtime-only",
		},
		{
			"write memory",
			Batch{Name: "x", Apply: []string{okCmd}, Rollback: []string{"write memory"}},
			"runtime-only",
		},
		{
			"configure framing",
			Batch{Name: "x", Apply: []string{"configure terminal"}, Rollback: []string{okCmd}},
			"runtime-only",
		},
		{
			"embedded newline",
			Batch{Name: "x", Apply: []string{"neighbor 198.51.100.1 shutdown\nwrite file"}, Rollback: []string{okCmd}},
			"control character",
		},
		{
			"empty command",
			Batch{Name: "x", Apply: []string{""}, Rollback: []string{okCmd}},
			"empty command",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.batch.Validate()
			if err == nil {
				t.Fatal("Validate accepted an invalid batch")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}

	// And a refusal reaches no runner.
	rr := &recordingRunner{}
	e := newTestExecutor(rr)
	bad := Batch{Name: "x", Apply: []string{"write file"}, Rollback: []string{okCmd}}
	if err := e.Apply(context.Background(), bad); err == nil {
		t.Fatal("Apply accepted a batch that persists configuration")
	}
	if got := rr.calls(); got != 0 {
		t.Errorf("a refused batch issued %d runner calls, want 0", got)
	}
}

// TestForbiddenVerbIsWordAnchored guards against an over-broad ban: a legitimate
// batch whose DESCRIPTION mentions a persistence verb is fine, because only the
// command verbs are checked, and a command whose value merely contains the word is
// fine too — what is refused is a command whose verb IS one.
func TestForbiddenVerbIsWordAnchored(t *testing.T) {
	b := Batch{
		Name:        "desc-ok",
		Apply:       []string{"description transitd never runs write file"},
		Rollback:    []string{"no description transitd never runs write file"},
		Description: "a batch whose description explains the write-file ban",
	}
	if err := b.Validate(); err != nil {
		t.Errorf("Validate refused a batch that only MENTIONS a forbidden verb in a value: %v", err)
	}
	// But a command that STARTS with the verb is refused.
	bad := Batch{Name: "x", Apply: []string{"write file"}, Rollback: []string{"no description x"}}
	if err := bad.Validate(); err == nil {
		t.Error("Validate accepted a command whose verb is `write`")
	}
}

// TestNeighborShutdownRejectsBadInput checks the constructors validate their
// inputs, so a config-derived neighbor address cannot become a second command.
func TestNeighborShutdownRejectsBadInput(t *testing.T) {
	cases := []struct {
		name     string
		asn      int
		neighbor string
	}{
		{"zero ASN", 0, "198.51.100.1"},
		{"negative ASN", -1, "198.51.100.1"},
		{"empty neighbor", 64496, ""},
		{"neighbor with a space", 64496, "198.51.100.1 shutdown"},
		{"neighbor with a semicolon", 64496, "198.51.100.1; write file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NeighborShutdown(tc.asn, tc.neighbor); err == nil {
				t.Error("NeighborShutdown accepted an invalid input")
			}
		})
	}
	// And the MSS constructor validates its value against FRR's range.
	if _, err := TCPMSSClamp(64496, "198.51.100.1", 0); err == nil {
		t.Error("TCPMSSClamp accepted an MSS of 0")
	}
	if _, err := TCPMSSClamp(64496, "198.51.100.1", 70000); err == nil {
		t.Error("TCPMSSClamp accepted an MSS over 65535")
	}
}

// assertLines compares a command list against a golden, element by element, so a
// failure names the exact differing line.
func assertLines(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %q, want %q", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", what, i, got[i], want[i])
		}
	}
}

// counterValue sums a transitd_act_ops series.
func counterValue(t *testing.T, op, result string) float64 {
	t.Helper()
	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "transitd_act_ops" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels[metrics.LabelOp] == op && labels[metrics.LabelResult] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}
