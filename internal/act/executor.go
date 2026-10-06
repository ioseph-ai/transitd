package act

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// Runner executes one vtysh batch: an ordered list of command lines, run as a
// single unit. It is the seam that lets the unit tier run without vtysh and
// without touching a router: production passes ExecRunner, tests pass a
// recording fake.
//
// The interface takes a command LIST, not a file and not a shell string, so a
// command cannot be smuggled in through word splitting, and the runner — not the
// caller — decides how the list reaches vtysh.
type Runner interface {
	// RunBatch runs cmds through vtysh as one batch and returns its combined
	// output. A non-zero vtysh exit is reported as an error.
	RunBatch(ctx context.Context, cmds []string) (string, error)
}

// ExecRunner is the production Runner. It writes the command list to a temporary
// batch file and runs `vtysh -f <file>`.
//
// The temporary file is a transport for commands, NOT configuration: it holds
// `configure terminal` / a mutation / `end`, it is mode 0600 inside a private
// directory, and it is removed before RunBatch returns. Nothing here — and
// nothing anywhere in act — issues FRR's `write file`, which is the command that
// would persist the running configuration. See Batch.Validate.
type ExecRunner struct {
	// Binary overrides the vtysh program; empty means "vtysh" on PATH.
	Binary string
	// Timeout bounds one batch; zero means DefaultBatchTimeout.
	Timeout time.Duration
}

// DefaultBatchTimeout bounds one vtysh batch.
const DefaultBatchTimeout = 10 * time.Second

// RunBatch writes cmds to a temp file and execs `vtysh -f` on it.
//
// The command list is wrapped in `configure terminal` / `end` here, in the runner,
// not in the Batch: a Batch describes a change, and the framing is transport. That is
// also why Batch.Validate forbids those verbs — a caller that put its own framing in
// would be describing a vtysh session instead of a mutation.
func (r ExecRunner) RunBatch(ctx context.Context, cmds []string) (string, error) {
	if len(cmds) == 0 {
		return "", errors.New("act: empty batch")
	}
	bin := r.Binary
	if bin == "" {
		bin = "vtysh"
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultBatchTimeout
	}
	bctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "transitd-act-")
	if err != nil {
		return "", fmt.Errorf("act: batch tempdir: %w", err)
	}
	// The temp dir is a transport for the command list, removed before return. A
	// removal failure is not actionable (the daemon is not a janitor) and must not
	// mask the batch result, so it is deliberately discarded.
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "batch.vtysh")
	body := strings.Join(frame(cmds), "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil { //nolint:gosec // private temp dir, fixed name, 0600
		return "", fmt.Errorf("act: writing batch file: %w", err)
	}

	cmd := exec.CommandContext(bctx, bin, "-f", path) //nolint:gosec // fixed binary, argv slice, no shell
	out, err := cmd.CombinedOutput()
	if err != nil {
		// FRR prints "% Unknown command" per rejected line and still exits 0 for a
		// `vtysh -f` run, so a silent no-op would otherwise look like success. The
		// output is scanned for that marker and the run is reported failed, because a
		// mutation that did not happen must not be recorded as applied.
		if bad := unknownCommand(string(out)); bad != "" {
			return string(out), fmt.Errorf("act: vtysh rejected a command in the batch: %s", bad)
		}
		return string(out), fmt.Errorf("act: vtysh batch exited: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if bad := unknownCommand(string(out)); bad != "" {
		return string(out), fmt.Errorf("act: vtysh rejected a command in the batch: %s", bad)
	}
	return string(out), nil
}

// Frame adds the vtysh configuration-mode framing around a command list. It is
// exported so a test or an alternate runner (the integration tier's stdin transport)
// produces byte-identical input to the production runner.
func Frame(cmds []string) []string { return frame(cmds) }

// frame is Frame's implementation. The framing is added only if the list does not
// already carry it, so calling Frame twice is safe.
func frame(cmds []string) []string {
	first := ""
	if len(cmds) > 0 {
		first = strings.TrimSpace(cmds[0])
	}
	if strings.EqualFold(first, "configure terminal") {
		return append([]string(nil), cmds...)
	}
	out := make([]string, 0, len(cmds)+2)
	out = append(out, "configure terminal")
	out = append(out, cmds...)
	out = append(out, "end")
	return out
}

// unknownCommand returns the first line of vtysh output that reports a rejected
// command, or "". FRR writes "% Unknown command: ..." for a line it did not accept;
// under `vtysh -f` that is not an exit-code failure, so it has to be read from the
// text.
func unknownCommand(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "% Unknown command") || strings.Contains(line, "Unknown command:") {
			return line
		}
	}
	return ""
}

// Executor applies and rolls back Batches, serialising them and auditing each
// attempt.
//
// Idempotency lives here rather than in the commands: the executor tracks which
// named batches are currently applied, so a second Apply of the same batch — or
// a Rollback of one that was never applied — issues no command at all and is
// recorded as "skipped". The underlying commands must ALSO be idempotent (the
// golden batches are: `no neighbor <ip> shutdown` on an already-restored session
// is a no-op in FRR), so the guarantee does not depend on the process still being
// the one that applied it. Across an agent restart the map is empty and the
// first Rollback re-issues the inverse once; that is correct, because FRR's
// idempotency makes it harmless, and the durable record is the audit log and
// transitd_act_ops.
type Executor struct {
	// Runner executes a batch. Nil means an ExecRunner.
	Runner Runner
	// Log receives one audit line per attempt. Nil means slog.Default().
	Log *slog.Logger

	mu      sync.Mutex
	applied map[string]bool
}

// New builds an Executor with production defaults.
func New(r Runner) *Executor {
	if r == nil {
		r = ExecRunner{}
	}
	return &Executor{Runner: r, applied: map[string]bool{}}
}

// log resolves the logger with its default.
func (e *Executor) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// Applied reports whether a named batch is currently applied according to this
// executor. It carries no side effect and is meant for tests and diagnostics.
func (e *Executor) Applied(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applied[name]
}

// Apply performs b's mutation. It validates the batch first, then — under the
// executor's lock, so two mutations never interleave — issues the Apply command
// list unless the batch is already applied.
//
// Every attempt is audited: a structured log line and the
// transitd_act_ops{op="apply",result=...} counter, where result is "applied",
// "skipped" (no-op) or "error".
func (e *Executor) Apply(ctx context.Context, b Batch) error {
	return e.run(ctx, b, metrics.ActOpApply, b.Apply, true)
}

// Rollback undoes b's mutation. It is Apply with the inverse command list and the
// opposite state transition: a Rollback of a batch that is not applied is a no-op
// (result="skipped"), so calling it twice issues the inverse exactly once — the
// idempotency issue #4 requires.
func (e *Executor) Rollback(ctx context.Context, b Batch) error {
	return e.run(ctx, b, metrics.ActOpRollback, b.Rollback, false)
}

// run is the shared apply/rollback path. want is the post-condition: true makes
// the batch applied, false makes it un-applied. cmds is the side that achieves
// it.
func (e *Executor) run(ctx context.Context, b Batch, op string, cmds []string, want bool) error {
	if err := b.Validate(); err != nil {
		e.audit(op, metrics.ActResultError, b.Name, err)
		return err
	}

	// The lock spans the exec on purpose: this serialises router mutations, so
	// two batches can never interleave their commands, and it makes the
	// check-then-act below atomic. A batch is a short-lived vtysh invocation, so
	// the contention this creates is between mutations that must not run together
	// anyway.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.applied == nil {
		e.applied = map[string]bool{}
	}
	if e.applied[b.Name] == want {
		e.audit(op, metrics.ActResultSkipped, b.Name, nil)
		return nil
	}

	out, err := e.Runner.RunBatch(ctx, cmds)
	if err != nil {
		e.audit(op, metrics.ActResultError, b.Name, err)
		return fmt.Errorf("act: %s %q: %w", op, b.Name, err)
	}
	e.applied[b.Name] = want
	e.log().Info("act: batch "+op+"ed",
		"batch", b.Name, "op", op, "commands", len(cmds),
		"description", b.Description, "vtysh_output", strings.TrimSpace(out))
	metrics.ActOps.WithLabelValues(op, metrics.ActResultApplied).Inc()
	return nil
}

// audit writes the structured log line and the counter for an attempt that did
// not reach (or did not need) a successful exec.
func (e *Executor) audit(op, result, name string, err error) {
	attrs := []any{"batch", name, "op", op, "result", result}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		e.log().Error("act: batch "+op+" failed", attrs...)
	} else {
		e.log().Info("act: batch "+op+" skipped (already in the requested state)", attrs...)
	}
	metrics.ActOps.WithLabelValues(op, result).Inc()
}
