//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/act"
	"github.com/ioseph-ai/transitd/internal/bgpwatch"
	"github.com/ioseph-ai/transitd/internal/config"
)

// Round-trip timeouts. A BGP session going administratively down is immediate;
// coming back up needs the connect timer, so the restore budget is the longer of the
// two. roundTripPos is the poll pause — the poller's 1 Hz cap makes a tighter loop
// pointless.
const (
	downTimeout  = 30 * time.Second
	upTimeout    = 90 * time.Second
	roundTripPos = 1 * time.Second
)

// composeShowRunner implements bgpwatch.Runner by exec'ing `vtysh -c 'show <query>'`
// inside a lab container. It is the real vtysh path bgpwatch runs in production,
// reached through the compose lab instead of a local socket.
type composeShowRunner struct{ service string }

func (r composeShowRunner) Show(ctx context.Context, query string) (string, error) {
	// vtysh is the lab's own helper (test/integration/seed_test.go); it prepends
	// nothing, so the `show` verb bgpwatch withholds is added here.
	full := []string{
		"compose", "-f", composeFile,
		"exec", "-T", r.service, "vtysh", "-c", "show " + query,
	}
	out, err := exec.CommandContext(ctx, "docker", full...).Output() //nolint:gosec // fixed binary, argv slice built from constants
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), fmt.Errorf("show %q in %s: %w: %s", query, r.service, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return string(out), fmt.Errorf("show %q in %s: %w", query, r.service, err)
	}
	return string(out), nil
}

// composeActRunner implements act.Runner by piping a batch into `vtysh` on the lab
// container's stdin. It is the transport the production ExecRunner achieves with a
// temp file; here the container's stdin is the file, which keeps the test free of a
// docker cp round-trip. The commands are the same list act produced and validated.
type composeActRunner struct{ service string }

func (r composeActRunner) RunBatch(ctx context.Context, cmds []string) (string, error) {
	full := []string{
		"compose", "-f", composeFile,
		"exec", "-T", r.service, "vtysh",
	}
	cmd := exec.CommandContext(ctx, "docker", full...) //nolint:gosec // fixed binary, argv slice built from constants
	// act.Frame adds the `configure terminal` / `end` framing the production runner
	// adds, so this transport exercises the same command stream.
	cmd.Stdin = strings.NewReader(strings.Join(act.Frame(cmds), "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("vtysh batch in %s: %w: %s", r.service, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// TestNeighborShutdownRestoreRoundTrip is issue #4's integration acceptance: against a
// live FRR container, apply the neighbor-shutdown batch, observe the session go down
// in bgpwatch's own view, apply the rollback, and observe it re-establish. Every
// observation is read through bgpwatch — the same parser and poller production runs —
// so the test proves the read path and the mutation path agree about the world.
func TestNeighborShutdownRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	waitForPeersEstablished(t, "r1", []string{r1PeerR2})

	poller := bgpwatch.New(
		configBGPWatch(),
		composeShowRunner{service: "r1"},
	)
	exec := act.New(composeActRunner{service: "r1"})

	// Baseline: bgpwatch must see the session up before anything is mutated, or the
	// "down" that follows would prove nothing about the injection.
	waitSessionState(t, poller, r1PeerR2, true, downTimeout)

	batch, err := act.NeighborShutdown(r1ASN, r1PeerR2)
	if err != nil {
		t.Fatalf("NeighborShutdown: %v", err)
	}
	if err := exec.Apply(ctx, batch); err != nil {
		t.Fatalf("Apply shutdown: %v", err)
	}
	// The session must be observed DOWN through bgpwatch. `neighbor shutdown` yields
	// "Idle (Admin)"; the poller reports Up=false for it.
	waitSessionState(t, poller, r1PeerR2, false, downTimeout)

	// The OTHER session must be untouched: a single-neighbor injection is not a
	// router-wide outage, and asserting it guards against a batch that took the
	// wrong peer (or every peer) down.
	waitSessionState(t, poller, r1PeerInject, true, downTimeout)

	// Rollback, then a bounded wait for re-establishment.
	if err := exec.Rollback(ctx, batch); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	waitSessionState(t, poller, r1PeerR2, true, upTimeout)

	// Idempotency against the live router: a second rollback must be a no-op, and the
	// session must stay up. This is the integration half of the recording-fake unit
	// test — it proves the inverse is harmless on FRR itself.
	if err := exec.Rollback(ctx, batch); err != nil {
		t.Fatalf("second Rollback: %v", err)
	}
	waitSessionState(t, poller, r1PeerR2, true, downTimeout)
}

// configBGPWatch returns the bgpwatch config the integration poller runs with. The
// interval is the 1 Hz floor: the poll loop below waits at least a second between
// reads anyway, and polling faster is forbidden by design.
func configBGPWatch() (cfg config.BGPWatchConfig) {
	cfg.Enabled = true
	cfg.MaxPrefixes = 1000
	cfg.Interval = time.Second
	return
}

// waitSessionState polls bgpwatch's summary until the named neighbor's session reads
// up (or down), or the budget expires. It fails with the last observed state so a
// timeout is diagnosable rather than a bare "not met".
//
// The poller enforces the 1 Hz cap, so a poll inside the window is skipped with a
// short sleep rather than treated as a failure — the test is bounded by wall time,
// not by a poll count.
func waitSessionState(t *testing.T, p *bgpwatch.Poller, neighbor string, wantUp bool, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last bgpwatch.Session
	var lastErr error
	for {
		sum, err := p.Summary(context.Background())
		switch {
		case errors.Is(err, bgpwatch.ErrRateLimited):
			time.Sleep(roundTripPos)
			continue
		case err != nil:
			lastErr = err
		default:
			s, ok := sum.Sessions[neighbor]
			if ok {
				last = s
				if s.Up == wantUp {
					return
				}
			} else {
				lastErr = fmt.Errorf("neighbor %s absent from the summary", neighbor)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %s did not reach up=%t within %s (last state=%q up=%t, last err=%v)",
				neighbor, wantUp, budget, last.State, last.Up, lastErr)
		}
		time.Sleep(roundTripPos)
	}
}
