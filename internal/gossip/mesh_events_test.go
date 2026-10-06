package gossip

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
)

// This file covers the memberlist event path. It exists because the rest of the
// suite passes an Options.MemberlistConfig override, which used to mean the mesh
// never installed its event delegate and no test ever ran a memberlist callback.
// The deadlock they can hide (a callback re-entering memberlist while memberlist
// holds its node lock) is invisible until an operator sends SIGTERM.

// freePort reserves a loopback port that is free for both transports memberlist
// binds (UDP gossip and TCP push/pull on the same port) and returns it. A
// production-shaped mesh derives its port from Gossip.BindPort, so a test cannot
// ask memberlist for an ephemeral one; it reserves a port, releases it and hands
// it to the mesh. The window between release and bind is a race in principle and
// not one in practice on a loopback interface; startProdMesh retries on the
// unlucky case.
func freePort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve TCP port: %v", err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err != nil {
			_ = tcp.Close()
			continue // that port is taken on UDP too; try another
		}
		_ = udp.Close()
		if err := tcp.Close(); err != nil {
			t.Fatalf("release TCP port: %v", err)
		}
		return port
	}
	t.Fatal("no loopback port was free for both UDP and TCP")
	return 0
}

// startProdMesh starts a mesh with the production wiring: Options.MemberlistConfig
// stays nil, so the mesh derives its memberlist configuration and installs its own
// delegate and event delegate, exactly as `transitd` does when gossip.key is set.
func startProdMesh(t *testing.T, c *config.Config, interval time.Duration) *Mesh {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		c.Gossip.BindPort = freePort(t)
		m, err := New(Options{
			Config:   c,
			Snapshot: func() HealthPayload { return HealthPayload{} },
			Interval: interval,
			Log:      discardLogger(),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := m.Start(context.Background()); err != nil {
			lastErr = err
			continue
		}
		return m
	}
	t.Fatalf("Start with a production-shaped config failed 3 times: %v", lastErr)
	return nil
}

// shutdownWithin fails the test if Shutdown has not returned after d, dumping
// every goroutine so a deadlock is legible instead of a bare test timeout.
func shutdownWithin(t *testing.T, m *Mesh, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		m.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("Shutdown did not return within %s — the mesh is deadlocked:\n%s", d, buf[:n])
	}
}

// TestMemberlistConfigAlwaysInstallsTheEventDelegate pins the wiring that keeps
// this bug class visible. An Options.MemberlistConfig override replaces the
// transport settings, not the mesh's own wiring: the event delegate goes on
// either way, so every mesh test exercises the callback path. While the override
// could silently skip it, a callback deadlock passed CI green.
func TestMemberlistConfigAlwaysInstallsTheEventDelegate(t *testing.T) {
	c := testConfig(t, "wiring")

	// The override path.
	override := memberlistConfigFor(c)
	overridden, err := New(Options{
		Config:           c,
		Snapshot:         func() HealthPayload { return HealthPayload{} },
		MemberlistConfig: override,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := overridden.memberlistConfig()
	if err != nil {
		t.Fatalf("memberlistConfig: %v", err)
	}
	// The transport settings still come from the override (the name is the
	// override's), so a test keeps the loopback port it pinned; only the mesh's
	// own wiring is added on top.
	if got.Name != override.Name {
		t.Errorf("memberlistConfig dropped the override's settings: Name = %q, want %q", got.Name, override.Name)
	}
	if got.Events == nil {
		t.Error("Events is nil with an override: the callback path is not wired and no test can catch a callback deadlock")
	}

	// The production path.
	derived, err := New(Options{Config: c, Snapshot: func() HealthPayload { return HealthPayload{} }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conf, err := derived.memberlistConfig()
	if err != nil {
		t.Fatalf("memberlistConfig: %v", err)
	}
	if conf.Events == nil {
		t.Error("Events is nil on the derived config: production would run with no membership callbacks at all")
	}
}

// TestProductionWiringShutdownReturns is the regression test for the shutdown
// deadlock. memberlist's deadNode holds its node lock for the whole call and then
// invokes NotifyLeave; a callback that reads the member count back through the
// memberlist API (NumMembers) blocks on that same non-reentrant RWMutex, so
// Shutdown never finished and SIGTERM had to be escalated to SIGKILL.
func TestProductionWiringShutdownReturns(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c := testConfig(t, "prod-shutdown")
	m := startProdMesh(t, c, time.Hour)
	shutdownWithin(t, m, 5*time.Second)
}

// TestMembershipEventsRefreshTheMemberCount covers the other half of the contract:
// the event callbacks still do their job (the gauge and the mesh's own count follow
// a join and a leave) without the callback reading memberlist state.
//
// The broadcast interval is an hour, so the periodic tick cannot be what updates
// the count: only the event-driven refresh can. It also drives the leave path that
// the original deadlock was reported on, at process level and here.
func TestMembershipEventsRefreshTheMemberCount(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	a := startProdMesh(t, testConfig(t, "evt-a"), time.Hour)
	defer func() { a.Shutdown() }()
	b := startProdMesh(t, testConfig(t, "evt-b"), time.Hour)
	defer func() { b.Shutdown() }()

	local := a.Local()
	if local == "" {
		t.Fatal("a.Local() is empty; the mesh did not open a listener")
	}
	// Join b to a. The mesh under test is b's event delegate: b learns about a,
	// and a learns about b through the push/pull b's join triggers.
	if _, err := b.ml.Join([]string{local}); err != nil {
		t.Fatalf("Join: %v", err)
	}

	waitForCount(t, "both meshes to count 2 members", 10*time.Second, func() bool {
		return a.Status().Members == 2 && b.Status().Members == 2
	})
	// The gauge is the metric this refresh exists for; a count nobody publishes
	// would be a dead metric.
	waitForCount(t, "transitd_gossip_members to reach 2", 10*time.Second, func() bool {
		return gossipMembersValue(t) == 2
	})

	// A leave is the path the bug was reported on: b broadcasts a leave, a must
	// drop it from its count. Shutdown returning at all is the deadlock assertion.
	shutdownWithin(t, b, 5*time.Second)
	waitForCount(t, "a to count 1 member after b left", 10*time.Second, func() bool {
		return a.Status().Members == 1
	})
}

// waitForCount polls cond until it holds or the deadline passes, reporting what
// the test was waiting for.
func waitForCount(t *testing.T, what string, deadline time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", deadline, what)
}
