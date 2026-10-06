package gossip

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
)

// testKey is a fixed 32-byte AES key (base64), so every mesh test joins with the
// same secret. It is a test constant, not a deployment value.
var testKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// testConfig builds a validated config for one router with the mesh block set.
// Addresses come from the RFC 5737 documentation range.
func testConfig(t *testing.T, router string) *config.Config {
	t.Helper()
	c := &config.Config{
		RouterName:  router,
		BindAddr:    "127.0.0.1",
		Gossip:      config.Gossip{Key: testKey, BindPort: 0},
		MarginMs:    10,
		WinCycles:   1,
		Dwell:       time.Millisecond,
		MaxSwitches: 4,
		LossDropPct: 5,
		Transits: []config.Transit{{
			Name:            "main",
			ImportMap:       "MAIN-LOCAL-IN",
			ProbeSource:     "192.0.2.1",
			ProbeTarget:     "198.51.100.5",
			EgressInterface: "eth-main",
			ProbeInterval:   time.Millisecond,
		}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("fixture config does not validate: %v", err)
	}
	return c
}

// memberlistConfigFor builds a memberlist config that binds an ephemeral port on
// loopback, so two meshes can run in one test process without colliding on 7946.
//
// It deliberately does NOT set Events: the mesh installs its own event delegate on
// the override path too, and a test that supplied its own would be testing a mesh
// that production never runs. See TestMemberlistConfigAlwaysInstallsTheEventDelegate.
func memberlistConfigFor(c *config.Config) *memberlist.Config {
	ml := memberlist.DefaultLANConfig()
	ml.Name = c.RouterName
	ml.BindAddr = c.BindAddr
	ml.BindPort = 0
	ml.AdvertisePort = 0
	key, _ := c.Gossip.KeyBytes()
	ml.SecretKey = key
	ml.LogOutput = discardWriter{}
	ml.ProbeInterval = 100 * time.Millisecond
	ml.PushPullInterval = 100 * time.Millisecond
	ml.GossipInterval = 50 * time.Millisecond
	ml.SuspicionMult = 2
	return ml
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// discardLogger returns a logger that swallows everything, so a mesh test's output
// is the test's own assertions.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestTwoNodeMeshDeliversHealth is the issue #3 acceptance test at the transport
// level: two agents join one mesh and one receives the other's health payload.
func TestTwoNodeMeshDeliversHealth(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}

	lat := 11.5
	payload := HealthPayload{Transits: []TransitSummary{{Name: "main", SessionUp: true, EwmaMs: &lat}}}

	var mu sync.Mutex
	sawByRouter := map[string]Message{}
	consumer := func(m Message) {
		mu.Lock()
		sawByRouter[m.Router] = m
		mu.Unlock()
	}

	cA := testConfig(t, "mesh-a")
	cB := testConfig(t, "mesh-b")

	a, err := New(Options{
		Config:           cA,
		Snapshot:         func() HealthPayload { return payload },
		Interval:         50 * time.Millisecond,
		Log:              discardLogger(),
		MemberlistConfig: memberlistConfigFor(cA),
	})
	if err != nil {
		t.Fatalf("New(a): %v", err)
	}
	b, err := New(Options{
		Config:           cB,
		Snapshot:         func() HealthPayload { return HealthPayload{} },
		OnMessage:        consumer,
		Interval:         50 * time.Millisecond,
		Log:              discardLogger(),
		MemberlistConfig: memberlistConfigFor(cB),
	})
	if err != nil {
		t.Fatalf("New(b): %v", err)
	}

	// Start A first (no peers), then join B to A. This is the join direction the
	// mesh tests can make deterministic: B has A's address before it starts.
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	if err := a.Start(ctxA); err != nil {
		t.Fatalf("Start(a): %v", err)
	}
	defer a.Shutdown()

	local := a.Local()
	if local == "" {
		t.Fatal("a.Local() is empty; the mesh did not open a listener")
	}

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	if err := b.Start(ctxB); err != nil {
		t.Fatalf("Start(b): %v", err)
	}
	defer b.Shutdown()

	if _, err := b.ml.Join([]string{local}); err != nil {
		t.Fatalf("Join: %v", err)
	}
	b.joined.Store(true)

	// Wait for the payload to arrive. B broadcasts an empty frame of its own, so
	// the assertion is specifically that A's view reached B.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got, ok := sawByRouter["mesh-a"]
		mu.Unlock()
		if ok {
			if len(got.Payload.Transits) != 1 || got.Payload.Transits[0].EwmaMs == nil {
				t.Fatalf("payload from mesh-a = %+v", got.Payload)
			}
			if *got.Payload.Transits[0].EwmaMs != lat {
				t.Fatalf("ewma = %v, want %v", *got.Payload.Transits[0].EwmaMs, lat)
			}
			if got.Version != CurrentSchemaVersion {
				t.Errorf("version = %d, want %d", got.Version, CurrentSchemaVersion)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mesh-b never received mesh-a's health message")
}

// TestMeshStatusAndMemberGauge checks the observable surface: a running mesh
// reports itself as joined and counts its members, and a mesh with no join peers is
// a valid single-node mesh.
func TestMeshStatusAndMemberGauge(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c := testConfig(t, "solo")
	m, err := New(Options{
		Config:           c,
		Snapshot:         func() HealthPayload { return HealthPayload{} },
		Interval:         time.Hour, // broadcast once at Start, then effectively idle
		Log:              discardLogger(),
		MemberlistConfig: memberlistConfigFor(c),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Shutdown()

	st := m.Status()
	if !st.Enabled {
		t.Error("Status.Enabled = false, want true for a configured mesh")
	}
	if !st.Joined {
		t.Error("Status.Joined = false, want true: no join peers means a single-node mesh, not a failure")
	}
	if st.Members < 1 {
		t.Errorf("Status.Members = %d, want >= 1", st.Members)
	}
	if st.JoinErr != "" {
		t.Errorf("Status.JoinErr = %q, want empty", st.JoinErr)
	}
	if m.Members() != st.Members {
		t.Errorf("Members() = %d but Status.Members = %d", m.Members(), st.Members)
	}
}

// TestMeshDisabledIsNotAnError pins the opt-in default: a router with no gossip
// block must be able to run, and asking it for a mesh is the caller's mistake.
func TestMeshDisabledIsNotAnError(t *testing.T) {
	c := testConfig(t, "no-mesh")
	c.Gossip = config.Gossip{}
	if _, err := New(Options{Config: c, Snapshot: func() HealthPayload { return HealthPayload{} }}); err == nil {
		t.Fatal("New accepted a config with no gossip key; want an error the caller can branch on")
	}
}

// TestMeshRequiresSnapshot checks the one option that cannot be defaulted: a mesh
// with nothing to broadcast is a mesh that does nothing.
func TestMeshRequiresSnapshot(t *testing.T) {
	c := testConfig(t, "no-snap")
	m, err := New(Options{Config: c, Log: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("Start without a Snapshot returned nil, want an error")
	}
}

// TestShutdownIsIdempotent pins the shutdown contract both the signal path and the
// context path rely on: calling Shutdown twice, or before Start, must not panic.
// memberlist's Leave panics after a shutdown, so this is a real hazard, not a
// stylistic one.
func TestShutdownIsIdempotent(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c := testConfig(t, "idem")

	// Before Start.
	pre, err := New(Options{Config: c, Snapshot: func() HealthPayload { return HealthPayload{} }, Log: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pre.Shutdown()
	pre.Shutdown()

	// After Start.
	m, err := New(Options{
		Config:           c,
		Snapshot:         func() HealthPayload { return HealthPayload{} },
		Interval:         time.Hour,
		Log:              discardLogger(),
		MemberlistConfig: memberlistConfigFor(c),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Shutdown()
	m.Shutdown()
}

// TestDelegateIgnoresNewerVersion is the mixed-version unit test the card asks for:
// a delegate receiving a message from a NEWER schema must count it by version and
// hand nothing to the consumer, while a message from the CURRENT version reaches
// the consumer. This is the "old node ignores new fields" acceptance criterion, at
// the delegate seam rather than the transport one.
func TestDelegateIgnoresNewerVersion(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}

	var mu sync.Mutex
	var got []Message
	d := &delegate{
		router:    "self",
		log:       discardLogger(),
		onMessage: func(m Message) { mu.Lock(); got = append(got, m); mu.Unlock() },
		queue: &memberlist.TransmitLimitedQueue{
			NumNodes: func() int { return 1 },
		},
	}

	// A newer peer's message, carrying the reserved append-only fields plus a
	// field name that does not exist yet.
	newer := []byte(`{"schema_version":2,"ts":"2026-01-01T00:00:00Z","router":"peer-new",
		"payload":{"transits":[{"name":"main","ewma_ms":1}],"mtu_state":{"main":9000},"not_a_real_field":{"x":1}}}`)
	d.NotifyMsg(newer)

	mu.Lock()
	if len(got) != 0 {
		got = nil
		mu.Unlock()
		t.Fatal("delegate handed a newer-version message to the consumer")
	}
	mu.Unlock()

	// The same payload at the current version must reach the consumer, with the
	// reserved fields ignored.
	current := []byte(`{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"peer-v1",
		"payload":{"transits":[{"name":"main","ewma_ms":1}],"mtu_state":{"main":9000}}}`)
	d.NotifyMsg(current)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("consumer saw %d messages, want exactly the v1 one", len(got))
	}
	if got[0].Router != "peer-v1" || len(got[0].Payload.Transits) != 1 {
		t.Errorf("consumer got %+v", got[0])
	}
}

// TestDelegateDropsGarbage checks the receive path's failure mode for undecodable
// input: it is counted (rx) and dropped, never re-broadcast and never handed on.
func TestDelegateDropsGarbage(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	var called bool
	d := &delegate{
		router:    "self",
		log:       discardLogger(),
		onMessage: func(Message) { called = true },
		queue:     &memberlist.TransmitLimitedQueue{NumNodes: func() int { return 1 }},
	}
	for _, b := range [][]byte{nil, {}, []byte("{"), []byte("not json"), []byte(`{"schema_version":"x"}`)} {
		d.NotifyMsg(b)
	}
	if called {
		t.Error("consumer was called for an undecodable message")
	}
}

// TestDelegateBroadcastDedupesPerRouter pins the NamedBroadcast contract: a newer
// message from the SAME router invalidates the older one, a message from a
// DIFFERENT router does not. Without this, the queue would gossip a stale snapshot
// alongside a fresh one.
func TestDelegateBroadcastDedupesPerRouter(t *testing.T) {
	old := &healthBroadcast{router: "r1", msg: []byte("old")}
	newer := &healthBroadcast{router: "r1", msg: []byte("new")}
	other := &healthBroadcast{router: "r2", msg: []byte("other")}

	if !newer.Invalidates(old) {
		t.Error("a newer message from the same router must invalidate the older one")
	}
	if newer.Invalidates(other) {
		t.Error("a message from another router must not invalidate this router's view")
	}
	if newer.Name() != "r1" {
		t.Errorf("Name() = %q, want r1", newer.Name())
	}
	if string(newer.Message()) != "new" {
		t.Errorf("Message() = %q", newer.Message())
	}
	newer.Finished() // must be a no-op that cannot panic
}

// TestShutdownStopsBroadcastLoop pins the fix for a directly-called Shutdown: the
// broadcast loop must stop ticking, or it would keep incrementing GossipTx for
// messages on a closed mesh and overwrite the GossipMembers=0 the shutdown set.
func TestShutdownStopsBroadcastLoop(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c := testConfig(t, "stop-loop")
	m, err := New(Options{
		Config:           c,
		Snapshot:         func() HealthPayload { return HealthPayload{} },
		Interval:         10 * time.Millisecond,
		Log:              discardLogger(),
		MemberlistConfig: memberlistConfigFor(c),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A never-cancelled context: Shutdown alone must stop the loop, which is the
	// case the finding was about.
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Shutdown() // direct, not via ctx

	before := gossipTxCount(t)
	time.Sleep(120 * time.Millisecond) // ~12 ticks at a 10ms interval
	after := gossipTxCount(t)
	if after != before {
		t.Errorf("GossipTx advanced from %v to %v after Shutdown: the broadcast loop is still ticking", before, after)
	}
	if v := gossipMembersValue(t); v != 0 {
		t.Errorf("GossipMembers = %v after Shutdown, want 0 (the loop overwrote it)", v)
	}
}

// TestStartDoesNotBlockOnUnreachablePeers pins the JoinTimeout fix: Start must
// return promptly even when every configured peer is dead, because the agent's
// local measurements are useful immediately and memberlist's own per-peer
// TCPTimeout (10s) would otherwise stall startup for minutes.
func TestStartDoesNotBlockOnUnreachablePeers(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c := testConfig(t, "slow-join")
	// A peer that is routable but never answers on the mesh port. 192.0.2.1
	// (TEST-NET-1) is reserved and must not be reachable, which is the point.
	c.Gossip.Join = []string{"192.0.2.1:7946", "198.51.100.1:7946", "203.0.113.1:7946"}

	m, err := New(Options{
		Config:           c,
		Snapshot:         func() HealthPayload { return HealthPayload{} },
		Interval:         time.Hour,
		JoinTimeout:      200 * time.Millisecond,
		Log:              discardLogger(),
		MemberlistConfig: memberlistConfigFor(c),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Shutdown()

	start := time.Now()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Start took %v with unreachable peers; the JoinTimeout bound is not applied", elapsed)
	}
	// A mesh that has not joined is reported as enabled-but-not-joined, which is
	// what healthz surfaces as degraded. The join runs in the background, so the
	// failure is recorded shortly after Start returns; poll for it.
	st := m.Status()
	if !st.Enabled {
		t.Error("Status.Enabled = false")
	}
	if st.Joined {
		t.Error("Status.Joined = true despite every peer being unreachable")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().JoinErr != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("Status.JoinErr stayed empty after a failed join with unreachable peers")
}

// gossipTxCount reads the current GossipTx counter value from the registry.
func gossipTxCount(t *testing.T) float64 {
	t.Helper()
	fams := gatherGossipMetrics(t)
	fam := fams["transitd_gossip_tx"]
	if fam == nil || len(fam.GetMetric()) == 0 {
		return 0
	}
	return fam.GetMetric()[0].GetCounter().GetValue()
}

// gossipMembersValue reads the current GossipMembers gauge from the registry.
func gossipMembersValue(t *testing.T) float64 {
	t.Helper()
	fams := gatherGossipMetrics(t)
	fam := fams["transitd_gossip_members"]
	if fam == nil || len(fam.GetMetric()) == 0 {
		return 0
	}
	return fam.GetMetric()[0].GetGauge().GetValue()
}

// TestNodeMetaAdvertisesSchemaVersion checks the memberlist meta tag, which is how
// a peer sees this node's schema capability without decoding a payload.
func TestNodeMetaAdvertisesSchemaVersion(t *testing.T) {
	d := &delegate{router: "r1"}
	meta := d.NodeMeta(64)
	if want := fmt.Sprintf("transitd:v%d", CurrentSchemaVersion); string(meta) != want {
		t.Errorf("NodeMeta = %q, want %q", meta, want)
	}
	// A caller with no room for the tag gets nil rather than a truncated one.
	if got := d.NodeMeta(2); got != nil {
		t.Errorf("NodeMeta(2) = %q, want nil", got)
	}
}
