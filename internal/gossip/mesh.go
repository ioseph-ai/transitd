package gossip

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
)

// DefaultBroadcastInterval is how often this router puts a fresh health snapshot
// on the mesh when Options.Interval is unset. It matches the default probe and
// decision cadence: broadcasting faster than samples arrive only re-sends the
// same view.
const DefaultBroadcastInterval = 30 * time.Second

// DefaultJoinTimeout bounds the startup join attempt. It is short on purpose: a
// router that cannot reach its peers must still come up and measure its own
// transits. A failed join is reported, not fatal.
const DefaultJoinTimeout = 5 * time.Second

// SnapshotFunc builds the health payload this router currently wants to gossip.
// It is called on each broadcast tick and on a TCP push/pull, never inside a
// memberlist receive callback.
type SnapshotFunc func() HealthPayload

// OnMessageFunc receives every decoded message whose schema version this build
// understands. It must not block: it runs on memberlist's UDP receive path.
type OnMessageFunc func(Message)

// Options configures a Mesh. Config and Snapshot are required; everything else has
// a production default.
type Options struct {
	// Config supplies the mesh settings (key, port, peers) and the router name
	// used as this node's memberlist identity.
	Config *config.Config

	// Snapshot builds the payload to broadcast. Required to Start: a mesh that
	// broadcasts nothing is a mesh that does nothing.
	Snapshot SnapshotFunc

	// OnMessage, when set, receives each understood message. Optional: a router
	// with no consumer still joins the mesh, so its peers see it and the member
	// count is right.
	OnMessage OnMessageFunc

	// Interval is the broadcast cadence. Zero means DefaultBroadcastInterval.
	Interval time.Duration

	// JoinTimeout bounds the startup join. Zero means DefaultJoinTimeout.
	JoinTimeout time.Duration

	// Log receives join and mesh lines. Nil means slog.Default().
	Log *slog.Logger

	// MemberlistConfig, when non-nil, replaces the configuration derived from
	// Config.Gossip. It exists so tests (in this package and in internal/agent) can
	// pin an ephemeral loopback port and a fast push/pull cadence; production code
	// leaves it nil and gets DefaultLANConfig-derived settings.
	MemberlistConfig *memberlist.Config
}

// Status is the mesh's observable state, for healthz (issue #5) and operators.
type Status struct {
	// Enabled is whether a mesh was configured at all. A disabled mesh is not a
	// fault: single-router deployments are expected.
	Enabled bool
	// Joined is whether the startup join reached at least one peer. A mesh with
	// no configured peers is joined by definition.
	Joined bool
	// Members is the current alive member count, including this router.
	Members int
	// JoinErr is the last startup join failure, empty when the join succeeded.
	JoinErr string
}

// Mesh is a running (or startable) health mesh.
type Mesh struct {
	opts Options
	log  *slog.Logger

	ml   *memberlist.Memberlist
	del  *delegate
	done chan struct{}

	// stop is closed by Shutdown to tell the broadcast loop to exit; loopExited
	// is closed by the loop when it has. Shutdown waits on the latter before
	// tearing memberlist down, so no tick can be in flight against a closed mesh
	// (which would count a GossipTx for a message never sent and republish the
	// member gauge as non-zero after shutdown set it to 0).
	stop       chan struct{}
	loopExited chan struct{}
	// stopped is the fast check broadcastOnce consults, so a tick already
	// dequeued by select does not do work after the stop signal.
	stopped atomic.Bool

	joined  atomic.Bool
	joinErr atomic.Pointer[string]

	// closeOnce guards Shutdown against a double call: memberlist's Leave panics
	// if it runs after Shutdown ("leave after shutdown"), and both the signal path
	// and the context path reach this.
	closeOnce sync.Once
}

// New builds a Mesh. It does not open a socket — the listener exists only after
// Start — so constructing a Mesh in a test is free.
func New(opts Options) (*Mesh, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("gossip: Options.Config is required")
	}
	if !opts.Config.Gossip.Enabled() {
		return nil, fmt.Errorf("gossip: no mesh configured (gossip.key is empty)")
	}
	if _, err := opts.Config.Gossip.KeyBytes(); err != nil {
		return nil, fmt.Errorf("gossip: %w", err)
	}
	m := &Mesh{
		opts: opts,
		log:  opts.Log,
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.opts.Interval <= 0 {
		m.opts.Interval = DefaultBroadcastInterval
	}
	if m.opts.JoinTimeout <= 0 {
		m.opts.JoinTimeout = DefaultJoinTimeout
	}
	return m, nil
}

// Enabled reports whether a mesh is configured for this router. The agent uses it
// to decide whether to start one at all.
func (m *Mesh) Enabled() bool { return m.opts.Config.Gossip.Enabled() }

// memberlistConfig derives the memberlist configuration from the transitd config.
// DefaultLANConfig is the documented starting point for a mesh on an
// operator-controlled transport, which is the deployment this agent assumes.
func (m *Mesh) memberlistConfig() (*memberlist.Config, error) {
	if m.opts.MemberlistConfig != nil {
		return m.opts.MemberlistConfig, nil
	}
	c := m.opts.Config
	key, err := c.Gossip.KeyBytes()
	if err != nil {
		return nil, err
	}
	ml := memberlist.DefaultLANConfig()
	// The node name is the router name: operators read the mesh in router terms,
	// and it is also what tags a peer's view in the merged health state.
	ml.Name = c.RouterName
	ml.BindAddr = c.BindAddr
	ml.BindPort = c.Gossip.Port()
	ml.AdvertisePort = ml.BindPort
	// Encryption is mandatory, not optional: an unencrypted mesh accepts health
	// state from anyone who can reach the port, and the merged view is what
	// preference decisions read (issue #3's threat note).
	ml.SecretKey = key
	// The delegate protocol level is memberlist's own compatibility gate and is
	// distinct from the envelope's schema_version. It only needs to change if the
	// delegate's memberlist-level contract changes (the NodeMeta shape, or the
	// fact that LocalState carries an envelope); the health schema then evolves
	// behind the envelope without touching it.
	ml.DelegateProtocolVersion = delegateProtocolVersion
	ml.DelegateProtocolMin = delegateProtocolMin
	ml.DelegateProtocolMax = delegateProtocolMax
	// memberlist logs through the stdlib log package; route it into slog at debug
	// level so transport chatter stays out of an operator's log but is available
	// when someone debugs a join. memberlist logs addresses, never key bytes.
	ml.LogOutput = logAdapter{log: m.log}
	ml.Events = &eventDelegate{mesh: m}
	return ml, nil
}

// delegateProtocolVersion is transitd's memberlist delegate protocol level. It is
// deliberately fixed at 1.
const (
	delegateProtocolVersion uint8 = 1
	delegateProtocolMin     uint8 = 1
	delegateProtocolMax     uint8 = 1
)

// Start creates the listener, joins the configured peers and begins broadcasting.
// It returns immediately; the mesh stops when ctx is cancelled or Shutdown is
// called.
//
// A failed join is NOT an error and does not stop the mesh: the node is up,
// advertises itself, and a peer can still join IT. The failure is recorded in
// Status so healthz can report a degraded mesh instead of it going quiet.
func (m *Mesh) Start(ctx context.Context) error {
	if m.opts.Snapshot == nil {
		return fmt.Errorf("gossip: Options.Snapshot is required to start the mesh")
	}
	mlConf, err := m.memberlistConfig()
	if err != nil {
		return fmt.Errorf("gossip: %w", err)
	}

	router := m.opts.Config.RouterName
	m.del = &delegate{
		router:    router,
		snapshot:  m.opts.Snapshot,
		onMessage: m.opts.OnMessage,
		log:       m.log,
	}
	// The retransmit limit is a function of cluster size, so the queue asks the
	// mesh for it. Before the mesh exists the honest answer is 1 (this node).
	m.del.queue = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int { return m.members() },
	}
	if mlConf.RetransmitMult > 0 {
		m.del.queue.RetransmitMult = mlConf.RetransmitMult
	}
	// This is the wiring that makes the mesh carry transitd's data at all: without
	// Delegate set, memberlist has nowhere to deliver user messages and never
	// consults GetBroadcasts.
	mlConf.Delegate = m.del
	m.loopExited = make(chan struct{})

	ml, err := memberlist.Create(mlConf)
	if err != nil {
		return fmt.Errorf("gossip: creating mesh: %w", err)
	}
	m.ml = ml
	metrics.GossipMembers.Set(float64(m.members()))

	if peers := m.opts.Config.Gossip.Join; len(peers) > 0 {
		m.joinAsync(peers)
	} else {
		// A single-node mesh is a valid configuration (the first router of a
		// fleet) and is deliberately not an error.
		m.joined.Store(true)
		m.log.Info("gossip: mesh started with no join peers (single-node mesh)",
			"router", router, "port", mlConf.BindPort)
	}

	go m.broadcastLoop(ctx)
	// A separate watcher (not the loop) owns the ctx-driven shutdown, so the loop
	// can exit and announce it without Shutdown waiting on the caller itself.
	go func() {
		select {
		case <-ctx.Done():
			m.Shutdown()
		case <-m.done:
		}
	}()
	return nil
}

// joinAsync contacts the configured peers without blocking Start.
//
// memberlist's Join is synchronous per peer, and each unreachable peer can hold
// it for TCPTimeout (10s in DefaultLANConfig). With a handful of dead peers that
// is minutes, during which the agent has not started measuring its own transits
// — the wrong trade for a router agent, whose local view is useful immediately.
//
// The bound is honoured by racing the join against JoinTimeout: on timeout the
// join keeps running in the background (memberlist will finish it and a late peer
// is still a good peer), but Start returns and the loop comes up. The timeout is
// recorded as the outcome so healthz reports a mesh that has not yet joined.
func (m *Mesh) joinAsync(peers []string) {
	router := m.opts.Config.RouterName
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := m.ml.Join(peers)
		done <- result{n: n, err: err}
	}()
	go func() {
		timer := time.NewTimer(m.opts.JoinTimeout)
		defer timer.Stop()
		select {
		case r := <-done:
			if r.err != nil {
				s := r.err.Error()
				m.joinErr.Store(&s)
				m.log.Warn("gossip: startup join failed — the mesh is up and will still accept inbound joins",
					"router", router, "peers", peers, "err", r.err)
				return
			}
			m.joined.Store(true)
			m.joinErr.Store(nil)
			m.log.Info("gossip: joined mesh", "router", router, "peers_contacted", r.n, "members", m.members())
		case <-timer.C:
			s := fmt.Sprintf("join still in progress after %s", m.opts.JoinTimeout)
			m.joinErr.Store(&s)
			m.log.Warn("gossip: join is slow; continuing in the background",
				"router", router, "peers", peers, "timeout", m.opts.JoinTimeout)
		case <-m.done:
			// Shutting down; nothing to report.
		}
	}()
}

// broadcastLoop puts a fresh snapshot on the mesh every interval and refreshes
// the member gauge. The snapshot is built here, on this goroutine, so a slow
// builder cannot stall memberlist's receive path.
//
// It announces its exit on loopExited so Shutdown can wait for it: without that
// wait, a tick already selected could run after Shutdown and count a GossipTx for
// a message on a closed mesh, or republish the member gauge as non-zero.
func (m *Mesh) broadcastLoop(ctx context.Context) {
	defer close(m.loopExited)
	t := time.NewTicker(m.opts.Interval)
	defer t.Stop()
	// Send one immediately: a peer that comes up after this node should not wait a
	// full interval for its first view.
	m.broadcastOnce()
	for {
		select {
		case <-ctx.Done():
			// Exit only; the watcher goroutine owns the ctx-driven Shutdown. The
			// loop must not call it here, because Shutdown waits for this loop to
			// exit and would deadlock against its own caller.
			return
		case <-m.stop:
			// Shutdown was called directly (not via ctx), or by another path. Stop
			// ticking; Shutdown is waiting on loopExited.
			return
		case <-t.C:
			if m.stopped.Load() {
				return
			}
			m.broadcastOnce()
		}
	}
}

func (m *Mesh) broadcastOnce() {
	if m.stopped.Load() {
		return
	}
	metrics.GossipMembers.Set(float64(m.members()))
	msg, err := Encode(m.opts.Config.RouterName, time.Now(), m.opts.Snapshot())
	if err != nil {
		// The payload is built entirely from local values, so an encode error is a
		// bug rather than bad input; log it and skip this tick rather than tearing
		// the mesh down.
		m.log.Error("gossip: encoding health message", "router", m.opts.Config.RouterName, "err", err)
		return
	}
	m.del.queue.QueueBroadcast(&healthBroadcast{router: m.opts.Config.RouterName, msg: msg})
	metrics.GossipTx.Inc()
}

// members returns the alive member count, or 1 (just this node) before the
// memberlist exists. The floor of 1 matters: a gauge reading 0 would look like a
// fully partitioned fleet rather than "not started yet".
func (m *Mesh) members() int {
	if m.ml == nil {
		return 1
	}
	if n := m.ml.NumMembers(); n > 0 {
		return n
	}
	return 1
}

// Members returns the current alive member count, including this router.
func (m *Mesh) Members() int { return m.members() }

// Status reports the mesh's observable state.
func (m *Mesh) Status() Status {
	s := Status{
		Enabled: m.opts.Config.Gossip.Enabled(),
		Joined:  m.joined.Load(),
		Members: m.members(),
	}
	if p := m.joinErr.Load(); p != nil {
		s.JoinErr = *p
	}
	return s
}

// Local returns this node's advertised "host:port", or "" before Start. It is what
// an operator (or a test) hands to a peer's join list.
func (m *Mesh) Local() string {
	if m.ml == nil {
		return ""
	}
	return m.ml.LocalNode().Address()
}

// Shutdown leaves the mesh and closes its listeners. It is safe to call more than
// once and before Start (a no-op), because both the signal path and the context
// path reach it.
func (m *Mesh) Shutdown() {
	m.closeOnce.Do(func() {
		close(m.done)
		// Signal the loop and wait for it, so no broadcast tick can still be in
		// flight once memberlist is torn down below. The wait is bounded: if Start
		// was never called the loop never existed, and if the loop is the caller
		// (it is not — the ctx watcher owns that path) this would deadlock, so the
		// select on done covers a second Shutdown racing this one.
		m.stopped.Store(true)
		close(m.stop)
		if m.loopExited != nil {
			select {
			case <-m.loopExited:
			case <-time.After(2 * time.Second):
				m.log.Warn("gossip: broadcast loop did not stop within 2s; continuing shutdown")
			}
		}
		if m.ml == nil {
			metrics.GossipMembers.Set(0)
			return
		}
		// A clean leave tells peers this node is gone, rather than making them
		// suspect it for a probe timeout. The timeout is short because a shutting
		// down router must not hang on an unreachable peer.
		if err := m.ml.Leave(2 * time.Second); err != nil {
			m.log.Debug("gossip: leave broadcast did not complete", "err", err)
		}
		if err := m.ml.Shutdown(); err != nil {
			m.log.Warn("gossip: shutdown", "err", err)
		}
		metrics.GossipMembers.Set(0)
	})
}

// delegate implements memberlist.Delegate. Every method must be safe for
// concurrent use: memberlist calls them from its UDP receive path and from its
// periodic push/pull, in parallel.
type delegate struct {
	router    string
	snapshot  SnapshotFunc
	queue     *memberlist.TransmitLimitedQueue
	onMessage OnMessageFunc
	log       *slog.Logger
}

// NodeMeta advertises this node's schema capability in the memberlist alive
// message. It is deliberately tiny and stable: it lets a peer see that this node
// speaks the v1 health schema without decoding a full payload.
func (d *delegate) NodeMeta(limit int) []byte {
	meta := []byte("transitd:v" + strconv.FormatUint(uint64(CurrentSchemaVersion), 10))
	if len(meta) > limit {
		return nil
	}
	return meta
}

// NotifyMsg is the receive path. It runs inside memberlist's UDP packet loop, so
// it must not block: decode, count, hand to the consumer, return. Decode is
// fuzz-tested never to panic, because these bytes come from anyone holding the
// shared key.
//
// The receive counter increments on every message that reaches here, whatever
// its framing, so a peer streaming garbage is visible as rx traffic without a
// version breakdown. The version counter increments only once the envelope
// decoded.
func (d *delegate) NotifyMsg(b []byte) {
	metrics.GossipRx.Inc()
	msg, err := Decode(b)
	if err != nil {
		// A malformed message is logged and dropped, never re-broadcast: one
		// peer's bad framing must not be able to stall the mesh.
		d.log.Warn("gossip: dropping undecodable message", "err", err)
		return
	}
	metrics.GossipSchemaRx.WithLabelValues(strconv.FormatUint(uint64(msg.Version), 10)).Inc()
	if !msg.Known {
		// A newer peer. Counted by version above and ignored here, on purpose and
		// without an error: this is the rolling-upgrade case the append-only
		// schema exists to make safe.
		d.log.Debug("gossip: ignoring message from a newer schema version",
			"from", msg.Router, "version", msg.Version, "current", CurrentSchemaVersion)
		return
	}
	if d.onMessage != nil {
		d.onMessage(msg)
	}
}

// GetBroadcasts returns the queued health messages for memberlist to piggyback on
// its gossip packets.
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return d.queue.GetBroadcasts(overhead, limit)
}

// LocalState is sent to a peer over TCP during a join or push/pull, so a joining
// node learns this router's current view immediately rather than waiting for the
// next broadcast tick.
func (d *delegate) LocalState(_ bool) []byte {
	if d.snapshot == nil {
		return nil
	}
	// Encoded through the same Encode as the UDP path, so a peer receives one wire
	// format whichever transport carried it.
	b, err := Encode(d.router, time.Now(), d.snapshot())
	if err != nil {
		d.log.Error("gossip: encoding local state for push/pull", "router", d.router, "err", err)
		return nil
	}
	return b
}

// MergeRemoteState receives a peer's LocalState. It is decoded through exactly the
// same versioned path as a UDP message, so the two transports cannot drift in
// their tolerance for old or newer payloads.
func (d *delegate) MergeRemoteState(buf []byte, _ bool) {
	if len(buf) == 0 {
		return
	}
	d.NotifyMsg(buf)
}

// healthBroadcast is one queued health message. Implementing memberlist's
// NamedBroadcast is what makes the queue keep only the newest view per router: a
// later message invalidates the earlier one, so a fleet never gossips a stale
// snapshot alongside a fresh one.
type healthBroadcast struct {
	router string
	msg    []byte
}

// Invalidates reports whether newMsg supersedes b. Only the same router's newer
// message does: two routers' views coexist, and one router has exactly one
// current view.
func (b *healthBroadcast) Invalidates(other memberlist.Broadcast) bool {
	o, ok := other.(*healthBroadcast)
	return ok && o.router == b.router
}

func (b *healthBroadcast) Message() []byte { return b.msg }

// Finished is required by memberlist.Broadcast. There is nothing to release: the
// message is an immutable byte slice shared with the queue.
func (b *healthBroadcast) Finished() {}

// Name implements memberlist.NamedBroadcast, keying the queue's dedup on the router
// whose view the message carries.
func (b *healthBroadcast) Name() string { return b.router }

// eventDelegate keeps the member gauge current between broadcast ticks. Without
// it, a member joining just after a tick would go uncounted for a full interval.
type eventDelegate struct{ mesh *Mesh }

func (e *eventDelegate) NotifyJoin(_ *memberlist.Node)   { e.refresh() }
func (e *eventDelegate) NotifyLeave(_ *memberlist.Node)  { e.refresh() }
func (e *eventDelegate) NotifyUpdate(_ *memberlist.Node) { e.refresh() }

func (e *eventDelegate) refresh() {
	metrics.GossipMembers.Set(float64(e.mesh.members()))
}

// logAdapter writes memberlist's stdlib log lines into the mesh's slog logger at
// debug level. It never fails, because a memberlist log line must not be able to
// abort a transport operation.
type logAdapter struct{ log *slog.Logger }

func (l logAdapter) Write(p []byte) (int, error) {
	l.log.Debug("memberlist: " + strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
