# Design: TCP-handshake probe mode (stateful-edge asymmetry detection)

> P1 backlog feature. Self-contained design doc. Public-repo safe: examples
> use RFC 5737/3849 ranges (198.51.100.0/24, 2001:db8::/48). Runtime-only;
> no new daemons; **no raw sockets, no packet capture** — pure black-box
> sockets.
> Tracking: #6

## 1. Goal

The ICMP latency/loss probes verify a transit can carry echo traffic. They
cannot see the failure mode small ASes actually hit with stateful upstream
edges: **asymmetric ECMP hashing sends our SYN out transit A while the
SYN-ACK returns via transit B, and a stateful middlebox on B drops the
unsolicited SYN-ACK** (or the SYN itself is policed as "non-HTTP", etc.).
ICMP passes; TCP flows stall. Users experience it as "some sites don't
load on this path".

This feature adds per-transit TCP connect probes (+ optional TLS
handshake) to configurable targets, **pinned to each transit like the ICMP
probes**, producing:

- per-transit TCP connect success rate + handshake latency (EWMA),
- a **divergence signal** (TCP failing where ICMP succeeds) as a first-class
  metric and, opt-in, a decision-engine input,
- optional TLS-level verdicts for targets where plain connect is filtered
  (catches SNI-based interference when compared against a control target).

Black-box only, per the validated research: packet capture to correlate
out-SYN vs in-SYN-ACK is explicitly rejected as too invasive for a 1 vCPU
router agent (and CAP_NET_RAW promiscuous capture is a no). The signal is
*connect success rate + latency*, interpreted with a documented heuristic.

## 2. Why plain sockets beat raw sockets and ping-hacks here

- A `net.Dialer` with `LocalAddr` set to the transit's source IP (and the
  kernel's source-based policy routing doing next-hop selection, exactly as
  the ICMP probes pin transits) requires **no privileges** beyond what
  transitd already has, works identically for IPv4/IPv6, and gets kernel
  SYN retry behavior for free.
- Raw SYN crafting would need CAP_NET_RAW *and* manual retransmit/RTT
  logic and still couldn't see the SYN-ACK direction policy. Rejected.
- The "asymmetry" question is answered statistically, not per-packet:
  enough connect attempts with a stable 5-tuple (Paris constant-flow
  principle: fixed src IP, fixed src port range hashing, fixed target
  port) that hash consistently to one ECMP member; divergence between
  ICMP-health and TCP-health on the *same pinned transit* is the
  middlebox/asymmetry signature.

## 3. User-facing config surface

```go
// added to Transit
type Transit struct {
    // ... existing ...
    ProbeTCP     bool          `yaml:"probe_tcp"`      // opt-in per transit
    TcpTargets   []TcpTarget   `yaml:"tcp_targets"`    // required when probe_tcp
}

type TcpTarget struct {
    Addr      string        `yaml:"addr"`        // host:port, doc example: 198.51.100.10:443
    TLS       bool          `yaml:"tls"`         // after-connect TLS handshake; timeout applies to whole probe
    TLSVerify bool          `yaml:"tls_verify"`  // default true; false allows captive-portal style checks
    Interval  time.Duration `yaml:"interval"`    // default: transit's probe_interval
    Timeout   time.Duration `yaml:"timeout"`     // per-attempt, default 3s
}

// new top-level block
type TcpProbeConfig struct {
    Enabled        bool          `yaml:"enabled"`           // master opt-in
    AttemptsPerTick int         `yaml:"attempts_per_tick"` // default 3 (spread over the tick)
    EwmaAlpha      float64      `yaml:"ewma_alpha"`         // default 0.3 (match ICMP EwmaMs smoothing philosophy)
    ConnectFailureDropPct float64 `yaml:"connect_failure_drop_pct"` // default 0 = metric-only
        // >0: feed decide as effective loss (see §6); e.g. 50 means a fully
        // failing TCP probe set behaves like 50% ICMP loss for ranking.
    MinTargetsUp   int           `yaml:"min_targets_up"`    // default 1: below this, TCP signal considered NO-DATA (target-side outage guard)
}
```

```yaml
tcp_probe:
  enabled: true
  attempts_per_tick: 3
transits:
  - name: main
    probe_tcp: true
    tcp_targets:
      - addr: 198.51.100.10:443
        tls: true
      - addr: 2001:db8::10:443
        tls: true
        timeout: 2s
```

Validation: addrs parse (`net.SplitHostPort`), ports sane, ≥1 target when
`probe_tcp`, `tcp_probe` block requires at least one transit with
`probe_tcp` (else startup error per existing strictness), TLS targets
require TLS defaults (`tls_verify` default true), no duplicate
(host, port) per transit.

## 4. Architecture and data flow

```
internal/tcpprobe/
    probe.go     // Dialer-based prober: connect, optional TLS, timing
    target.go    // target state: EWMA, ring of recent attempts, verdicts
    loop.go      // scheduler: spreads attempts across the tick, per transit
    signal.go    // divergence computation (TCP vs ICMP), EWMA -> LossPct mapping
    metrics.go   // prometheus collectors
    *_test.go
internal/config/config.go  // keys + validation
internal/decide/decide.go  // consumption (§6)
```

Core types:

```go
type Outcome int8
const (
    OutcomeSuccess Outcome = iota // connect (+TLS if set) within Timeout
    OutcomeRefused                // RST / connection refused — path WORKS (see §5)
    OutcomeTimeout                // no SYN-ACK: silent drop — the interesting one
    OutcomeTLSError               // connected, TLS failed (SNI/middlebox interference signal)
    OutcomeNetError               // unreachable/no-route — treat as no-data, log
)

type Attempt struct {
    At      time.Time
    Outcome Outcome
    Ms      float64 // connect (or TLS) completion time; 0 on non-success
}

// Prober is the seam for tests: fake clock + fake dialer.
type Prober struct {
    Dial    func(ctx context.Context, localAddr string, addr string, tlsCfg *tls.Config, timeout time.Duration) (Outcome, float64, error)
    LocalIP func(transitName string, af string) (string, error) // transit's pinned source (from existing probe pinning)
}

func (p *Prober) ProbeOnce(ctx context.Context, t config.TcpTarget, localIP string) Attempt
// Implementation sketch:
//  d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: parsedLocalIP}, Timeout: t.Timeout}
//  start := time.Now()
//  conn, err := d.DialContext(ctx, "tcp", t.Addr)
//  refused / timeout classification from err (errors.Is(syscall.ECONNREFUSED),
//  os.IsTimeout / context deadline), then TLS via tls.Client with
//  tlsCfg{InsecureSkipVerify: !t.TLSVerify, ServerName: host part} and
//  HandshakeContext, whole attempt under one context.WithTimeout.

// Per-target aggregator.
type TargetState struct {
    Target   config.TcpTarget
    EwmaMs   float64
    Window   []Attempt // last N=20 attempts
    SuccessRate float64 // over Window
}

// Signal = per-transit rollup + divergence vs the ICMP view.
type TransitTcpSignal struct {
    Transit      string
    TargetsUp    int       // targets with SuccessRate >= 0.5 in window
    ConnectEwmaMs float64  // EWMA over successful attempts only
    SuccessRate  float64   // pooled across UP targets
    Outcome      Divergence
}

type Divergence int8
const (
    DivNone Divergence = iota    // TCP and ICMP agree (both healthy or both sick)
    DivTcpDownIcmpUp             // THE signature: middlebox/asymmetry on this transit
    DivTcpUpIcmpDown             // rare (ICMP policed) — metric only
    DivNoData                    // < MinTargetsUp: target-side outage, suppress
)

func ComputeSignal(transit string, tcp []TargetState, icmp probes.Summary) TransitTcpSignal
// Divergence rule (hysteresis applied): DivTcpDownIcmpUp requires
// SuccessRate <= 0.2 over the window AND icmp.LossPct < 10 AND TargetsUp >=
// MinTargetsUp at SOME recent tick (i.e. targets were proven working on
// this transit before) — a never-worked target is a config/target problem,
// not a transit problem.
```

Loop wiring (into the existing per-transit probe loop, not a new daemon):

```
per transit with probe_tcp:
  per tick (transit.ProbeInterval):
    for each target, AttemptsPerTick attempts spread evenly across the tick:
      Attempt = Prober.ProbeOnce(...)          // bounded goroutines, ≤ 2 concurrent dials router-wide
    update TargetState (EWMA, window)
  ComputeSignal(tcpStates, icmpSummary[transit])
  → metrics (always)
  → gossip health message gains TcpSignal (so peers see it; quorum as usual)
  → decide input (only if ConnectFailureDropPct > 0, §6)
```

## 5. Outcome semantics — the edge cases that matter

- **`connection refused` (RST) is SUCCESS for path purposes**: the target's
  stack answered, so the transit carried SYN and SYN-ACK both ways and any
  stateful middlebox allowed the flow. The path works; the service's port
  is closed. Classify `OutcomeRefused`, count as up for reachability, don't
  feed latency (RST is faster than a handshake — it would bias EWMA low).
- **TLS failures after successful connect** (`OutcomeTLSError`): the TCP
  path is fine; TLS-level reset mid-handshake on one transit but not others
  is the classic SNI-interference fingerprint. Reported as its own metric;
  not a decide input (transport is healthy); detail string captures the
  TLS error category only (no key material, no full SNI in logs beyond
  configured target host).
- **Local source exhaustion** (ephemeral port range pressure on 1 vCPU
    router): attempts are tiny in number (attempts_per_tick default 3 ×
  targets ≤ ~3 × transits ≤ ~4 → ≤ ~36 conns/tick at 30s ticks — trivial);
  still, dialer reuses one `LocalAddr` per transit, and the loop enforces
  ≤2 concurrent dials.
- **Target-side outage** (CDN target dies): `MinTargetsUp` guard — if ALL
  targets on ALL transits fail, that's a target problem: signal becomes
  DivNoData, decide input suppressed, metric `targets_up` drops, alert
  fires for operators to fix targets. Single-transit failure with other
  transits reaching the same target = genuine transit TCP failure.
- **DNS**: targets are IPs by validation (no hostname resolution in the
  hot path — a resolver outage must not fake a transit outage). TLS SNI
  uses the literal IP (no ServerName) — documented; targets wanting SNI
  use an IP with a cert SAN covering it (doc labs do this) — avoids
  resolver dependency entirely.
- **Happy eyeballs interference**: dial `"tcp"` with an IP literal never
  races; no RFC 8305 fallback, so pinning is deterministic.
- **IPv6**: identical path; `LocalIP(transit, "ipv6")`; targets may mix
  families per transit; family is a label on metrics.
- **Retransmission-counting (SACK etc.)**: out of scope — black-box only.
- **SYN flooding optics**: ≤ ~1 conn/s per transit worst case, from one
  source port cadence; far below anything an upstream edges out.

## 6. Integration with the decision engine

Two-layer design — metrics always, decide opt-in:

1. **Always**: `TransitHealth` gains `Tcp *TransitTcpSignalSummary` (nil =
   feature off). `rank()` unchanged when nil.
2. **Opt-in via `connect_failure_drop_pct: P`**: the probe loop maps TCP
   failure into an *effective* loss contribution fed to the existing
   `LossPct` field — NOT a new ranking dimension. Pooled TCP success rate
   `S` contributes `LossPct_eff = LossPct_icmp × (1 − P/100) + (1 − S) ×
   P/100`... (linear blend, P=100 → TCP failure alone can exclude via the
   existing `loss_drop_pct` threshold and inherits ALL existing machinery:
   hysteresis, dwell, win_cycles, quorum, freeze). This keeps exactly one
   latency/loss ranking semantics and avoids a second EWMA dimension in
   `rank()`; latency from TCP (`ConnectEwmaMs`) is exported but does not
   enter `EwmaMs` (different distribution — handshake RTT ≈ ICMP RTT but
   with middlebox processing; mixing would muddy the margin).

   Dwell for the TCP signal: divergence must persist
   `tcp_divergence_cycles` (internal, = WinCycles) ticks before it bites —
   same streak machinery as latency challengers, reusing `WinStreak`.

3. **DivTcpDownIcmpUp event**: always logged + metric; a suggested alert,
   not an automatic action, when decide coupling is off.

## 7. Prometheus metrics

```
transitd_tcp_probe_success{router,transit,target,family}          gauge (windowed rate)
transitd_tcp_connect_ewma_ms{router,transit,target,family}        gauge
transitd_tcp_probe_outcomes_total{router,transit,target,outcome}  counter (success/refused/timeout/tlserror/neterror)
transitd_tcp_divergence{router,transit}                           gauge 0=none 1=tcp_down_icmp_up 2=tcp_up_icmp_down 3=no_data
transitd_tcp_targets_up{router,transit}                           gauge
transitd_tcp_first_seen_divergence_unixtime{router,transit}       gauge (alert on age > 15m)
```

## 8. Failure modes + mitigations

- **Target rot** (target blocks the router's source after seeing probes):
  outcomes shift timeout → divergence fires. Mitigation: target rotation
  guidance in docs; `targets_up` cross-transit guard suppresses decide
  input when the target is down everywhere; alert distinguishes
  "all-transit target failure" from "single-transit divergence".
- **Middlebox idle-established behavior invisible**: we never hold
  connections open (no keepalive probing) — established-flow asymmetry
  (e.g. conntrack timeout differences) is out of scope; noted because
  operators will ask.
- **Clock/timeout skew under load**: per-attempt timeout from context;
  attempts spread across the tick so a CPU spike can't serialize-fake a
  latency regression; `Ms` measured with monotonic clock.
- **TLS library differences**: pinned Go crypto/tls, no external binary —
  consistent across fleet; `tls_verify: false` targets flagged in metrics
  label `verify=off` for auditability.
- **Decide flapping from TCP signal**: impossible unless explicitly opted
  in; when opted in, blended loss inherits dwell/win_cycles/quorum; plus
  DivNoData suppression (targets-down) prevents target outages from
  demoting a healthy transit.
- **Gossip message growth**: TcpSignal is ~6 fields per transit — bounded,
  appended to the existing health struct; no new message type.

## 9. Test strategy

CI-safe, no routers:

- **Outcome classification unit tests**: fake dialer table — success
  timings, ECONNREFUSED, i/o timeout, context deadline, TLS alert
  categories, net-error → expected Outcome + no-panic on weird errors.
- **Aggregator tests**: EWMA convergence, window eviction, success-rate
  math, pooled rollup, TargetsUp counting.
- **Divergence tests** (the heart): table over (tcpStates, icmpSummary) →
  Divergence: healthy/healthy, tcp-down/icmp-up (fingerprint),
  both-down, tcp-up/icmp-down, never-worked-target suppression
  (DivNoData), MinTargetsUp boundary, hysteresis cycle counts.
- **Decide integration**: blended-loss formula table; nil-TCP transits
  rank identically to today (regression golden); divergence + quorum +
  freeze interplay using the existing decide tests' harness.
- **Config validation tests**: bad addr, port 0, probe_tcp without
  targets, hostname targets rejected, unresolvable → startup error.
- **Loop tests**: attempt spreading bounds, ≤2 concurrent dials enforced,
  tick cadence with fake clock, per-family LocalIP selection.
- **Integration (containers, no real routers)**: in-CI TCP echo servers
  (Go `net.Listen` stubs) + `iptables -j REJECT --reject-with
  tcp-reset` vs `DROP` on per-transit veth paths → assert refused-vs-
  timeout classification live; TLS stub with self-signed cert (doc CN) →
  success/verify-fail paths; full FRR-container scenario asserting
  metrics + (opted-in) decide switch driven purely by blended loss.

## 10. Out of scope

- Packet capture / SYN-SYN-ACK correlation (rejected: too invasive;
  documented as a possible standalone debugging tool, not agent code).
- Long-lived connection health (keepalive, conntrack aging) — v2 idea.
- HTTP semantics (status codes, redirects) — transport handshake only.
- Per-application ports heuristics beyond configured targets.
- QUIC/UDP probes (stateful edges treat them differently; separate design).
- Using TCP RTT as a ranking latency input (kept out of `EwmaMs` by design).
