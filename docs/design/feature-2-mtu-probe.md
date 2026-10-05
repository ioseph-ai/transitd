# Design: per-transit MTU probe (PMTU discovery + blackhole detection)

> P1 backlog feature. Self-contained design doc. Public-repo safe: examples
> use RFC 5737/3849 ranges (198.51.100.0/24, 2001:db8::/48). Runtime-only;
> no new daemons; no raw sockets required.
> Tracking: #7

## 1. Goal

Answer, per transit, two questions the existing latency/loss probes cannot:

1. **What is the largest MTU that actually traverses this transit end-to-end
   with DF set?** (usable PMTU)
2. **Is this transit a PMTU blackhole** — i.e. does it silently discard
   large DF packets AND fail to return ICMP "Fragmentation Needed" /
   "Packet Too Big", so end-host PMTUD breaks?

Results feed: Prometheus metrics, the decision engine (exclude a blackholed
transit; cap effective MSS otherwise), and alerts. MTU is a stable property,
so the probe runs on a **slow cadence** (default 6h) with an on-change
trigger option — never in the hot probe loop.

## 2. Key design decisions

### 2.1 System `ping` binary, not raw sockets

Precedent: the existing probes already exec the system ping (ICMP needs
CAP_NET_RAW, which the container has anyway). PMTU discovery requires DF-set
probes of controlled size; `ping(8)` (iputils) exposes exactly this:

- IPv4: `ping -4 -I <src> -M do -s <payload> -c 1 -W 2 <target>`
  (`-M do` = DF set, don't fragment)
- IPv6: `ping -6 -I <src> -s <payload> -c 1 -W 2 <target>` (DF semantics are
  mandatory in v6; PMTUD errors are ICMPv6 Packet Too Big)

Trade-offs vs raw sockets (`IPPROTO_ICMP`/`IPPROTO_ICMPV6` datagram sockets):
raw/ICMP datagram sockets would let us correlate errors precisely, but need
root or CAP_NET_RAW *for our binary*, complicate cross-distro behavior, and
buy little — exit status + parsed stderr of ping distinguishes the three
outcomes we need (§2.3). Decision: **exec system ping**, parse output. No
new capabilities, no new privileges, keeps the "boring tech" principle.

`-I <src>` pins the source address to the transit's interface address, so
ECMP/route selection follows the per-transit policy routing the same way the
existing latency probes pin next-hops (Paris-traceroute constant-flow
principle applies to any future multi-path refinement — keep the 5-tuple
stable across the binary search by also fixing payload pattern and target).

### 2.2 Binary search, then verify

Naïve linear scan of MTU space is wasteful; classic binary search over
`[min_mtu, max_mtu]` converges in ~ceil(log2(range/1)) ≈ 11 probes from
1500→576. But ping sizes step in 8-byte increments (ICMP payload must be
word-aligned for some stacks), so we search over the aligned grid.

```go
// ProbeResult is one transit, one address family.
type ProbeResult struct {
    Transit   string
    Af        string        // "ipv4" | "ipv6"
    UsableMtu int           // largest DF probe that got a reply (0 = see Verdict)
    Verdict   Verdict       // OK | Blackhole | Filtered | Unknown
    ProbeErrM int           // largest size for which an ICMP frag-needed/too-big WAS seen
    StartedAt time.Time
    Duration  time.Duration
    Probes    int           // total pings sent (budget accounting)
}

type Verdict int8
const (
    VerdictOK Verdict = iota        // usable MTU found, ICMP errors flow
    VerdictBlackhole                // small passes, large DF dies silently (no ICMP error seen)
    VerdictFiltered                 // even small probes die — probe path broken, NOT an MTU verdict
    VerdictUnknown                  // inconclusive (mixed/timeout mid-search)
)

// MtuProber does one full discovery pass for one transit+AF.
type MtuProber struct {
    Src     string   // transit's pinned source IP (v4 or v6, matching Af)
    Target  string   // per-transit probe target (same target list as latency probes)
    Ping    PingRunner  // seam: func(ctx, args...) (exit int, stdout, stderr string, err error)
    Clock   func() time.Time
    Budget  int      // max probes per pass (default 16; binary search needs ≤ ~12)
}

func (m *MtuProber) Discover(ctx context.Context) ProbeResult
// Algorithm:
//  0. sanity probe at min_mtu (default 552B v4 total / 1280 v6 total):
//     no reply → VerdictFiltered (do NOT call this a blackhole).
//  1. probe at max_mtu (interface MTU, capped 1500 default):
//     reply → UsableMtu = max, VerdictOK (fast path, no search).
//  2. binary search on 8-byte-aligned sizes in (min, max]:
//     reply → lo = size; timeout AND "Frag needed"/"Message too big" in
//     stderr → hi = size - 8 (error seen = PMTUD signalling WORKS);
//     timeout with NO ICMP error → suspicion counter++, treat as hi = size - 8
//     but remember silent-loss count.
//  3. verdict: if silent large-packet losses occurred while small packets
//     passed, and zero ICMP frag-needed errors were seen all pass →
//     VerdictBlackhole with UsableMtu = lo (the last good size).
//     If any frag-needed was seen → VerdictOK (signalling works; hosts
//     doing PMTUD will adapt — not a transitd emergency).

func (m *MtuProber) probeOnce(ctx context.Context, totalSize int) (probeOutcome, error)
// probeOutcome: reply | fragNeeded | silentDrop | error
// Parses: exit 0 → reply; exit 1 + stderr matching /frag(mentation)? needed|too big|message too long/i
// → fragNeeded; exit 1 + "100% packet loss"/timeout → silentDrop.
```

### 2.3 Blackhole vs filtered — the verdict table

| small (min_mtu) | large (max_mtu) | ICMP frag-needed seen? | Verdict |
|---|---|---|---|
| pass | pass | — | **OK**, usable = max |
| pass | fail | yes | **OK** (signalling works; usable = search result) |
| pass | fail | no, repeatedly | **Blackhole** (usable = last good) |
| fail | — | — | **Filtered** — probe target/path broken; suppress decision impact, alert separately |
| mixed | mixed | — | **Unknown** — retry pass next cycle; N consecutive Unknown → alert only |

The crucial safety property: a transit whose *probe target* became
unreachable is never classified as a PMTU blackhole, because step 0 fails
first. Blackhole requires positive evidence (small passes) plus negative
evidence (no signalling) — it is a conjunction, not an absence.

### 2.4 TTL/expiry handling

Oversized DF packets must die *in the transit's path*, not at our own host.
Two guards:

- The kernel will return `EMSGSIZE` on `sendto` for sizes above the
  *interface* MTU — ping reports this distinctly ("message too long"). We
  cap `max_mtu` at the interface MTU read at probe time (via
  `ip -j link show` or syscall) so this is an assertion, not a branch.
- v4 probes carry default TTL; any ICMP `TTL exceeded` in stderr is treated
  as `error` (path weirdness), not `silentDrop` — a frag-needed generator
  at TTL boundary would misreport otherwise.
- `-W 2` (2s timeout) bounds each probe; whole pass has a context deadline
  (default 60s). No hang risk on the slow cadence loop.

### 2.5 Cadence and triggers

MTU is stable. Default `probe_interval: 6h` with jitter (±10%) so routers
don't stampede. Optional triggers re-arming an early pass:

- BGP session to the transit re-established (path may have changed),
- `pmtu_change_only: true` semantics: if the pass result differs from the
  cached one by > tolerance (default 8B), emit event + refresh decision
  input immediately; identical result → metrics refresh only, no decide
  nudge.

## 3. User-facing config surface

Per-transit keys (opt-in per transit) + one global block:

```go
// added to Transit (internal/config)
type Transit struct {
    // ... existing ...
    ProbeMtu      bool `yaml:"probe_mtu"`       // opt-in per transit
    MtuMin        int  `yaml:"mtu_min"`         // default: 552 (v4 total) / 1280 (v6 total)
    MtuMax        int  `yaml:"mtu_max"`         // default: min(interface MTU at runtime, 1500); 0 = auto
}

// new top-level block
type MtuConfig struct {
    Enabled        bool          `yaml:"enabled"`          // master opt-in (per-transit flag also required)
    Interval       time.Duration `yaml:"interval"`         // default 6h, min 1h enforced
    Jitter         float64       `yaml:"jitter"`           // default 0.10
    PassTimeout    time.Duration `yaml:"pass_timeout"`     // default 60s
    BlackholeDropPct float64     `yaml:"blackhole_action_exclude"` // true/false semantics via action key:
    ExcludeOnBlackhole bool      `yaml:"exclude_on_blackhole"` // default false: metric+alert only
    CapMssOnReducedMtu bool      `yaml:"cap_mss_on_reduced_mtu"` // default false
}
```

```yaml
mtu:
  enabled: true
  interval: 6h
  exclude_on_blackhole: false
transits:
  - name: main
    probe_mtu: true
    mtu_max: 1500
```

Validation: `mtu_min < mtu_max`, both within [576, 9000] v4 / [1280, 9000]
v6; `exclude_on_blackhole` requires quorum note (a single blackhole verdict
on one router excludes the transit *for that router's ranking only* —
gossip-merged like other health, so multi-router agreement gates any
announcement-level action).

## 4. Architecture and data flow

New files:

```
internal/mtu/probe.go        // MtuProber, binary search, verdict table
internal/mtu/ping.go         // PingRunner: exec system ping, output parsing
internal/mtu/ping_test.go    // golden stdout/stderr fixtures → probeOutcome
internal/mtu/probe_test.go   // algorithm table tests (fake PingRunner)
internal/mtu/scheduler.go    // slow-cadence loop, jitter, triggers
internal/mtu/metrics.go      // prometheus collectors
internal/config/config.go    // keys + validation
internal/decide/decide.go    // consume MtuState (see below)
```

Loop integration — deliberately **outside** the hot probe loop:

```
scheduler (per router):
  every Interval±jitter, or on session-up trigger:
    for each transit with probe_mtu (per AF):
      MtuProber.Discover(ctx)          ← bounded by PassTimeout
      cache result (in-memory + last-write-wins map)
      emit metrics
      if result changed vs cached:
        push MtuState into the gossip health message
        decide engine sees it on the next Evaluate cycle
```

`decide.TransitHealth` gains optional MTU fields (nil = feature off for
that transit → ranking unaffected, strictly opt-in):

```go
type TransitHealth struct {
    // ... existing ...
    MtuUsable    *int   // nil = unknown/feature off
    MtuBlackhole bool   // only meaningful when MtuUsable != nil
}

// rank() additions (pseudocode-level):
//   if h.MtuBlackhole && cfg.Mtu.ExcludeOnBlackhole → excluded (like hard-down)
//   MSS capping: if h.MtuUsable != nil && *h.MtuUsable < ifaceMtu && cfg.Mtu.CapMss:
//     act phase ensures a route-map rule setting ip/tcp mtu-adjust or clamps
//     tcp-mss-adjust on the transit's interface — DEFAULT OFF, documented
//     as a runtime-only write the same as LP (never persisted).
```

Decision-engine coupling is conservative: MTU data never *initiates* a
switch by itself (it's not latency); it only (a) excludes on blackhole when
explicitly enabled, (b) annotates. This avoids a slow signal causing
flapping.

## 5. Prometheus metrics

```
transitd_pmtu_usable_bytes{router,transit,af}      gauge   (0 when blackhole-with-last-good unknown)
transitd_pmtu_verdict{router,transit,af}           gauge   0=ok 1=blackhole 2=filtered 3=unknown
transitd_pmtu_frag_needed_seen{router,transit,af}  counter (ICMP signalling observed)
transitd_pmtu_probes_total{router,transit,af}      counter
transitd_pmtu_last_success_unixtime{router,transit}  gauge  (alert: now() - > 2*interval)
```

Alerting thresholds (documented, not hard-coded): page on
`verdict==blackhole` for 2 consecutive passes; warn on `usable < 1500` when
previous was ≥1500 (regression); page on `verdict==filtered` persisting >
1h (probe target problem, not MTU).

## 6. Edge cases

- **ECMP hashing splits the binary search across paths**: pin src (interface
  address) and target so the flow 5-tuple is constant across all probes of
  a pass (constant-flow principle); document that per-path MTU divergence
  inside one transit is fundamentally unobservable from one router — the
  usable MTU reflects the probed path; a second target narrows this.
- **Target behind tunnel**: usable MTU measures transit+target path, not
  transit alone. Config guidance: prefer targets known to be near the
  upstream (same doc range as existing probe targets). Not solvable
  generically; documented limitation.
- **v6 min MTU floor**: IPv6 never fragments senders; `mtu_min` for v6
  clamped to ≥1280 by validation regardless of config.
- **Jumbo interfaces**: `mtu_max` up to 9000 allowed; runtime cap at actual
  interface MTU still applies (EMSGSIZE guard).
- **Rate-limited ICMP on return path**: frag-needed may be dropped by our
  own edge policer → misread as blackhole. Mitigation: blackhole requires
  `min_consecutive_silent` (default 3) large-size silent losses across the
  pass, and pass-level verdict must hold on 2 consecutive passes before any
  decision-engine exclusion (dwell for MTU).
- **Router under load / pps budget**: budget cap (default 16 probes/pass,
  1 concurrent pass router-wide, nice-level via `ionice`-style exec
  niceness where available); cadence is hours, so worst case ~16 pings/6h.
- **Dual-stack divergence**: run and report v4 and v6 independently; never
  infer one from the other.
- **Clock/interval drift after agent restart**: scheduler is stateless;
  first pass runs `Interval/2` after start (staggered), then cached-value
  comparison keeps decisions stable across restarts (cache seeded from
  gossip peers before first local pass).

## 7. Failure modes + mitigations

- **ping binary missing/incompatible** (BusyBox ping lacks `-M do`):
  capability probe at startup (`ping -V` + one dry parse); on failure,
  feature self-disables with `transitd_pmtu_probe_broken` metric + warn
  log; decide engine never sees MTU state (nil).
- **Parsing surprises across iputils versions**: parser is
  fixture-tested (§8); unknown output shape → `error` outcome → VerdictUnknown,
  never a false blackhole.
- **Probe pass hangs** (ping wedged): context deadline kills the process
  group (Setpgid + Kill), pass → Unknown.
- **Stale blackhole excludes a repaired transit**: exclusion requires 2
  consecutive blackhole passes; un-exclusion on first OK pass; gossip merge
  lets other routers' OK verdicts surface divergence.
- **Config management conflict on tcp-mss clamping** (when cap enabled):
  identical drift-repair semantics as LP writes (re-apply wins until inputs
  change; runtime-only).
- **Metric cardinality**: fixed label sets (router, transit, af ∈ {ipv4,
  ipv6}) — bounded by transit count × 2.

## 8. Test strategy

CI-safe, no routers:

- **Parser unit tests**: golden stdout/stderr fixtures for iputils-ping
  variants (exit 0 reply; exit 1 "Destination Port Unreachable" red herring;
  "Frag needed and DF set"; "Message too long"; "Message too big" v6;
  BusyBox shapes; TTL exceeded) → expected `probeOutcome`.
- **Algorithm tests** (fake PingRunner): table of reply-patterns → expected
  (UsableMtu, Verdict): clean 1500; 1492 boundary; classic 1480 blackhole
  (silent at >1480, no frag-needed); filtered (step-0 fail); flaky mid-search
  → Unknown; budget exhaustion → Unknown.
- **Alignment tests**: search only emits 8-byte-aligned sizes; lo/hi
  invariants never cross.
- **Scheduler tests**: jitter bounds; trigger on session-up event; no
  concurrent passes; Unknown-retry counting.
- **Decide integration**: blackhole transit excluded only when
  `exclude_on_blackhole` && 2 consecutive passes && quorum; MSS-cap path
  emits correct vtysh batch (golden file); nil-MTU transits rank identically
  to today (regression guard).
- **Integration (FRR containers)**: veth pairs with explicit MTUs (1400,
  1500) + `iptables --police`/nft to drop ICMP frag-needed → assert real
  blackhole verdict; without drop → OK verdict with 1400 usable; assert
  metrics exported; assert decide exclusion only after configured dwell.

## 9. Out of scope

- Full PMTUD session plumbing (TCP MSS clamping is config-opt-in and
  interface-level only; no per-peer MSS tracking).
- PLPMTUD (RFC 8899) for transitd's own control traffic.
- Path MTU *history* per next-hop (single cached verdict per transit+AF).
- Jumbo/9000 probing by default (config allows, but no auto-detection of
  upstream support beyond the binary search itself).
- IPv6 extension-header interplay analysis beyond standard PMTUD signalling.
