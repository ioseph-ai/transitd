# Design: `transitctl drill` — automated failover drill

> P1 backlog feature. Self-contained design doc. Public-repo safe: all examples
> use RFC 5737/3849 documentation ranges and RFC 5398 documentation ASNs
> (64496–64511). Runtime-only changes; nothing persisted to FRR config.
> Tracking: #9

## 1. Goal

A CLI subcommand (`transitctl drill run`) that executes a scripted failover
drill against one router's primary transit:

1. **Preflight** — prove the drill is safe to run right now.
2. **Inject** — simulate transit failure in the safest available way.
3. **Measure** — time-to-backup-announcement, time-to-egress-switch, packet
   loss during the transition.
4. **Restore** — undo the injection, guaranteed, even if the drill process or
   the drill host dies.
5. **Verify** — confirm the router returned to the pre-drill state.
6. **Report** — JSON + human table + Prometheus metrics + audit log.

Guarantee: **the network is never left in a broken state**. Cleanup survives
crash of the drill process, crash of the drill host, and loss of the control
path, through layered deadman switches (§6).

## 2. Why the injection is `neighbor shutdown` (decision record)

Four candidate fault-injection mechanisms were evaluated:

| Mechanism | Fidelity | Reversibility | Blast radius | Verdict |
|---|---|---|---|---|
| `neighbor <ip> shutdown` (BGP) | High — session-down is exactly how transits fail hard; routes withdrawn via NOTIFICATION, BGP/BFD/MRAI timers all participate | Runtime-only, `no neighbor … shutdown` restores; idempotent | Only that transit's session; no interface, no other neighbors, no route-maps touched | **Chosen (default)** |
| Route-map deny (import) | Low — simulates "no routes learned", not transit down; withdraw timing not exercised | Reversible but **conflicts with transitd's own LP writes** into the same import maps (`act` package owns route-map rule 10) | Corrupts the act/decide LP machinery | Rejected |
| Interface down (`ip link set down`) | Too high — kills probes, BFD, ARP, possibly the mesh/control path and drill host access | Reversible in principle, but if it's the management path you lose the ability to undo | Whole interface, all sessions on it | Rejected |
| BFD peer shutdown | Medium — fast detection, but only works where BFD is configured; version-dependent vtysh surface | Reversible | Transit + anything sharing the BFD profile | Optional `--inject bfd` (only offered if `show bfd peers json` shows the peer; never default) |

`neighbor shutdown` is a single-neighbor, config-plane, runtime-only,
idempotent mutation whose effect is semantically "this transit is gone".
It exercises the same convergence machinery a real failure would.

## 3. User-facing config surface (YAML keys on `Config`)

New top-level struct in `internal/config`:

```go
type DrillConfig struct {
    Enabled          bool          `yaml:"enabled"`            // opt-in; agent refuses drill control requests when false
    StateDir         string        `yaml:"state_dir"`          // default /var/lib/transitd/drills
    MaxDuration      time.Duration `yaml:"max_duration"`       // hard TTL per drill (default 3m); agent force-restores after
    DeadmanTimeout   time.Duration `yaml:"deadman_timeout"`    // control-path heartbeat loss => auto-restore (default 10s)
    Cooldown         time.Duration `yaml:"cooldown"`           // min time between drills on one router (default 30m)
    AllowedTransits  []string      `yaml:"allowed_transits"`   // empty = all transits with a BGP neighbor
    AllowedNeighbors []string      `yaml:"allowed_neighbors"`  // neighbor IPs that may be drilled (doc example: [198.51.100.1])
    MaxLossProbePps  int           `yaml:"max_loss_probe_pps"` // cap on measurement pings (default 10/s)
}
```

```yaml
drill:
  enabled: true
  max_duration: 3m
  deadman_timeout: 10s
  allowed_transits: [main]
```

CLI surface (new binary `cmd/transitctl`, a client — **not** a daemon):

```
transitctl drill run     --router edge-1 --transit main [--inject bgp|bfd] [--dry-run] [--max-duration 2m] [--json]
transitctl drill restore --router edge-1 [--state-file /var/lib/transitd/drills/<id>.json]  # idempotent
transitctl drill status  --router edge-1
transitctl drill list
```

There is deliberately **no** `--no-restore`. Restoration is unconditional;
only its ordering (immediate vs. after hold) is controlled.

## 4. Architecture

### 4.1 Division of labor: CLI = client, agent = executor

The drill subcommand never mutates FRR itself. It sends the plan to the
**transitd agent on the target router** (over the existing gossip mesh /
local unix socket control endpoint — the mesh rides wireguard/IXP/LAN, never
the transit under test). The agent owns:

- execution of vtysh batches,
- the on-disk drill state file,
- the TTL deadman,
- the heartbeat deadman,
- decide-engine maintenance freeze during the drill.

This is what makes cleanup survive drill-host death: the thing that can undo
the injection lives on the box that was mutated.

New/changed files:

```
cmd/transitctl/main.go              # CLI: drill run/restore/status/list
internal/drill/types.go             # Plan, Step, Snapshot, Report
internal/drill/plan.go              # preflight checks + plan builder
internal/drill/run.go               # phase executor (defer-restore)
internal/drill/state.go             # state file: write/fsync/read/replay
internal/drill/measure.go           # bestpath poller, announcement watcher, loss pinger
internal/drill/report.go            # JSON/human output, metrics emission
internal/drill/drill_test.go
internal/config/config.go           # + DrillConfig, validation
internal/decide/decide.go           # + State.Maintenance (see §7)
```

### 4.2 Core types and signatures

```go
// Phase names: preflight, baseline, inject, measure, hold, restore, verify, report.
type Step struct {
    Name       string   // "shutdown-neighbor-main"
    Apply      []string // vtysh batch, e.g. {"configure terminal","router bgp 64496","neighbor 198.51.100.1 shutdown"}
    Rollback   []string // {"configure terminal","router bgp 64496","no neighbor 198.51.100.1 shutdown"}
    Idempotent bool     // Apply/Rollback are safe to re-run
}

// Snapshot captures everything the drill mutates or depends on, so verify
// can diff and restore can reconstruct.
type Snapshot struct {
    TakenAt        time.Time
    NeighborJSON   string          // `show bgp neighbors 198.51.100.1 json`
    NeighborConfig string          // running-config section for the neighbor
    BestPaths      map[string]string // prefix -> nexthop before drill
    AssignedLP     map[string]int
}

type Plan struct {
    ID          string        // ulid
    Router      string
    Transit     string
    NeighborIP  string        // doc example: 198.51.100.1
    Inject      Step
    WatchPrefix string        // our announced prefix, doc example: 192.0.2.0/24
    BackupTransit string
    MaxDuration time.Duration
    Baseline    Snapshot
}

type Report struct {
    PlanID                            string
    StartedAt, InjectedAt, RestoredAt time.Time
    BackupAnnouncedAt                 time.Time // zero = never observed
    EgressSwitchedAt                  time.Time // bestpath moved primary->backup
    PrimaryReestablishedAt            time.Time
    RecoveredAt                       time.Time  // bestpath back on primary
    TBackupAnnounce, TEgressSwitch    time.Duration
    TRecover                          time.Duration
    SentPackets, LostPackets          int
    ForcedRestore                     bool       // TTL/heartbeat deadman fired
    VerifyDiff                        []string   // empty = clean
}

// AgentControl abstracts everything the runner touches — the mock seam for CI.
type AgentControl interface {
    Vtysh(ctx context.Context, cmds ...string) (string, error)
    BestPath(ctx context.Context, prefix string) (nexthop string, err error) // polls `show bgp ipv4 unicast <p> bestpath json`
    AnnouncementSeen(ctx context.Context, prefix, viaUpstreamASN uint32) (bool, error)
        // true when any gossip peer (other routers) reports the prefix in its
        // Adj-RIB-In via the backup transit's AS — internal-only measurement.
    Heartbeat(ctx context.Context) error
    LossProbe(ctx context.Context, target string, pps int, until time.Time) (sent, recv int, err error) // system ping loop
    SetMaintenance(ctx context.Context, reason string, until time.Time) error // decide-engine freeze
    ClearMaintenance(ctx context.Context) error
}

type Runner struct {
    Ctl      AgentControl
    Cfg      *config.DrillConfig
    StateDir string
    Log      *slog.Logger
}

func (r *Runner) Preflight(ctx context.Context, transit string) (Plan, error)
func (r *Runner) Execute(ctx context.Context, p Plan) (Report, error)
    // Execute: writes state file (fsync) BEFORE Apply; defer r.Restore(...) so
    // every return path — panic, error, ctx cancel — runs restore.
func (r *Runner) Restore(ctx context.Context, planID string) error
    // Idempotent: reads state file, checks current neighbor state first,
    // applies Rollback only if needed, fsyncs "restored: true" into the file.
func (r *Runner) Verify(ctx context.Context, p Plan) (diff []string, err error)
```

### 4.3 Agent-side watchdogs (the actual safety net)

Inside the transitd agent (`internal/drill` linked into the daemon):

```go
func (a *Agent) StartDrillWatchdog(ctx context.Context) {
    // 1. Startup scan: any state file without "restored": true => force
    //    Restore() immediately (covers agent crash + restart).
    // 2. TTL goroutine: drill running longer than MaxDuration => force Restore.
    // 3. Heartbeat deadman: drill client misses DeadmanTimeout of beats =>
    //    force Restore.
    // 4. Forced restores increment transitd_drill_forced_restores_total and
    //    flip the router's healthz to "degraded" until an operator acks.
}
```

## 5. Data flow (happy path)

```
transitctl drill run --router edge-1 --transit main
  └─(gossip/control)→ agent.Preflight
       checks: drill.enabled; no active drill (lockfile); transit in
       allowed_transits; neighbor in allowed_neighbors; backup session
       Established; primary is current decide primary; control path
       (mesh) egress interface != injected transit's interface;
       decide not Frozen/settle; MaxDuration sane; vtysh reachable.
  ← Plan (incl. baseline Snapshot)
  state file <id>.json written + fsync'd        ← BEFORE any mutation
  agent: SetMaintenance("drill <id>", InjectedAt+MaxDuration)
       → decide engine skips actions this window (§7)
  agent: LossProbe starts (capped pps, via a target on the announced prefix)
  agent: Apply ["neighbor 198.51.100.1 shutdown"]         t=injected
  measure.go pollers (all timestamps taken ROUTER-SIDE, agent clock):
    - bestpath poller: 200ms `show bgp … bestpath json` → nexthop moves
      198.51.100.1 → 203.0.113.1                → EgressSwitchedAt
    - announcement watcher: gossip peers' Adj-RIB-In gains prefix via
      backup upstream ASN 64501                  → BackupAnnouncedAt
  hold (default 30s): assert steady state on backup; abort+restore if
      backup flaps
  Restore (idempotent)                                   t=restore
    - ClearMaintenance
    - poll session re-Established → PrimaryReestablishedAt
    - bestpath back on primary     → RecoveredAt
  Verify: diff current neighbor section + LPs vs Snapshot
  Report → stdout JSON + `transitd_drill_*` metrics + audit log line
```

### Measuring "backup announced" without external dependencies

The only fully internal, dependency-free signal is **cross-router gossip**:
each router's bgpwatch already polls its own RIB; during a drill it adds
`show bgp <prefix>` for the watched prefix and gossips the result. The
prefix appearing in a peer's Adj-RIB-In **via the backup transit's AS**
(64501 in doc examples) proves the backup path is advertised end-to-end.
Fallbacks, in order: (a) local Adj-RIB-Out on the backup-announcing router
(proves sent, not seen); (b) if only one router exists, report
`BackupAnnouncedAt = n/a (single-router)` and rely on egress-switch timing.
External looking glasses are explicitly **not** used (that's Feature 3's
job, and drills must work offline).

## 6. Safety model — "never leave it broken", layered

| Failure | Safety layer |
|---|---|
| Drill process errors/panics | `defer Restore` in `Execute` |
| Drill host (laptop) dies | Router-side TTL deadman (MaxDuration) + heartbeat deadman |
| Agent process killed post-inject | On-disk state file + agent startup scan force-restore |
| Agent restarted but state file unreadable/corrupt | `transitctl drill restore --router --neighbor` manual path; agent logs the neighbor from the filename (state filename embeds `router_transit_neighbor`) |
| vtysh socket dies mid-drill | Restore retries with backoff up to MaxDuration, then healthz=degraded + alert; FRR restart clears running-config shutdown anyway (runtime-only principle) |
| Drill breaks connectivity to drill host | Control path is the mesh, and preflight asserts mesh egress ≠ injected transit; heartbeat deadman restores if the assertion was wrong |
| Backup transit dies mid-drill | hold-phase watchdog aborts and restores immediately (no point measuring) |
| Operator runs two drills | Lockfile + agent refuses (single active drill per router, cooldown between) |
| Config management re-applies mid-drill | Re-apply removes the shutdown (same as any runtime change); verify phase reports the diff, restore is a no-op |

State file lifecycle: `pending → injected → restoring → restored:true`.
`Execute` refuses to start if any non-`restored:true` file exists for the
router; `drill status` surfaces stale ones; startup scan auto-heals them.

## 7. Interaction with the decide engine

A drill deliberately breaks the primary transit — the decide engine would
otherwise react (switch, then switch back, burning dwell/rate-limit budget
and polluting the measurement). Therefore `decide.State` gains:

```go
type Maintenance struct {
    Reason string
    Until  time.Time // auto-expires; never persists across restarts
}
// State.Maintenance *Maintenance
```

While `Maintenance != nil`, `Evaluate` returns the incumbent decision with
`Reason: "maintenance: <reason>"` — no switches, no LP writes. It is
time-bounded (capped at MaxDuration + grace) and cleared on Restore, so a
crash can at worst freeze decisions for a bounded window. This is distinct
from `State.Frozen` (rate-limit) so a drill never trips the switch budget.

## 8. Edge cases

- Crash window between `Apply` and state-file durability: state file is
  written and fsync'd **before** the first mutating vtysh batch; worst case
  is a restore with no injection (idempotent no-op).
- Clock skew between laptop and router: all timings come from the router's
  clock via the agent; the CLI only relays them.
- High loss during transition makes the loss-probe itself flaky: pings are
  sent throughout, gaps counted — a lost probe *is* the measurement; pps is
  capped (`max_loss_probe_pps`) to protect the 1 vCPU envelope.
- Neighbor is a peer-group member: shutdown must reference the neighbor IP
  (or the specific peer if `neighbor <name>` form); preflight captures the
  exact running-config line so Rollback is textual-inverse-correct.
- Graceful-BGP / RFC 8323 long-lived sessions: `shutdown` still withdraws;
  restore brings it back — but note in report if `graceful-restart` delayed
  withdrawal visibility (timings then measure GR, which is the honest result).
- MRAI/withdraw damping on the upstream may delay visibility; measurement
  records what happened, does not judge — the report exposes raw timings.
- `--inject bfd` on a session without BFD: preflight rejects.
- IPv6 sessions: neighbor key is the v6 address; all phases identical.
- Router with a single transit: preflight rejects (no backup to measure).

## 9. Failure modes and mitigations (summary)

- **Injection succeeds, measurement hangs** → TTL deadman restores; report
  marked `ForcedRestore: true`, exit code 2.
- **Restore vtysh batch fails transiently** → retry with backoff until
  MaxDuration, then degraded healthz + `transitd_drill_forced_restores_total`.
- **Session doesn't re-establish after restore** → drill never retries
  injection; report warns; BGP connect timers own it; metrics expose
  `t_reestablish` as absent.
- **Announcement watcher gets no gossip peers** (single router) → report
  degrades gracefully (§5).
- **Report lost** (CLI died) → report also written by the agent to
  `StateDir/<id>-report.json` and emitted as metrics.

## 10. Test strategy

CI-safe (no real routers):

- **Unit (table-driven, golden batches)**: plan builder emits expected vtysh
  apply/rollback batches (golden files); state-file write→fsync→apply
  ordering enforced by a recording fake; Restore idempotency (double-call =
  single rollback); report math from synthetic timestamp sets; verify-diff
  logic against mutated snapshots.
- **AgentControl mock**: full Execute happy path, abort paths (ctx cancel,
  panic in measure, backup flap) — assert restore ran in every case, assert
  Maintenance set/cleared around injection.
- **Integration (docker compose: 3 FRR containers + exabgp "transits" +
  drill container)**: real BGP convergence measured against real FRR —
  `neighbor shutdown` on container A, assert container B/C observe the
  backup announcement (real Adj-RIB-In), assert bestpath switch, assert
  timings > 0 and sane; `kill -9` the CLI mid-drill → assert agent TTL
  restored the neighbor; drop heartbeats (iptables on control link) →
  assert heartbeat deadman restored; restart agent post-inject → assert
  startup-scan restore; two concurrent drills → second refused.
- **Decide-engine tests**: Maintenance freeze suppresses switching;
  auto-expiry after `Until`.

## 11. Out of scope

- Traffic-engineering drills (LP manipulation, prefix withdrawal variants).
- Multi-router coordinated drills (inject on A, measure on B/C) — future
  `--mesh-wide`.
- Scheduled/recurring drills (cron exists; the agent will not self-schedule).
- Packet-level loss measurement (Scapy/pcap) — ping counts only.
- External vantage-point verification during the drill (Feature 3 covers
  steady-state global visibility; a drill must run offline).
