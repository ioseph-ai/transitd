# transitd

Distributed transit manager for small autonomous systems. A per-router
agent (FRR/VyOS and plain Linux+FRR) that observes BGP/BFD/probe health
across your transits, gossips that state between routers, and adjusts
egress preference (route-map local-preference) and announcements at
runtime — with hysteresis, quorum and full audit.

## Why

Small ASes typically have 2–4 upstream transits and a BGP setup that can
fail over *hard* (session down) but cannot react to *soft* problems:
latency regression, packet loss on one path, an upstream whose stateful
edge drops asymmetrically-routed flows. transitd closes that gap without
turning your routers into a Kubernetes cluster:

- **No new infrastructure** — agents talk peer-to-peer over your existing
  mesh (wireguard, IXP direct, or routed LAN).
- **Runtime-only changes** — the agent drives `vtysh` on the host; it
  never writes persisted config. Your config management (Ansible, etc.)
  stays the source of truth; any re-apply cleanly reverts agent tweaks,
  and the agent re-applies its decision only if still warranted.
- **Safe by construction** — decisions require quorum, changes are
  rate-limited, every action is logged and exported as metrics.

## Features (roadmap)

- [x] P1 (partial): observation — per-transit probes (latency/loss) with
      startup pin verification, Prometheus metrics, healthz endpoint with
      [feature capability surfacing](docs/health.md), the gossip mesh between
      agents (memberlist, issue #3), the observe-only agent loop
      (`cmd/transitd`), and bounded read-only BGP state (bgpwatch: session/
      prefix views feeding `SessionUp`). Mutation batches (act: neighbor
      shutdown, tcp-mss clamp) exist and are idempotent, but are deliberately
      NOT wired to decide yet — observe-only until the wiring is
      review-carded. Remaining P1 core: manual `transitctl set-primary <name>`
      (issue #2), act wiring (issue #4).
- [ ] P2: automatic latency/loss-aware transit preference with
      hysteresis + minimum dwell.
- [ ] P3: traffic engineering — per-prefix-class preferences, scheduled
      shifts, capacity-aware shedding.

## Design principles

1. **Crash-safe**: a dead agent is passive. Hard failures remain the job
   of BFD/BGP timers and your router's own failover design.
2. **Repo-friendly**: all runtime mutations are reversible and visible;
   `vtysh show run` diff is logged on every change.
3. **Boring tech**: single static Go binary, YAML config, MPL-2.0 deps.

## Install

Not yet — pre-release. See [docs/design.md](docs/design.md).

## License

MIT (see LICENSE).
