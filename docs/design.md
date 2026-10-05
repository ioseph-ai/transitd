# transitd internal design

> Public-repo document. Contains **no** site-specific values — no IPs, ASNs,
> hostnames, or topology of any deployment. Configuration is entirely via
> the agent's YAML file at runtime.

## Components

```
┌─────────────────────────── router (VyOS or Linux+FRR) ───────────────────────────┐
│  ┌─────────────── transitd ────────────────┐                                      │
│  │ probes   → latency/loss per transit     │      /run/frr (bind-mounted rw)      │
│  │ bgpwatch → vtysh -c 'show ... json'     │────► vtysh unix sockets (bgpd.vty…)  │
│  │ decide   → state machine + hysteresis   │                                      │
│  │ act      → vtysh -c configure … (runtime│      wg/IXP mesh                    │
│  │            only: route-map LP, soft clr)│◄────► gossip UDP+TCP 7946 (memberlist)
│  │ metrics  → :9414/metrics (Prometheus)   │                                      │
│  └─────────────────────────────────────────┘                                      │
└───────────────────────────────────────────────────────────────────────────────────┘
```

## Data flow

1. **bgpwatch** polls `show bgp summary json`, `show bfd peers json`
   (bounded, 1 Hz max) — session state, flap counters.
2. **probes** measure per-transit latency/loss to a configurable set of
   anycast targets, pinned to each transit's next-hop interface.
3. **gossip** (memberlist, DefaultLANConfig over the operator mesh) merges
   per-router views: every agent knows every other agent's transit health.
4. **decide** runs a deterministic total order over the merged view:
   candidate ranking = (hard-down excluded) → (loss threshold) → (EWMA
   latency) → (config tiebreak). Promotion requires:
   - candidate wins by `margin_ms` over incumbent for `win_cycles` cycles,
   - at least `dwell` since the last switch, and
   - at most `max_switches_hour` switches (else alert + freeze).
5. **act** applies the decision with `vtysh` batch commands:
   `route-map <X-LOCAL-IN> rule 10 set local-preference <LP>` for each
   transit's import map + `clear bgp * soft`. LP values are assigned from
   the ranking position (configurable base/step). **Never** `write file`,
   never touches persisted config.
6. **audit** every decision/action → structured log + Prometheus counter +
   `transitd_decisions_total{from,to,reason}`.

## Safety model

- **Quorum**: gossip state carries epoch; actions require `ceil(n/2)+1`
  agents alive. Split-brain → all agents freeze (BGP/BFD still handles
  hard failure natively).
- **Watchdog**: agent exposes `:9414/healthz`; supervisor restarts on
  hang; restart always begins in observe-only mode for `settle` seconds.
- **Drift repair**: if runtime LP differs from the agent's decision for
  more than `drift_repair` seconds (e.g. an operator re-applied config
  management), the agent re-applies its decision — but only if the
  decision inputs are unchanged; otherwise it re-decides first.
- **Config validation**: unknown keys, unreachable probe targets, and
  route-maps that don't exist on the host are startup errors.

## Threat model (brief)

The agent runs as root-equivalent on the router (needs vtysh socket
access). Gossip is encrypted with a shared key (memberlist SecretKey);
the mesh itself is assumed trusted (wireguard). vtysh access is not a
privilege boundary — anyone with the gossip key can cause preference
changes; treat the key like an SSH key.

## Non-goals

- Replacing config management (repo stays source of truth).
- Automatic RPKI/prefix-list editing.
- Anything below BGP-level (interface flap detection is BFD's job).

## CI policy

- Unit tests for decide/act/metrics (table-driven, golden vtysh batches).
- Integration tests against FRR containers (docker compose: 3 frr
  containers + vtysh socket wiring) exercising: election, hysteresis,
  quorum freeze, drift repair, soft-clear batching.
- golangci-lint, gofumpt, govulncheck on every PR; release builds via
  goreleaser (linux/amd64 + arm64, static, distroless).
