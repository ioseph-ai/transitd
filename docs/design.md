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
   (bounded, 1 Hz max) — session state, flap counters. Session state feeds
   each transit's `SessionUp` in the decide input; a transit that names a
   `bgp_neighbor` is hard-down to the ranking while that session is not
   Established.
   - **Prefix-level views (issue #4).** Beyond the session summary, bgpwatch
     parses the prefix-level Adj-RIB-In (`show bgp ipv4 unicast json` /
     `show bgp ipv6 unicast json`) and a single-prefix bestpath query
     (`show bgp <af> <prefix> json`). The prefix views are **bounded**: a
     parse is capped at `bgpwatch.max_prefixes` (default 1000), and a table
     over the cap is a hard error, never a silent truncation. A truncated RIB
     would make "does peer X see prefix P" answer a confident no about a
     prefix bgpwatch simply did not read; the bound turns that into an error
     the operator can act on.
   - All bgpwatch access is read-only: it issues `show` commands only, and
     the package holds no configure path. An operator never has to wonder
     whether the observer changed the router.
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
5. **act** applies runtime-only mutations as paired vtysh batches:
   `route-map <X-LOCAL-IN> rule 10 set local-preference <LP>` for each
   transit's import map + `clear bgp * soft`, and the shared-infra batches —
   `neighbor <ip> shutdown` (the drill's injection, issue #4) and
   `neighbor <ip> tcp-mss <value>` (the MTU probe's clamp, issue #4).
   A `Batch` is `{Apply, Rollback}`: it carries its own textual inverse, so
   an irreversible mutation cannot be expressed. Applying the rollback twice
   issues the inverse once (an idempotent no-op the second time). **Never**
   `write file`, never touches persisted config — the batch validator refuses
   any config-preserving verb before anything is exec'd.

   > The tcp-mss clamp is per-neighbor **BGP** (`neighbor <ip> tcp-mss`), not an
   > interface command: FRR has no interface-level TCP MSS clamp. The Cisco
   > spelling `ip tcp adjust-mss` / `ip tcp-mss-clamp` is not an FRR interface
   > command. See the FRR BGP docs (`neighbor tcp-mss`) and the ZEBRA interface
   > command set; the batch constructor cites both.
6. **audit** every decision/action → structured log + Prometheus counter +
   `transitd_decisions_total{from,to,reason}` + `transitd_act_ops{op,result}`.

### Drift repair vs. config management re-apply (issue #4)

`act` is runtime-only by construction; it never writes persisted config. When
config management re-applies the operator's source-of-truth configuration, the
re-apply **wins**: any runtime mutation the agent applied (a neighbor shutdown,
an MSS clamp, a local-preference) is reverted to the committed config, because
the commit is what config management owns and the agent does not own it.

The agent then **re-applies its decision only if the decision inputs are
unchanged**. If the re-apply changed routing or session state, the inputs have
moved, so the agent re-decides first and applies the new verdict rather than
blindly re-asserting a stale one. This is the design.md "drift repair" rule,
and it is why `act` is idempotent: re-applying a batch whose effect is already
present is a no-op, so a re-apply that already restored the desired state costs
nothing and issues no command.

The practical consequence for the drill (issue #4's neighbor shutdown): a
config-management re-apply during a drill removes the shutdown the same way the
drill's own rollback would; the drill's restore is then a no-op (FRR's `no
neighbor ... shutdown` on an already-restored session does nothing), and the
verify phase reports the diff rather than failing.


## Safety model

- **Quorum**: gossip state carries epoch; actions require `ceil(n/2)+1`
  agents alive. Split-brain → all agents freeze (BGP/BFD still handles
  hard failure natively).
- **Watchdog**: agent exposes `:9414/healthz`; supervisor restarts on
  hang; restart always begins in observe-only mode for `settle` seconds.
- **Drift repair**: if runtime LP differs from the agent's decision for
  more than `drift_repair` seconds (e.g. an operator re-applied config
  management), the agent re-applies its decision — but only if the
  decision inputs are unchanged; otherwise it re-decides first. A
  config-management re-apply therefore wins over the agent's runtime state;
  the agent re-asserts only what the (possibly re-decided) inputs still
  warrant. Every act batch carries its textual inverse and is idempotent, so
  re-asserting state that is already present is a no-op. See "Drift repair vs.
  config management re-apply" under Data flow.
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
- The decide ranking engine keeps a byte-exact golden baseline under
  `internal/decide/testdata/golden/decide`, enforced by `TestGoldenDecide`
  (`make golden-update` regenerates deliberately). See
  [ci.md](ci.md#decision-goldens); every decide-touching PR must update it on
  purpose, and CI fails on an unexpected diff.
- Integration tests against FRR containers (docker compose: 3 frr
  containers + vtysh socket wiring) exercising: election, hysteresis,
  quorum freeze, drift repair, soft-clear batching.
- golangci-lint, gofumpt, govulncheck on every PR; release builds via
  goreleaser (linux/amd64 + arm64, static, distroless).
