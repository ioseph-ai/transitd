# Probe pinning and startup verification

> Tracking: [#1](https://github.com/ioseph-ai/transitd/issues/1)
>
> Public-repo document. Every address, interface name and table id below is an
> RFC 5737 / RFC 3849 documentation value or an obviously synthetic name.
> Nothing here describes a real deployment.

## 1. The problem this resolves

Three probe features (ICMP latency, MTU discovery, TCP handshake) each have to
send their traffic through **one specific transit**. A probe that is only bound
to a source address fixes the *source IP*, not the *egress path*: unless the
kernel also has a per-source policy route, the packet leaves through the
default or ECMP path with a foreign source. The consequences split three ways:

| What actually happened | What the probe reports |
|---|---|
| Egressed the intended transit | Correct latency/loss for that transit |
| Egressed a different path, reply came back | **A number for the wrong transit** |
| Egressed a different path, uRPF-dropped | 100% loss for a transit that is fine |

The middle row is the dangerous one. A mis-pinned probe produces data that is
indistinguishable from correct data, and that data feeds `decide`'s exclusions
and the operator dashboards. The failure mode is not "the numbers look wrong",
it is "the numbers look right".

## 2. Interface-pin vs source-pin — the divergence, resolved

Two mechanisms were proposed across the design documents:

- `docs/design.md` (component overview) pins probes to *"each transit's
  next-hop interface"* — an **interface pin**.
- The feature designs (`feature-2-mtu-probe.md` §2.1, `feature-4-tcp-probe.md`
  §2) pin probes to *"the transit source address"* — a **source pin**.

They are not interchangeable, and the difference is exactly where ECMP decides
the path:

- **Interface pin** (`SO_BINDTODEVICE`, `-I <iface>`, or a route with `dev`) fixes
  the *first hop's egress interface*. On a link with more than one path to the
  same next hop — a LAG member, a bundle, an ECMP fabric — the *rest* of the
  path is still chosen by the fabric's hash. It also does not compose with the
  route the transit actually uses: forcing an interface can select a route the
  transit does not have, i.e. measure a path the transit never uses.
- **Source pin** (`-I <addr>`, or binding the socket to the address) fixes the
  *source* and lets the kernel's routing table pick the egress. When the transit
  is modelled the way transitd models it — one source address per transit, with
  a per-source policy route (`ip rule from <src> lookup <table>`) that the
  operator or the lab installs — the source pin *is* the transit selector: the
  same hash inputs the transit's own traffic uses decide the path.

**Decision (this document, MVP): the pin is the transit's source address, and the
expected path is the transit's egress interface.** Concretely:

1. `probe_source` is the transit's own interface address. It is passed as `-I
   <src>` to `ping` (and, later, as the source bind for the TCP probe).
2. The per-transit policy route (`from <probe_source> lookup <table>`) is the
   operator's routing configuration, not something transitd writes. transitd
   *verifies* it (below); it does not create it. A future card may add
   `ip rule`/`ip route` management, but that is an `act`-class change and is out
   of scope for #1.
3. `egress_interface` is the interface the transit's probes are expected to
   leave through. It is the **assertion target**, not a pin: transitd never
   forces probes out of it, it checks that the operator's routing already sends
   them there.

This keeps one code path for v4 and v6 (the address family follows `src`), keeps
the source pin identical across the ICMP, MTU and TCP probes, and avoids the
interface-pin trap of measuring a path the transit does not use.

### ECMP caveat

Source pinning is deterministic **only when the transit's hash inputs are
fixed**. The hash tuple is typically (src, dst, protocol, src-port, dst-port).
transitd pins src and dst (one source, one probe target per transit) and uses one
protocol (ICMP). For a future multi-target probe, keep the tuple stable across a
session — a varying target or port can hash to a different bundle member and turn
one transit into two measured paths. The MTU probe's binary search deliberately
holds payload pattern and target fixed for this reason.

## 3. Startup verification preflight

At startup, before any probe runs, each transit is verified:

```
ip route get <probe_target> from <probe_source>
```

The command is executed directly (argv slice, never a shell). Its first line
names the resolved egress with a `dev <iface>` token; the resolved interface is
compared against the transit's `egress_interface`.

```
203.0.113.200 from 203.0.113.1 dev eth-transit table 4511 uid 0
```

- `dev == egress_interface` → **verified**. The transit gets a probe loop.
- anything else (mismatch, lookup failure, unparseable output) → **unverified**.
  The transit gets **no probe loop**, exports **no** `transitd_probe_*` samples,
  and its `transitd_pin_verified` gauge is `0`.

The verification is a single-shot query at startup. It is not a substitute for
the probe's own pin (the probe still passes `-I <src>` every cycle); it is the
guard that catches a routing change that would make the probe lie.

### Failure semantics — suppression, not correction

An unverified transit is **suppressed**, never guessed at:

- No probe loop is constructed for it. This is structural: the sample stream
  does not exist, so no downstream consumer can forget to filter it.
- Its `transitd_probe_latency_ms` / `transitd_probe_loss_pct` series are deleted
  if they exist. A *missing* series is distinguishable from a healthy `0%`; a
  zeroed series would be a lie. Dashboards must treat absence as "no data".
- `transitd_pin_verified{transit}` is exported as `0`, so the transit is visible
  as *present but broken*, which is different from *not configured*.
- The agent reports `degraded` health (formalised in #5).

A transit that is down and a transit that is mis-pinned therefore look different:
the former exports a probe series showing loss, the latter exports no probe
series at all and a `pin_verified=0`.

## 4. Configuration

```yaml
transits:
  - name: main
    import_map: MAIN-LOCAL-IN
    probe_source: 203.0.113.1      # transit's own interface address (the pin)
    probe_target: 203.0.113.200    # canary destination
    egress_interface: eth-transit  # expected egress (the assertion target)
    probe_interval: 30s
```

All three pinning fields are required; validation fails at startup:

- `probe_source` must parse as an IP,
- `probe_target` must parse as an IP,
- `egress_interface` must be a plausible interface name (no whitespace, slashes
  or control characters) — it reaches an argv element, and a config typo must not
  become a shell metacharacter or a confusing exec failure.

Unknown keys stay rejected by the strict loader exactly as before; these fields
do not loosen it.

## 5. Tests

- **Unit (`internal/pinning`)** — a `Runner` interface fakes `ip route get`:
  match, mismatch (asserting the *observed* interface is surfaced), v6 output,
  lookup failure, unparseable output, incomplete config. No root, no netlink.
- **Unit (`internal/probes`)** — golden `ParsePing` fixtures for the iputils and
  busybox reply/timeout shapes and the fragmentation error; EWMA convergence and
  rolling-loss window behaviour against a scripted fake runner; the suppression
  tests asserting an unverified transit emits no sample, runs no `ping`, and
  exports no probe series.
- **Integration (`test/integration/pinverify`, `//go:build integration`)** — two
  veth pairs; the target is routed out the SECOND while the transit expects the
  FIRST → `Verified=false` with the observed egress; then the route is corrected
  → `Verified=true`. IPv4 and IPv6 variants. Skips cleanly when the host cannot
  create veth pairs; otherwise it needs no docker.

## 6. Non-goals

- writing `ip rule`/`ip route` (routing config remains the operator's).
- per-packet path selection or Paris-traceroute-style refinement (a future
  multi-path feature; the pin keeps the 5-tuple stable so it can be added later).
- MTU/TCP probe specifics — they reuse this pinning mechanism and this
  verification, and are tracked in #7 and #6.
