# Feature capability and health surfacing

> Public-repo document. Contains **no** site-specific values — no IPs, ASNs,
> hostnames, or topology of any deployment. Addresses in examples are from the
> RFC 5737/3849 documentation ranges.

A transitd feature can stop working without the process dying: the probe binary
is missing from the image, a transit's pin does not verify, a gossip join fails,
a visibility provider goes down. This document is the contract for how such a
failure becomes visible. The design rule is **no silent self-disable**: a
capability that is not doing its job says so on at least one surface an operator
actually watches.

## The mechanism

Every capability registers with one registry (`internal/health`). A single
`Set`/`Register` call updates three surfaces at once, from one state value, so
they cannot disagree:

| Surface          | What it carries                                                          |
| ---------------- | ------------------------------------------------------------------------ |
| `/healthz` JSON   | `status` (`ok`/`degraded`), `pin_verified`, and `features` per capability |
| metric            | `transitd_feature_state{feature}` — `0` enabled, `1` degraded, `2` disabled |
| log               | one line per **state change**: WARN when a feature stops fully working, INFO when it recovers |

`/healthz` is served by the agent on the metrics listener (default `:9414`).

### `features` shape

```json
{
  "status": "degraded",
  "pin_verified": {"transit-a": true, "transit-b": false},
  "features": {
    "pinning":  {"state": "degraded", "reason": "1 of 2 transits unverified at startup: their probes are suppressed (no samples, no decisions)"},
    "probes":   {"state": "degraded", "reason": "1 of 2 transits unverified at startup: their probes are suppressed (no samples, no decisions)"},
    "decisions": {"state": "enabled"},
    "gossip":   {"state": "disabled", "reason": "gossip mesh not built into this binary (issue #3), but join is configured"}
  }
}
```

`state` is always present. `reason` is present whenever the state is not
`enabled`, and answers "what do I fix". A capability this build does not have is
**absent** unless the config asked for it, in which case it is reported disabled
with a reason — so `degraded` always means a real, fixable problem rather than a
roadmap item that is permanently alarming.

### Metric values

```
transitd_feature_state{feature="probes"}   0   # enabled
transitd_feature_state{feature="pinning"}  1   # degraded
transitd_feature_state{feature="gossip"}   2   # disabled
```

It is a gauge, not a counter: a feature can recover, and the question it answers
is "is this working right now".

### Logging rule

The warning fires on a **state change**, once per transition — not once per
report. A probe loop that re-asserts the same missing binary every cycle must
not fill the log with the same line; the operator learns of the failure once,
and the metric carries the ongoing state. A change of reason at the same state
updates the payload silently. A feature that is already broken when the process
starts still warns, because a capability is assumed enabled until it says
otherwise and so the first report of a failure is a transition.

## Failure modes

Each row is one way a capability quietly stops working, and where an operator
sees it. "healthz field" is the JSON path in `/healthz`.

| Failure mode | healthz field | metric | log |
| ------------ | ------------- | ------ | --- |
| Probe binary missing from the image (distroless, no `ping`) | `features.probes.state = disabled` (+ `reason`) | `transitd_feature_state{feature="probes"} = 2` | WARN `feature not fully working` |
| Probe binary present but not a recognised implementation | `features.probes.state = degraded` (+ `reason`) | `transitd_feature_state{feature="probes"} = 1` | WARN `feature not fully working` |
| A transit's pin unverified (`ip route get` disagrees with `egress_interface`) | `pin_verified[transit] = false`; `features.pinning.state = degraded`; `features.probes.state = degraded` (+ `reason`, naming the count) | `transitd_pin_verified{transit} = 0`; `feature_state{feature="pinning"} = 1`; `feature_state{feature="probes"} = 1` | ERROR `pin NOT verified — transit suppressed: no probe samples, no decisions`, then WARN `feature not fully working` |
| All transits unverified | `features.pinning.state = degraded`, `features.probes.state = degraded`; every `pin_verified` entry `false` | same as above, per transit | as above |
| Gossip join configured but the mesh is not built into this binary | `features.gossip.state = disabled` (+ `reason`) | `transitd_feature_state{feature="gossip"} = 2` | WARN `feature not fully working` |
| Gossip memberlist join failure (issue #3) | `features.gossip.state = degraded` (+ `reason`) | `transitd_feature_state{feature="gossip"} = 1` | WARN `feature not fully working` |
| Decision loop not running | `features.decisions.state = disabled` (+ `reason`) | `transitd_feature_state{feature="decisions"} = 2` | WARN `feature not fully working` |
| Visibility provider down / rate-limited / schema drift (planned) | `features.visibility.state = degraded` (+ `reason`) | `transitd_feature_state{feature="visibility"} = 1` | WARN `feature not fully working` |

Notes:

- **Probe binary** is checked once at startup with a `ping -V`-style probe. The
  check is the difference between "no probes configured" and "probes are
  broken", which otherwise look identical from the outside.
- **Pin failure degrades probes as well as pinning.** An unverified transit emits
  no samples at all (see `docs/design.md`, issue #1), so "probes are working" is
  not true in the sense an operator cares about while any configured transit is
  suppressed: the agent is observing a strict subset. The probes feature is
  *degraded*, not disabled — the verified transits still probe. A missing probe
  binary is the harder failure and is not overwritten by a pin outcome.
- **Gossip** is listed twice on purpose. Once issue #3 lands, a failed memberlist
  join becomes a `degraded` set with the join error as the reason; until then, a
  config that names `join` hosts is reported `disabled`, because the operator has
  clearly asked for a mesh that will never form.
- **Visibility** rides this mechanism per issue #5's design-review note, and its
  metric (when it lands) is documented as page-worthy for a monitoring system.

## Status semantics

`status` is `degraded` when **any registered** feature is not `enabled`, and
`ok` otherwise. It is derived from the registry, never set by hand, so the
top-level verdict and the per-feature map can never disagree.

`/healthz` answers HTTP 200 in both cases. It reports state; it does not gate
traffic, and a supervisor watching for a hang needs "alive" to be distinguishable
from "not listening". The `status` field is the machine-readable verdict; alert
on that, or on `transitd_feature_state`, not on the HTTP code.

## Extending it

To surface a new capability, register it once and report state changes through
the same call:

```go
reg.Register("mtu", health.Enabled, "")
reg.Set("mtu", health.Degraded, "no ping binary in image: MTU probe cannot run")
```

The registry is generic: it knows nothing about the subsystem beyond the name.
Pick a stable feature name (dashboards and alert rules key on it), give a reason
for every non-enabled state, and add a row to the table above.
