# P1 feature design docs

Reviewed design documents for the four P1 backlog features (post adversarial
review). Each design is complete and agreed; **implementation is tracked in the
linked issue** — these documents describe intent and constraints, they do not
ship the feature.

| Design | Feature | Tracking issue |
|---|---|---|
| [`feature-1-drill.md`](feature-1-drill.md) | `transitctl drill` — automated failover drill | [#9](https://github.com/ioseph-ai/transitd/issues/9) |
| [`feature-2-mtu-probe.md`](feature-2-mtu-probe.md) | Per-transit MTU probe (PMTUD + blackhole detection) | [#7](https://github.com/ioseph-ai/transitd/issues/7) |
| [`feature-3-visibility.md`](feature-3-visibility.md) | Global visibility monitor (DFZ view vs intended state) | [#8](https://github.com/ioseph-ai/transitd/issues/8) |
| [`feature-4-tcp-probe.md`](feature-4-tcp-probe.md) | TCP-handshake probe mode (stateful-edge asymmetry) | [#6](https://github.com/ioseph-ai/transitd/issues/6) |

All examples in these documents use RFC 5737/3849 documentation ranges and
RFC 5398 documentation ASNs (64496–64511) only.
