# Gossip health schema — version policy and changelog

This document is the contract between transitd versions that share a gossip
mesh. It is deliberately short: the policy is one rule, and the changelog is
append-only like the schema it describes.

The package doc (`gossip` in `internal/gossip/schema.go`) is the executable half
of this document; when the two disagree, the tests in this directory are the
tie-breaker and the disagreement is a bug.

## The wire format

Every health message is an envelope:

```json
{
  "schema_version": 1,
  "ts": "2026-01-01T00:00:00Z",
  "router": "r-example",
  "payload": { "transits": [...], "decide": {...} }
}
```

- `schema_version` (uint32) is the version of the **payload schema**, not of
  memberlist's transport. It is what a rolling upgrade keys on.
- `ts` is the sender's wall-clock time.
- `router` is the sender's `router_name`; it tags the view's owner.
- `payload` is version-specific JSON, carried as raw bytes. Keeping it raw is
  what makes the append-only promise work: an old node can read the envelope,
  count the version, and decline to guess at a body it does not understand.

The envelope is fixed at these four fields. Everything a feature adds goes
**inside** the payload, so the frame never changes and never needs a breaking
bump.

## Version policy

1. **Append-only.** A field may be **added** to the payload at any time without
   a version bump. Once a field name has shipped it is never removed, renamed,
   retyped, or given a different meaning.
2. **Bump the major on any breaking change.** A change to an existing field's
   name, type, or meaning is by definition a new schema version. Since there is
   no way to make such a change invisible to old readers, the version is bumped
   and the change is documented in the changelog below.
3. **Old nodes must tolerate new payloads.** Unknown fields are ignored, always.
   A message from a version this build does not know is **ignored**, not
   rejected: it is counted in `transitd_gossip_schema_rx{version}` so an operator
   can see the rollout, and dropped otherwise.
4. **New nodes must tolerate old payloads.** Version 0 (the pre-envelope shape)
   is accepted for one rollout. See the changelog.
5. **A node never acts on another node's decision.** The `decide` block is
   advisory. It is merged into the view; it does not drive local router state.

### What "ignore" means precisely

| Situation | Behaviour |
|---|---|
| Unknown field inside a known-version payload | Dropped. Message accepted. |
| Unknown field inside the envelope | Error. The envelope is the part both ends must agree on. |
| `schema_version` **newer** than this build | Message ignored, counted by version, no error. |
| `schema_version` **older** than this build (and known) | Decoded at that version. |
| Malformed envelope / not JSON | Error, logged, dropped. Never re-broadcast. |
| Any input at all | Never panics. `FuzzGossipDecode` holds this. |

## Changelog

### v0 — pre-envelope (legacy, accepted for one rollout)

The scaffold's message, with the sender's identity inside the body and no
version frame:

```json
{"router": "r-example", "ts": "...", "transits": [...], "decide": {...}}
```

Accepted because during the window when a new build is rolling out, an old node
is still emitting this shape and the new node must not go deaf. There is no
forward path: the encoder never emits v0.

### v1 — versioned envelope, current

- Introduces the envelope (`schema_version`, `ts`, `router`, `payload`).
- Payload: `transits[]` (per-transit `name`, `session_up`, `loss_pct`,
  `ewma_ms`) and `decide` (`primary`, `switched`, `reason`, `frozen`).
- `ewma_ms` is absent, never `0`, when a transit has no successful measurement.
  A fabricated `0 ms` would rank a silent transit as the fastest path.

## Reserved append-only fields

The following payload field names are **reserved** for planned features. They
are not implemented and are deliberately not declared in the Go structs: a
declared field carries a zero value, and a zero would look like a measurement.
A sender may ship them before this build knows what they mean — the message
still decodes, because unknown fields are ignored. That is the whole point of
reserving the names here rather than after the fact.

| Field | Reserved for | Issue |
|---|---|---|
| `mtu_state` | per-transit path-MTU probe state | #7 |
| `tcp_signal` | per-transit TCP handshake/rtt signal | #6 |
| `maintenance` | drill and planned-maintenance notices | #9 |
| `visibility_intent` | intended announcement sets for the visibility monitor | #8 |

When one of these lands, it is added as a new field whose zero value
unambiguously means "not reported", and `schema_version` stays at 1 unless an
existing field changes shape or meaning.

Note that the mesh carries the whole merged health view, so a probe feature that
wants its signal gossiped does not need a new envelope: it appends its field to
the v1 payload and every node on the current version sees it.

## Testing the policy

- `testdata/golden/v1-new.json`, `testdata/golden/v0-old.json`,
  `testdata/golden/v2-unknown.json`, `testdata/golden/v1-reserved-fields.json`
  are the compat fixtures; `schema_test.go` asserts each behaviour in the table
  above against them.
- `testdata/fuzz/FuzzGossipDecode/` is the committed fuzz seed corpus. It runs on
  every plain `go test`; a crasher found by the weekly fuzz job (issue #18) lands
  there as a regression case.
- `testdata/golden/v1-encode.golden` pins the encoder's bytes. A change to it is
  a wire change: either the schema moved (bump `CurrentSchemaVersion` and this
  document) or the encoder broke.

## Metrics

- `transitd_gossip_members` — alive mesh size, including this router.
- `transitd_gossip_rx` — messages reaching the delegate's receive path, counted
  before decode, so it includes frames that fail to decode. The per-version
  counter is the one that breaks the rate down by schema.
- `transitd_gossip_tx` — health messages broadcast by this router.
- `transitd_gossip_schema_rx{version}` — messages received, by envelope
  `schema_version`. A series for a version this build does not know is the
  rollout signal the policy is built around.
