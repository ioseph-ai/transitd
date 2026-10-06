# transitd control channel protocol (issue #2)

This document is the contract for the control channel: the authenticated RPC
surface `transitctl` (and, later, `transitctl drill`) uses to reach a transitd
agent. It covers the transport, the request/response shapes, the auth model, the
rate limits and the reserved remote-over-gossip extension.

The implementation is `internal/ctrl` (server and client) and `cmd/transitctl`
(the operator's CLI). Where this document and the code disagree, the code is
wrong and should be fixed — the code exists to implement what is written here.

> Public-repo document. Every address and key below is a documentation range or a
> placeholder: RFC 5737 `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24`,
> RFC 3849 `2001:db8::/48`. No deployment values appear here.

## 1. Transport (this PR: local only)

The transport is a **unix stream socket** on the agent's host. There is no TCP
listener and nothing on the gossip mesh in this PR.

- Path: the config's `control.socket_path`, default `/run/transitd/ctrl.sock`.
- The agent creates the socket's parent directory with mode **0750** and the
  socket itself with mode **0660**, both owned by its uid/gid (root:root when the
  agent runs as root, which it does in the deployment target).
- One request per connection: the client connects, writes one request document,
  half-closes its write side (so the server sees a clean end of request), and
  reads one reply line. The connection is then closed. This keeps all per-call
  state on the connection and lets `socat`/`nc -U` drive the socket by hand.

The socket's filesystem permissions are the first access-control layer: only a
process that can traverse the 0750 directory and open the 0660 socket can reach
the server. The shared key (§3) is the second, orthogonal layer. Neither is
optional; the channel is designed so that losing one still leaves the other.

## 2. Wire format

A request is one UTF-8 JSON object, optionally followed by a newline (the client
sends one; the server does not require it). A reply is one JSON object followed by
a newline. The request body is capped at **4 KiB**; a larger body is refused with
`bad_request`.

### 2.1 Request

```json
{
  "v": 1,
  "header": { "X-Transitd-Key": "<base64 shared key>" },
  "method": "set-primary",
  "params": { "transit": "main" }
}
```

| Field    | Type              | Required | Meaning                                                              |
|----------|-------------------|----------|----------------------------------------------------------------------|
| `v`      | integer           | no       | Protocol version. `0`/absent is read as `1` (first implementation). |
| `header` | object<string,string> | yes | Request headers. `X-Transitd-Key` is the only one defined today.    |
| `method` | string            | yes      | The operation. Unknown values are `bad_request`.                     |
| `params` | object            | per-method | The method's arguments.                                           |

### 2.2 Response

```json
{ "v": 1, "method": "status", "result": { "...": "..." } }
{ "v": 1, "method": "status", "error": "unauthorized: missing or wrong X-Transitd-Key" }
```

| Field    | Type   | Meaning                                                                 |
|----------|--------|-------------------------------------------------------------------------|
| `v`      | integer | Protocol version of the reply.                                        |
| `method` | string | Echo of the request's method, so a pipelining client can match replies. Absent only when the request had no method at all. |
| `result` | object | The method's success body. Present only on success.                   |
| `error`  | string | `"<code>: <detail>"`. Present only on failure. Codes in §2.4.         |

A client MUST treat a non-empty `error` as failure even though the transport
succeeded: the socket answering is not the request succeeding.

### 2.3 Methods

#### `status`

Returns the healthz-equivalent document. Read-only and **exempt from the rate
limit** (§4). `params` must be absent or empty.

```json
{
  "version": 1,
  "router": "r-example",
  "health": { "status": "ok", "pin_verified": { "main": true }, "features": { "...": "ok" } }
}
```

The `health` object is the agent's `/healthz` payload passed through verbatim, so
a control client and a monitoring scrape cannot disagree about the agent's state.
The control channel does not define the health schema; `internal/agent` does.

#### `ping`

Liveness. `params` absent. Rate-limited.

```json
{ "version": 1, "router": "r-example" }
```

#### `set-primary`

Records the operator's desired primary transit. `params`:

```json
{ "transit": "main" }
```

Reply:

```json
{
  "version": 1,
  "router": "r-example",
  "transit": "main",
  "applied": false,
  "note": "recorded desired primary; not applied — this build is observe-only (act wiring tracks issue #4)"
}
```

**`applied` is `false` in this PR.** The agent records the preference, logs it
and exports `transitd_ctrl_set_primary` (1 for the requested transit, 0 for its
peers), but applies nothing to the router: applying a preference needs the act
package of issue #4. A client MUST NOT present a success here as "the transit is
now preferred"; it must say "recorded, not applied". The field is a boolean
rather than an omitted key so a future act-wired build flips it to `true` and a
client can key its messaging on the value without a version bump.

The transit name is validated against the agent's configured transits; an
unknown name is `bad_request` and the recording hook does not run.

### 2.4 Error codes

| Code           | Meaning                                                                 | Also                                                   |
|----------------|-------------------------------------------------------------------------|--------------------------------------------------------|
| `unauthorized` | Missing or wrong `X-Transitd-Key`.                                      | increments `transitd_ctrl_auth_fail`, audit-logged.    |
| `rate_limited` | A rate-limited method has no tokens left.                              | increments `transitd_ctrl_rate_limited`.                |
| `bad_request`  | Malformed JSON, unknown method, bad/missing params, oversized body.   | —                                                      |
| `internal`     | The agent could not produce a reply it believes in (e.g. health failed). | —                                                    |

## 3. Authentication

Every request must carry the **gossip shared key** — the same secret as
`gossip.key`, base64, used as the memberlist `SecretKey` — in the
`X-Transitd-Key` header. This is the key docs/design.md already treats as an SSH
key: anyone holding it can inject health state, and now also ask the agent to
change preference. There is no second secret to manage, and no per-client
identity in this PR (there is no caller identity to key on for a local socket
beyond the peer credentials the filesystem already enforces).

- The comparison is constant-time (`crypto/subtle.ConstantTimeCompare`), so a
  wrong key is not distinguishable by timing from a wrong-length key.
- A missing or wrong key is answered with **`unauthorized`** and:
  - the audit line `control: auth rejected` is logged with the presented-key
    presence and the failure reason; the key bytes are **never** logged;
  - `transitd_ctrl_auth_fail` is incremented.
- **Auth is checked before method dispatch.** An unauthenticated caller learns
  nothing about which methods exist: an unknown method with no key returns
  `unauthorized`, not `unknown method`.

The header name is matched case-insensitively, so a client that lowercases its
headers is not rejected on a spelling technicality.

## 4. Rate limiting

A **token bucket per method**, **10 requests per minute**, refilling
continuously. A method's first request starts from a full bucket.

- **`status` is exempt.** It is read-only, it is the method a monitoring probe
  calls hardest, and shedding it would make a healthy agent look unreachable.
- Buckets are **per method, not per client**: exhausting `ping` never sheds
  `set-primary`. There is no caller identity to key a per-client limit on
  locally; the limit caps how fast the agent will accept a given method from
  anyone.
- A shed request is answered with **`rate_limited`** and increments
  `transitd_ctrl_rate_limited`. It is **not** an auth failure: a throttled client
  and a probing one are different signals and must stay distinguishable in the
  metrics.

## 5. Metrics

| Metric                        | Type    | Meaning                                                     |
|-------------------------------|---------|-------------------------------------------------------------|
| `transitd_ctrl_auth_fail`     | counter | Requests rejected for a missing/wrong key.                 |
| `transitd_ctrl_rate_limited`  | counter | Requests shed by the per-method limit (not an auth failure). |
| `transitd_ctrl_set_primary`   | gauge{transit} | 1 for the last requested transit, 0 for its peers. Observe-only. |

## 6. Reserved extension: remote invocation over the gossip mesh

**This PR is local-only.** The remote path is a later PR; it is described here so
the wire format above is shaped to accept it without a flag day.

The intended design: `transitctl` on one host reaches an agent on another by
sending the same request document over the existing gossip mesh, keyed off the
memberlist shared key. Two properties follow from reusing the mesh rather than
opening a port:

- **No new port.** docs/design.md exposes only the metrics listener and the mesh;
  remote control rides the mesh, so the security surface does not grow.
- **Same auth secret.** The mesh already authenticates and encrypts with the
  shared key; a remote control request presents that key the same way a local one
  does, in `X-Transitd-Key`.

What the request/response shapes already do to make that possible:

1. **Headers are a map.** A remote transport needs to carry more than one header
   (the key, a reply address, a request id). The `header` object is a map for
   exactly that reason; only the key is defined today.
2. **`method` is echoed in the reply.** A remote transport multiplexes replies
   from possibly many agents, so matching a reply to its request cannot rely on
   connection identity. The echo is already there.
3. **A `v` version on both directions.** The remote message can be a distinct
   mesh payload with its own `schema_version`, while the control protocol keeps
   its own `v`; the two evolve independently.
4. **`status` returns the health document verbatim.** A remote reply crosses a
   schema boundary the same way a gossiped health payload does, so the control
   layer must not own the health schema — it does not.

Deliberately **not** decided here (for the later PR): whether remote invocation is
a new gossip payload type or rides the health envelope; how a remote agent is
addressed (mesh node name vs. router name); the quorum interaction with
docs/design.md's safety model (a remote preference change is an action, and the
safety model's quorum rule may apply to it).

## 7. Client

`cmd/transitctl` is the reference client. It reads `control.socket_path` and
`gossip.key` from the agent's config (`--config`) unless overridden by `--socket`
and `--key`, and exposes:

```
transitctl --config /etc/transitd.yaml status
transitctl --config /etc/transitd.yaml set-primary <name>
```

It is a client, not a daemon. Exit codes distinguish the failure modes so a
script can branch: `0` success, `2` usage, `3` the agent refused (auth, unknown
method, bad request), `4` the agent could not be reached.
