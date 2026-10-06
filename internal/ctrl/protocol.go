// Package ctrl implements transitd's local control channel: the authenticated
// unix-socket RPC surface `transitctl` talks to (issue #2).
//
// This MVP is LOCAL ONLY. The socket is the whole transport: there is no remote
// listener, no TCP port and nothing on the gossip mesh. Remote invocation is the
// reserved extension documented in PROTOCOL.md; the request/response types here
// are shaped so it can be added as a second transport without a wire change.
//
// The channel is a privilege boundary in the same sense the mesh key is (see
// docs/design.md's threat model): the agent runs root-equivalent and can drive
// vtysh, so anyone who can reach the socket with the shared key can ask it to
// change preference. Two things enforce it — the socket's filesystem permissions
// (0750 directory, 0660 socket, root:root) and a constant-time key check on every
// request. Neither is treated as optional.
package ctrl

import (
	"encoding/json"
	"fmt"
	"strings"
)

// maxRequestBytes bounds a control request. The wire format is tiny — the
// request type is three fields and at most one short string — so the limit is
// generous for legitimate use while keeping a client from making the server
// buffer an unbounded body. Exceeding it is a 400, not a read that grows until
// the process is out of memory.
const maxRequestBytes = 4 << 10 // 4 KiB

// ProtocolVersion is the version of the request/response shapes in this
// package. It is the `v` field of every request and the `version` field of the
// status reply. It exists so a future remote transport (over gossip) can carry
// the same documents and evolve them without a flag day. It is NOT the gossip
// envelope schema_version: those evolve independently.
const ProtocolVersion = 1

// DefaultRateLimit is the token-bucket allowance for a rate-limited method. The
// card fixes it at 10 requests per minute.
const DefaultRateLimit = 10

// Method names. They are the `method` field of a request.
const (
	// MethodStatus returns the healthz-equivalent JSON document. It is exempt
	// from the rate limit: it is read-only, it is the request a monitoring probe
	// makes, and shedding it would make the agent look down when it is not.
	MethodStatus = "status"
	// MethodPing returns a liveness reply. It is rate-limited like any other
	// method; a client that needs an unthrottled liveness check scrapes
	// /healthz on the metrics listener instead.
	MethodPing = "ping"
	// MethodSetPrimary records an operator's desired primary transit. It is
	// observe-only in this MVP: the agent records the preference, logs it and
	// exports a metric, but applies nothing (issue #4 lands the act wiring).
	MethodSetPrimary = "set-primary"
)

// HeaderKey is the request header every call must carry: the gossip shared key,
// base64, exactly as it appears in `gossip.key`. It is named the way an HTTP
// header would be because the reserved remote transport (see PROTOCOL.md) is
// expected to carry it as one; locally it is a field of the request document's
// header map.
const HeaderKey = "X-Transitd-Key"

// Request is one control-channel call. It is a small JSON document on its own
// line, so a human can drive the socket with `socat` while debugging without
// hand-writing a length prefix.
type Request struct {
	// V is the protocol version. Zero is treated as ProtocolVersion for the
	// same reason gossip treats a zero schema_version as v0: an omitted field
	// must not be a parse error on the first implementation.
	V int `json:"v"`
	// Header carries the request's authorization, keyed by header name. Only
	// HeaderKey is defined today; the map (rather than a single field) is what
	// lets the remote-over-gossip transport add the same headers an HTTP call
	// would carry without a wire change.
	Header map[string]string `json:"header,omitempty"`
	// Method is the operation to perform.
	Method string `json:"method"`
	// Params carries the method's arguments. Each method defines its own shape;
	// a missing or unparsable params object is a method error, not a transport
	// error.
	Params json.RawMessage `json:"params,omitempty"`
}

// Key returns the presented shared key, looked up case-insensitively so a client
// that lowercases its headers is not rejected on a spelling technicality. An
// absent header returns "".
func (r *Request) Key() string {
	for k, v := range r.Header {
		if strings.EqualFold(k, HeaderKey) {
			return v
		}
	}
	return ""
}

// SetPrimaryParams is MethodSetPrimary's argument shape.
type SetPrimaryParams struct {
	// Transit is the configured transit name the operator wants preferred.
	Transit string `json:"transit"`
}

// StatusResult is MethodStatus's reply body. It carries the same document
// /healthz serves — the agent's Health value — so a control client and a
// monitoring scrape cannot disagree about the agent's state. It is opaque here
// (json.RawMessage) because the agent owns that contract, not this package; the
// server passes it through rather than decoding and re-encoding it.
type StatusResult struct {
	// Version is the control protocol version the agent speaks.
	Version int `json:"version"`
	// Router is the agent's configured router name, so a client that reached the
	// wrong socket by mistake can tell.
	Router string `json:"router"`
	// Health is the /healthz payload verbatim.
	Health json.RawMessage `json:"health"`
}

// PingResult is MethodPing's reply body.
type PingResult struct {
	Version int    `json:"version"`
	Router  string `json:"router"`
}

// SetPrimaryResult is MethodSetPrimary's reply body. It says explicitly that the
// preference was recorded and NOT applied, because in this MVP those differ —
// a client must never read "ok" as "your transit is now primary".
type SetPrimaryResult struct {
	Version int    `json:"version"`
	Router  string `json:"router"`
	// Transit is the name the agent recorded.
	Transit string `json:"transit"`
	// Applied is always false in this MVP. It is a field rather than an omitted
	// one so a future act-wired build can flip it to true and a client can key
	// its messaging on the value instead of on a version bump.
	Applied bool `json:"applied"`
	// Note is a human-readable line for `transitctl` to print.
	Note string `json:"note"`
}

// Response is the envelope every reply uses. A single shape means a client needs
// no per-method parsing branch and a failure is never mistaken for a body: on
// error, Result is absent and Error is set.
type Response struct {
	// V is the protocol version of the reply.
	V int `json:"v"`
	// Method echoes the request's method, so a client pipelining calls can
	// match a reply to its request.
	Method string `json:"method"`
	// Result is the method's success body, present only on success.
	Result json.RawMessage `json:"result,omitempty"`
	// Error is the failure description, present only on failure.
	Error string `json:"error,omitempty"`
}

// Error codes. They are carried in the audit/wire text rather than as a separate
// numeric field, because the set is small and a client keys on the HTTP-ish
// intent (auth vs. method vs. rate) that the code names.
const (
	// ErrCodeUnauthorized is returned when a request's X-Transitd-Key header is
	// missing or wrong. Every one of these audit-logs and increments
	// transitd_ctrl_auth_fail.
	ErrCodeUnauthorized = "unauthorized"
	// ErrCodeRateLimited is returned when a rate-limited method has no tokens
	// left.
	ErrCodeRateLimited = "rate_limited"
	// ErrCodeBadRequest is returned for a malformed document, an unknown method
	// or bad parameters.
	ErrCodeBadRequest = "bad_request"
	// ErrCodeInternal is returned when the server could not produce a reply it
	// believes in.
	ErrCodeInternal = "internal"
)

// errorText formats the `error` field. The code leads so a client can match a
// prefix, and the detail follows for a human reading `transitctl` output.
func errorText(code, detail string) string {
	if detail == "" {
		return code
	}
	return fmt.Sprintf("%s: %s", code, detail)
}
