// Package gossip implements transitd's shared health mesh: a memberlist gossip
// layer that carries a versioned, append-only health schema between routers.
//
// Two properties define this package and are enforced by tests rather than by
// convention:
//
//   - The wire format is append-only. The decoder is STRICT about the envelope
//     (a malformed envelope is a bug we want to see) and LENIENT about the
//     payload (unknown fields are ignored, always). A message whose
//     schema_version is NEWER than this build's is ignored, never an error:
//     that is what lets a fleet upgrade one router at a time.
//   - Decoding untrusted bytes never panics. The mesh delegate is reachable by
//     anyone holding the shared key, and FuzzGossipDecode holds this invariant.
//
// See SCHEMA.md in this directory for the version policy, the v1 changelog and
// the reserved append-only field names.
package gossip

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// CurrentSchemaVersion is the schema version this build encodes. Decode always
// happens at this version; Encode always stamps it.
//
// Version 0 is the pre-envelope legacy shape (see legacyPayload) and is accepted
// on the wire for the length of one rollout. Every version ABOVE this one is
// unknown to this build and is ignored on receipt.
const CurrentSchemaVersion uint32 = 1

// Envelope is the versioned outer frame of every health message. It is decoded
// strictly: an unknown or misspelled field here is a protocol error, because the
// envelope is the part both ends must agree on for the payload leniency below to
// mean anything.
//
// The envelope is deliberately fixed at four fields. Everything a feature adds
// goes inside Payload, so the frame never changes and never needs a breaking
// version bump.
type Envelope struct {
	// SchemaVersion is the version of the PAYLOAD schema, not of memberlist's
	// transport. It is what a rolling upgrade keys on.
	SchemaVersion uint32 `json:"schema_version"`
	// TS is the sender's wall-clock time when the message was built.
	TS time.Time `json:"ts"`
	// Router is the sender's configured router_name. It identifies the view's
	// owner in the merged health state, so it is carried in the envelope rather
	// than only in the payload.
	Router string `json:"router"`
	// Payload is the version-specific body. Keeping it as raw JSON is what makes
	// the append-only promise work: an old node can read the envelope, count the
	// version, and decline to guess at a body it does not understand.
	Payload json.RawMessage `json:"payload"`
}

// HealthPayload is the v1 body: the sender's per-transit probe summary plus its
// decide view. Every consumer of the mesh (the merged health view, the
// visibility monitor, the drill watcher) reads from here.
//
// # Reserved append-only fields
//
// The following field names are reserved for planned features. They are NOT
// implemented yet and are NOT declared below, deliberately: declaring them would
// make a zero value look like a measured one. A payload that already carries them
// decodes fine (unknown fields are ignored), which is the whole point of the
// append-only policy — the senders can ship first and this node upgrades later.
//
//	mtu_state         (issue #7)  per-transit path-MTU probe state
//	tcp_signal        (issue #6)  per-transit TCP handshake/rtt signal
//	maintenance       (issue #9)  drill/planned-maintenance notices
//	visibility_intent (issue #8)  intended announcement sets for the monitor
//
// When one of these lands it is added as a new field with a zero-value that
// unambiguously means "not reported", and CurrentSchemaVersion stays at 1 unless
// an existing field changes shape or meaning.
type HealthPayload struct {
	// Transits is this router's per-transit probe summary. An absent list means
	// "this router reports nothing", which is distinct from an empty measurement.
	Transits []TransitSummary `json:"transits,omitempty"`
	// Decide is this router's decision view: what it currently prefers and why.
	Decide *DecideView `json:"decide,omitempty"`
}

// TransitSummary is one transit as the sending router measures it.
//
// SessionUp is a BGP-session fact. Until bgpwatch (issue #4) exists the sender
// has no session source and reports the probe-derived liveness instead, which is
// why a receiver must treat this field as the sender's claim, not as ground
// truth from its own point of view.
type TransitSummary struct {
	Name      string `json:"name"`
	SessionUp bool   `json:"session_up"`
	// LossPct is probe loss over the sender's rolling window, 0..100.
	LossPct float64 `json:"loss_pct"`
	// EwmaMs is the sender's EWMA latency in milliseconds. It is a POINTER so
	// that "no measurement yet" is an ABSENT field rather than a zero: a
	// fabricated 0 ms would make a silent transit look like the fastest path,
	// and it is also why this field is not a plain float64 — encoding/json
	// cannot represent the +Inf a probe loop uses for "no reply".
	EwmaMs *float64 `json:"ewma_ms,omitempty"`
}

// DecideView is the sending router's decision state. It is advisory: a receiver
// merges it into its own view but never acts on another router's decision.
type DecideView struct {
	Primary  string `json:"primary"`
	Switched bool   `json:"switched"`
	Reason   string `json:"reason"`
	Frozen   bool   `json:"frozen,omitempty"`
}

// Message is a decoded health message.
type Message struct {
	// Version is the envelope's schema_version, or 0 for a legacy frame.
	Version uint32
	// TS and Router come from the envelope, or from the body for a v0 frame.
	TS     time.Time
	Router string
	// Payload is the decoded body. It is the zero value when Known is false.
	Payload HealthPayload
	// Known reports whether this build understood the message's version. A
	// false Known is not an error: the caller counts it (by version) and moves
	// on. It is false exactly when the sender is NEWER than this build.
	Known bool
}

// legacyPayload is the v0 wire shape: the pre-envelope scaffold's message, which
// carried its identity inside the body and had no version frame at all.
//
// v0 is accepted for exactly one rollout and has no forward path: the encoder
// never emits it. It exists so that "new node tolerates old payloads" is a
// property with a test behind it rather than a hope.
type legacyPayload struct {
	Router   string           `json:"router"`
	TS       time.Time        `json:"ts"`
	Transits []TransitSummary `json:"transits,omitempty"`
	Decide   *DecideView      `json:"decide,omitempty"`
}

// ErrEmpty is returned for a zero-length message. It is a distinct sentinel
// because an empty datagram is a transport artifact, not a malformed envelope,
// and the caller may want to count the two differently.
var ErrEmpty = fmt.Errorf("gossip: empty message")

// Encode frames a payload at the current schema version. It is the only encoder
// in the package: nothing else may construct an Envelope, so CurrentSchemaVersion
// is stamped in exactly one place.
func Encode(router string, ts time.Time, p HealthPayload) ([]byte, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("gossip: encoding payload for %q: %w", router, err)
	}
	return json.Marshal(Envelope{
		SchemaVersion: CurrentSchemaVersion,
		TS:            ts.UTC(),
		Router:        router,
		Payload:       body,
	})
}

// Decode parses one wire message.
//
// The rules, in the order they are applied:
//
//  1. A zero-length message is ErrEmpty.
//  2. A document with no schema_version field is a v0 legacy frame and is
//     accepted with Version 0 (see legacyPayload).
//  3. Otherwise the envelope is decoded STRICTLY: an unknown envelope field, a
//     bad type or trailing garbage is an error.
//  4. A schema_version NEWER than CurrentSchemaVersion returns a Message with
//     Known=false and a nil error. The message is ignored, not rejected.
//  5. Otherwise the payload is decoded LENIENTLY: unknown fields are dropped.
//
// The payload's own type is checked: a payload that is not a JSON object cannot
// yield a health view, and silently reading it as "no transits" would turn a
// malformed message into a plausible-looking empty one. That case is an error
// so the caller logs it instead of merging a fiction.
//
// It never panics, whatever the bytes: FuzzGossipDecode holds that.
func Decode(b []byte) (Message, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return Message{}, ErrEmpty
	}

	// (2) Envelope presence probe. This is a lenient decode of a single field on
	// purpose: at this point the document has not been validated yet, and the
	// only question being asked is "is there a version frame at all".
	var probe struct {
		SchemaVersion *uint32 `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return Message{}, fmt.Errorf("gossip: message is not a JSON object: %w", err)
	}
	if probe.SchemaVersion == nil {
		return decodeLegacy(b)
	}

	// (3) Strict envelope.
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Message{}, fmt.Errorf("gossip: malformed envelope: %w", err)
	}
	// DisallowUnknownFields does not catch trailing content, and a second JSON
	// document after the first means the framing is not what it claims to be.
	if err := ensureEOF(dec); err != nil {
		return Message{}, fmt.Errorf("gossip: malformed envelope: %w", err)
	}

	m := Message{Version: env.SchemaVersion, TS: env.TS.UTC(), Router: env.Router}

	// (4) A newer version is not ours to read.
	if env.SchemaVersion > CurrentSchemaVersion {
		return m, nil
	}
	m.Known = true

	// (5) Lenient payload.
	if len(env.Payload) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(env.Payload, &m.Payload); err != nil {
		return m, fmt.Errorf("gossip: payload of v%d message from %q: %w", env.SchemaVersion, env.Router, err)
	}
	return m, nil
}

// decodeLegacy parses a v0 frame: a bare body with its identity inside it.
func decodeLegacy(b []byte) (Message, error) {
	var lp legacyPayload
	// Lenient, for the same reason the v1 payload path is: v0 is the shape we
	// have the least control over, and fields we do not know are not our
	// business.
	if err := json.Unmarshal(b, &lp); err != nil {
		return Message{}, fmt.Errorf("gossip: unversioned message is not a JSON object: %w", err)
	}
	return Message{
		Version: 0,
		TS:      lp.TS.UTC(),
		Router:  lp.Router,
		Payload: HealthPayload{Transits: lp.Transits, Decide: lp.Decide},
		Known:   true,
	}, nil
}

// ensureEOF checks that the decoder consumed the whole document, so a message
// cannot smuggle a second JSON value past the strict envelope check. A clean
// end of input reports io.EOF, which is the success case.
func ensureEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	err := dec.Decode(&extra)
	if err == nil {
		return fmt.Errorf("trailing content after the envelope")
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// FloatPtr returns a pointer to v, for building a TransitSummary whose latency is
// known. It exists so call sites read as "I measured this" rather than sprinkling
// address-of operators, and so the NaN/Inf case is a visible omission instead of
// an accidental 0.
func FloatPtr(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}
