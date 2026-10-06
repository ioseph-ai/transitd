package gossip

import (
	"testing"
)

// FuzzGossipDecode drives the decode path with arbitrary bytes.
//
// The gossip delegate is reachable by anyone who holds the shared key, and the
// bytes arrive over UDP, so the decoder is an untrusted-input parser by
// definition. The invariant is blunt and absolute: Decode must NEVER panic. A
// panic inside memberlist's receive loop takes the whole mesh down on one bad
// datagram, which is precisely the availability failure the mesh must not have.
//
// The seed corpus is committed under testdata/fuzz/FuzzGossipDecode and runs on
// every plain `go test` (Go replays the corpus as regression cases), so a crasher
// found by the weekly fuzz job (issue #18) lands as a corpus file and becomes a
// regression test for free. Regenerate/extend the corpus with
// `go test ./internal/gossip -run FuzzGossipDecode -fuzz FuzzGossipDecode -fuzztime 60s`
// and commit whatever new files appear.
func FuzzGossipDecode(f *testing.F) {
	// In-code seeds are the readable, self-documenting part of the corpus; the
	// committed files under testdata/fuzz are the durable part. Both run.
	seeds := []string{
		// The four shapes that must be ACCEPTED, so the fuzzer's accept-path is
		// exercised and not just its error handling.
		`{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r-x","payload":{"transits":[{"name":"main","session_up":true,"loss_pct":0,"ewma_ms":1.5}]}}`,
		`{"router":"r-old","ts":"2026-01-01T00:00:00Z","transits":[{"name":"main","session_up":true}]}`,
		`{"schema_version":4294967295,"ts":"2026-01-01T00:00:00Z","router":"r-max","payload":{}}`,
		`{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r-x","payload":{"mtu_state":{"main":1500}}}`,
		// The shapes that must be rejected without panicking.
		``,
		`{`,
		`[]`,
		`null`,
		`{"schema_version":"x"}`,
		`{"schema_version":1,"payload":"scalar"}`,
		`{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r","payload":{"transits":[`,
		"{\"schema_version\":1}\x00\xff\xfe",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		// Decode must be total. When it returns a Message it must be internally
		// consistent: Known implies a version this build understands, and a nil
		// error must never accompany an inconsistent pair.
		msg, err := Decode(b)
		if err != nil {
			return
		}
		if msg.Known && msg.Version > CurrentSchemaVersion {
			t.Fatalf("Known=true for version %d (> current %d): % x", msg.Version, CurrentSchemaVersion, b)
		}
		if !msg.Known && msg.Version <= CurrentSchemaVersion {
			t.Fatalf("Known=false for version %d (<= current %d): % x", msg.Version, CurrentSchemaVersion, b)
		}
		// A decoded message must be re-encodable at the current version. This is the
		// round-trip half of the append-only policy: whatever an old peer sends, the
		// content this build keeps can be re-gossiped forward.
		if !msg.Known {
			return
		}
		if _, err := Encode(msg.Router, msg.TS, msg.Payload); err != nil {
			t.Fatalf("re-encode of a decoded message failed: %v (input % x)", err, b)
		}
	})
}
