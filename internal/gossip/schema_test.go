package gossip

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// fixedTS is the timestamp every golden fixture and expectation uses, so the
// encoder's output is byte-stable across machines and timezones.
var fixedTS = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// readGolden loads one committed fixture from testdata/golden.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	// The path is a constant directory plus a name chosen by the test, never user
	// input.
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name)) //nolint:gosec // fixed dir, test-chosen name
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return b
}

// TestDecodeGoldenNewPayload is the "this build reads the current schema" half of
// the compatibility contract: a v1 fixture decodes to exactly the values it
// carries.
func TestDecodeGoldenNewPayload(t *testing.T) {
	msg, err := Decode(readGolden(t, "v1-new.json"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !msg.Known || msg.Version != CurrentSchemaVersion {
		t.Fatalf("Known=%t Version=%d, want true/%d", msg.Known, msg.Version, CurrentSchemaVersion)
	}
	if msg.Router != "r-new" {
		t.Errorf("router = %q, want r-new", msg.Router)
	}
	if !msg.TS.Equal(fixedTS) {
		t.Errorf("ts = %v, want %v", msg.TS, fixedTS)
	}
	if len(msg.Payload.Transits) != 2 {
		t.Fatalf("transits = %d, want 2", len(msg.Payload.Transits))
	}
	main := msg.Payload.Transits[0]
	if main.Name != "main" || !main.SessionUp || main.LossPct != 0 {
		t.Errorf("transits[0] = %+v", main)
	}
	if main.EwmaMs == nil || *main.EwmaMs != 12.5 {
		t.Errorf("transits[0].ewma_ms = %v, want 12.5", main.EwmaMs)
	}
	// The second transit has no latency: "not measured" must stay an ABSENT field,
	// never a fabricated 0 ms.
	if msg.Payload.Transits[1].EwmaMs != nil {
		t.Errorf("transits[1].ewma_ms = %v, want nil (unmeasured)", *msg.Payload.Transits[1].EwmaMs)
	}
	if msg.Payload.Decide == nil || msg.Payload.Decide.Primary != "main" || !msg.Payload.Decide.Switched {
		t.Errorf("decide = %+v", msg.Payload.Decide)
	}
}

// TestDecodeGoldenOldPayload is the "new node tolerates an old payload" half,
// and the acceptance criterion from issue #3. A v0 frame carries no envelope, so
// its identity lives in the body; the decoder must read it as Version 0 rather
// than rejecting it, for exactly as long as one rollout takes.
func TestDecodeGoldenOldPayload(t *testing.T) {
	msg, err := Decode(readGolden(t, "v0-old.json"))
	if err != nil {
		t.Fatalf("Decode(v0): %v", err)
	}
	if msg.Version != 0 {
		t.Errorf("version = %d, want 0", msg.Version)
	}
	if !msg.Known {
		t.Error("v0 message reported unknown; this build accepts v0 during a rollout")
	}
	if msg.Router != "r-old" {
		t.Errorf("router = %q, want r-old", msg.Router)
	}
	if len(msg.Payload.Transits) != 1 || msg.Payload.Transits[0].Name != "main" {
		t.Errorf("transits = %+v", msg.Payload.Transits)
	}
	if msg.Payload.Transits[0].EwmaMs == nil || *msg.Payload.Transits[0].EwmaMs != 20 {
		t.Errorf("transits[0].ewma_ms = %v, want 20", msg.Payload.Transits[0].EwmaMs)
	}
}

// TestDecodeGoldenNewerVersionIsIgnored is the rolling-upgrade contract: a peer
// running a schema this build does not know is IGNORED, with no error. The
// envelope is still parsed (so the version can be counted), the payload is not
// read, and Known is false.
func TestDecodeGoldenNewerVersionIsIgnored(t *testing.T) {
	msg, err := Decode(readGolden(t, "v2-unknown.json"))
	if err != nil {
		t.Fatalf("Decode(v2) returned an error %v; an unknown schema version must be ignored, never an error", err)
	}
	if msg.Known {
		t.Error("Known = true for a v2 message; this build only understands v0/v1")
	}
	if msg.Version != 2 {
		t.Errorf("version = %d, want 2 (the envelope is still readable)", msg.Version)
	}
	if msg.Router != "r-future" {
		t.Errorf("router = %q, want r-future", msg.Router)
	}
	// The payload must not be half-decoded into a plausible-looking view.
	if len(msg.Payload.Transits) != 0 || msg.Payload.Decide != nil {
		t.Errorf("payload from a newer version was decoded anyway: %+v", msg.Payload)
	}
}

// TestDecodeGoldenReservedFieldsIgnored exercises the append-only promise with the
// concrete field names the schema document reserves (mtu_state, tcp_signal,
// maintenance, visibility_intent). A future sender can ship them today, before
// this build knows what they mean, and the message is still readable.
func TestDecodeGoldenReservedFieldsIgnored(t *testing.T) {
	msg, err := Decode(readGolden(t, "v1-reserved-fields.json"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !msg.Known || msg.Version != 1 {
		t.Fatalf("Known=%t Version=%d, want true/1", msg.Known, msg.Version)
	}
	if len(msg.Payload.Transits) != 1 || msg.Payload.Transits[0].EwmaMs == nil {
		t.Fatalf("known fields were lost while ignoring reserved ones: %+v", msg.Payload)
	}
}

// TestEncodeGoldenBytes pins the encoder's output for fixed input, byte for byte.
// A change here is a wire change and must be a deliberate one: it is the signal
// that either the schema moved (bump CurrentSchemaVersion and SCHEMA.md) or the
// encoder broke.
func TestEncodeGoldenBytes(t *testing.T) {
	lat := 12.5
	p := HealthPayload{
		Transits: []TransitSummary{
			{Name: "main", SessionUp: true, LossPct: 0, EwmaMs: &lat},
		},
		Decide: &DecideView{Primary: "main", Switched: true, Reason: "initial adoption"},
	}
	got, err := Encode("r-new", fixedTS, p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, readGolden(t, "v1-encode.golden")); err != nil {
		t.Fatalf("compact golden: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), buf.Bytes()) {
		t.Errorf("encoded bytes changed:\n got: %s\nwant: %s", got, buf.Bytes())
	}
}

// TestEncodeStampsCurrentVersion checks the one rule the encoder owns: whatever it
// is given, it stamps CurrentSchemaVersion. Nothing else may construct an Envelope.
func TestEncodeStampsCurrentVersion(t *testing.T) {
	b, err := Encode("r-x", fixedTS, HealthPayload{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schema_version = %d, want %d", env.SchemaVersion, CurrentSchemaVersion)
	}
	if env.Router != "r-x" || !env.TS.Equal(fixedTS) {
		t.Errorf("envelope identity = %q/%v, want r-x/%v", env.Router, env.TS, fixedTS)
	}
}

// TestRoundTrip verifies Encode then Decode reproduces the payload, including the
// absent-latency case: the round trip must not turn "no measurement" into 0.
func TestRoundTrip(t *testing.T) {
	lat := 7.25
	in := HealthPayload{
		Transits: []TransitSummary{
			{Name: "a", SessionUp: true, LossPct: 1.5, EwmaMs: &lat},
			{Name: "b", SessionUp: false, LossPct: 100},
		},
		Decide: &DecideView{Primary: "a", Reason: "incumbent retained", Frozen: true},
	}
	b, err := Encode("r-rt", fixedTS, in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	msg, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msg.Payload.Transits) != 2 {
		t.Fatalf("transits = %d, want 2", len(msg.Payload.Transits))
	}
	if got := msg.Payload.Transits[1]; got.EwmaMs != nil {
		t.Errorf("transit b latency = %v, want nil after a round trip", *got.EwmaMs)
	}
	if msg.Payload.Decide == nil || !msg.Payload.Decide.Frozen {
		t.Errorf("decide = %+v, want frozen", msg.Payload.Decide)
	}
}

// TestDecodeRejectsMalformedEnvelope is the strict half: the envelope is the part
// both ends must agree on, so a bad frame is an error rather than a guess.
func TestDecodeRejectsMalformedEnvelope(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"unknown envelope field", `{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r-x","payload":{},"extra":true}`},
		{"schema_version wrong type", `{"schema_version":"one","ts":"2026-01-01T00:00:00Z","router":"r-x","payload":{}}`},
		{"ts wrong type", `{"schema_version":1,"ts":12345,"router":"r-x","payload":{}}`},
		{"trailing document", `{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r-x","payload":{}}{"a":1}`},
		{"truncated", `{"schema_version":1,"ts":"2026-01-01T00`},
		{"array top level", `[1,2,3]`},
		{"not json", `nope`},
		{"payload is a scalar", `{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r-x","payload":"nope"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// None of these may panic; the fuzz target holds the same invariant.
			msg, err := Decode([]byte(tc.in))
			if err == nil {
				t.Fatalf("Decode(%s) = %+v, want an error", tc.in, msg)
			}
		})
	}
}

// TestDecodeEmpty checks the empty-datagram sentinel: a zero-length message is a
// transport artifact and is reported as itself, not as a malformed envelope.
func TestDecodeEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\t"} {
		_, err := Decode([]byte(in))
		if err == nil {
			t.Fatalf("Decode(%q) = nil error, want ErrEmpty", in)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("Decode(%q) error = %q, want the empty-message sentinel", in, err)
		}
	}
}

// TestDecodeLenientPayload checks the payload half of the policy in the direction
// the append-only rule cares about: unknown payload fields are dropped and the
// known ones survive.
func TestDecodeLenientPayload(t *testing.T) {
	in := `{"schema_version":1,"ts":"2026-01-01T00:00:00Z","router":"r-x","payload":{
		"transits":[{"name":"main","session_up":true,"loss_pct":0,"ewma_ms":9,"future_field":{"a":1},"another":[1,2,3]}],
		"decide":{"primary":"main","switched":false,"reason":"x","future":true},
		"unknown_top":42}}`
	msg, err := Decode([]byte(in))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(msg.Payload.Transits) != 1 {
		t.Fatalf("transits = %d, want 1", len(msg.Payload.Transits))
	}
	tr := msg.Payload.Transits[0]
	if tr.Name != "main" || tr.EwmaMs == nil || *tr.EwmaMs != 9 {
		t.Errorf("transit = %+v, want main/9ms with unknown fields dropped", tr)
	}
	if msg.Payload.Decide == nil || msg.Payload.Decide.Reason != "x" {
		t.Errorf("decide = %+v", msg.Payload.Decide)
	}
}

// TestDecodeUnversionedGarbageIsError checks the v0 fallback is not a hole: an
// unversioned document that is not a JSON object is still an error, so the lenient
// legacy path cannot be used to smuggle arbitrary bytes past the decoder.
func TestDecodeUnversionedGarbageIsError(t *testing.T) {
	for _, in := range []string{`"just a string"`, `[1,2]`, `{"router":`, `{"router":123}`} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%s) = nil error, want an error", in)
		}
	}
}

// TestFloatPtr documents the helper's one job: a value that cannot be encoded
// (NaN, an infinity) becomes an absent field rather than a fabricated zero.
func TestFloatPtr(t *testing.T) {
	if got := FloatPtr(0); got == nil || *got != 0 {
		t.Errorf("FloatPtr(0) = %v, want a pointer to 0", got)
	}
	for name, v := range map[string]float64{
		"nan":  math.NaN(),
		"+inf": math.Inf(1),
		"-inf": math.Inf(-1),
	} {
		if got := FloatPtr(v); got != nil {
			t.Errorf("FloatPtr(%s) = %v, want nil", name, *got)
		}
	}
}

// TestGossipMetricsAreRegistered checks the four metrics the card names are
// exported with the transitd_ prefix and the schema-version label.
func TestGossipMetricsAreRegistered(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A CounterVec with no observed label values is not gathered at all, so the
	// version counter needs a sample before it can be asserted on. That is itself
	// the operator-visible property: a version series exists only once a message
	// of that version arrived.
	metrics.GossipSchemaRx.WithLabelValues("1").Inc()

	names := []string{
		"transitd_gossip_members",
		"transitd_gossip_rx",
		"transitd_gossip_tx",
		"transitd_gossip_schema_rx",
	}
	fams := gatherGossipMetrics(t)
	for _, n := range names {
		if fams[n] == nil {
			t.Errorf("%s is not exported", n)
		}
	}
	fam := fams["transitd_gossip_schema_rx"]
	if fam == nil {
		t.Fatal("transitd_gossip_schema_rx is not exported")
	}
	if v, ok := counterValue(t, fam, "1"); !ok || v < 1 {
		t.Errorf("schema_rx{version=1} = %v (present=%t), want >= 1", v, ok)
	}
}

// gatherGossipMetrics collects the transitd registry by metric family name.
func gatherGossipMetrics(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(fams))
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

// counterValue returns the value of the schema-rx counter for a version label.
func counterValue(t *testing.T, fam *dto.MetricFamily, version string) (float64, bool) {
	t.Helper()
	if fam == nil {
		return 0, false
	}
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == metrics.LabelSchemaVersion && lp.GetValue() == version {
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}
