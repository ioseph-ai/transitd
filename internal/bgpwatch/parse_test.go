package bgpwatch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a committed golden parser fixture. The fixtures under testdata/
// are hand-written to the FRR 10.7.1 `show ... json` field set; no real capture is
// committed.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // committed fixture, fixed dir
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

// TestParseSummaryGolden pins the summary parser against the exact document FRR
// 10.7.1 emits: the neighbor map key becomes the Session key, machine state maps
// to Up, and pfxRcd/pfxSnt/uptime survive.
func TestParseSummaryGolden(t *testing.T) {
	s, err := ParseSummary(fixture(t, "summary-established.json"))
	if err != nil {
		t.Fatalf("ParseSummary: %v", err)
	}
	if s.RouterID != "192.0.2.2" || s.LocalAS != 64496 {
		t.Errorf("routerId/as = %q/%d, want 192.0.2.2/64496", s.RouterID, s.LocalAS)
	}
	if len(s.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(s.Sessions))
	}

	r2, ok := s.Sessions["192.0.2.3"]
	if !ok {
		t.Fatal("neighbor 192.0.2.3 missing from the session map")
	}
	if !r2.Up || r2.State != StateEstablished {
		t.Errorf("r2 session = %+v, want up/Established", r2)
	}
	if r2.PfxRcvd != 0 || r2.PfxSnt != 2 {
		t.Errorf("r2 pfxRcvd/pfxSnt = %d/%d, want 0/2", r2.PfxRcvd, r2.PfxSnt)
	}
	if r2.Uptime != "00:00:24" {
		t.Errorf("r2 uptime = %q, want 00:00:24", r2.Uptime)
	}
	if r2.EstablishedAt.IsZero() {
		t.Error("r2 established epoch did not decode")
	}

	exa := s.Sessions["192.0.2.11"]
	if !exa.Up || exa.PfxRcvd != 1 {
		t.Errorf("exabgp session = %+v, want up with 1 received prefix", exa)
	}
}

// TestParseSummaryShutdownIsNotUp is the shutdown half: `neighbor <ip> shutdown`
// produces "Idle (Admin)", which must map to Up=false. A session that is
// administratively down is not a usable transit, and the drill's round-trip
// assertion reads exactly this.
func TestParseSummaryShutdownIsNotUp(t *testing.T) {
	s, err := ParseSummary(fixture(t, "summary-shutdown.json"))
	if err != nil {
		t.Fatalf("ParseSummary: %v", err)
	}
	down := s.Sessions["192.0.2.3"]
	if down.Up {
		t.Errorf("shut-down neighbor reported Up=true: %+v", down)
	}
	if down.State != StateIdleAdmin {
		t.Errorf("state = %q, want %q", down.State, StateIdleAdmin)
	}
	// The OTHER neighbor must be untouched: a shutdown of one peer is not a
	// router-wide outage.
	if !s.Sessions["192.0.2.11"].Up {
		t.Error("shutting one neighbor down also reported its peer down")
	}
}

// TestParseSummaryUnknownStateIsNotUp is the conservative default: a state string
// this build does not recognise must never be treated as healthy. Anything other
// than "Established" is not a session the agent will rank.
func TestParseSummaryUnknownStateIsNotUp(t *testing.T) {
	raw := `{"ipv4Unicast":{"routerId":"192.0.2.2","as":64496,"peers":{
	  "192.0.2.3":{"state":"Active","peerState":"No route to peer","pfxRcd":0,"pfxSnt":0}}}}`
	s, err := ParseSummary(raw)
	if err != nil {
		t.Fatalf("ParseSummary: %v", err)
	}
	if s.Sessions["192.0.2.3"].Up {
		t.Errorf("Active state reported Up=true: %+v", s.Sessions["192.0.2.3"])
	}
}

// TestParseSummaryFallsBackToPeerState covers a build that omits `state`: the
// coarse peerState is used, and "OK" is the only value that maps to Up.
func TestParseSummaryFallsBackToPeerState(t *testing.T) {
	raw := `{"ipv4Unicast":{"routerId":"192.0.2.2","as":64496,"peers":{
	  "192.0.2.3":{"peerState":"OK","pfxRcd":3,"pfxSnt":1}}}}`
	s, err := ParseSummary(raw)
	if err != nil {
		t.Fatalf("ParseSummary: %v", err)
	}
	if !s.Sessions["192.0.2.3"].Up {
		t.Errorf("peerState OK fallback did not map to Up: %+v", s.Sessions["192.0.2.3"])
	}
}

// TestParseSummaryRejectsNonJSON pins the error path: a parser that returned an
// empty Summary on garbage would look like "no BGP sessions", which is exactly the
// confident-wrong answer this package exists to avoid.
func TestParseSummaryRejectsNonJSON(t *testing.T) {
	if _, err := ParseSummary("% Invalid input detected"); err == nil {
		t.Fatal("expected an error for non-JSON summary output")
	}
}

// TestParseSummaryV6 reads the ipv6Unicast block, proving the v6 session view is
// covered by the same code path.
func TestParseSummaryV6(t *testing.T) {
	raw := `{"ipv6Unicast":{"routerId":"192.0.2.2","as":64496,"peers":{
	  "2001:db8::3":{"state":"Established","peerState":"OK","pfxRcd":4,"pfxSnt":5,"peerUptime":"00:01:00"}}}}`
	s, err := ParseSummaryV6(raw)
	if err != nil {
		t.Fatalf("ParseSummaryV6: %v", err)
	}
	if len(s.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(s.Sessions))
	}
	v6 := s.Sessions["2001:db8::3"]
	if !v6.Up || v6.PfxRcvd != 4 {
		t.Errorf("v6 session = %+v, want up with 4 received", v6)
	}
}

// TestParsePrefixesGolden pins the prefix-level parser against the real shape:
// routes is a map from CIDR to a path array, the AS path arrives space-joined, and
// the nexthop of interest is the first entry.
func TestParsePrefixesGolden(t *testing.T) {
	prefixes, err := ParsePrefixes(fixture(t, "routes-ipv4.json"), 1000)
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %d, want 2", len(prefixes))
	}

	p, ok := FindPrefix(prefixes, "198.51.100.0/24")
	if !ok {
		t.Fatal("198.51.100.0/24 missing from the parsed view")
	}
	if p.TotalPrefixes != 2 {
		t.Errorf("TotalPrefixes = %d, want 2", p.TotalPrefixes)
	}
	if len(p.Paths) != 1 {
		t.Fatalf("paths = %d, want 1", len(p.Paths))
	}
	path := p.Paths[0]
	if !path.Valid || !path.BestPath {
		t.Errorf("path = %+v, want valid+bestpath", path)
	}
	if path.ASPath != "64511 64498" {
		t.Errorf("ASPath = %q, want %q", path.ASPath, "64511 64498")
	}
	if path.PeerID != "192.0.2.11" || path.NextHop != "192.0.2.11" {
		t.Errorf("peer/nexthop = %q/%q", path.PeerID, path.NextHop)
	}
	if !ASPathContains(p.Paths, 64498) {
		t.Error("ASPathContains(64498) = false on a path whose AS path is 64511 64498")
	}
	if ASPathContains(p.Paths, 64512) {
		t.Error("ASPathContains(64512) = true on a path that does not carry it")
	}

	// The locally originated prefix has an empty AS path and an (unspec) peer.
	local, ok := FindPrefix(prefixes, "203.0.113.1/32")
	if !ok {
		t.Fatal("203.0.113.1/32 missing")
	}
	if local.Paths[0].ASPath != "" {
		t.Errorf("local prefix AS path = %q, want empty", local.Paths[0].ASPath)
	}
	if ASPathContains(local.Paths, 64496) {
		t.Error("ASPathContains found an ASN in a locally originated (empty) AS path")
	}
}

// TestParsePrefixesEmptyTable is the empty-view case: an AF with no routes must
// parse to an empty slice, not an error. An IPv6 view with nothing in it is a
// legitimate answer.
func TestParsePrefixesEmptyTable(t *testing.T) {
	prefixes, err := ParsePrefixes(fixture(t, "routes-ipv6-empty.json"), 1000)
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	if len(prefixes) != 0 {
		t.Errorf("prefixes = %d, want 0", len(prefixes))
	}
}

// TestParsePrefixesCapIsErrorNotTruncation is the bound's core promise: a table
// larger than the cap must ERROR and return nothing, never a silently truncated
// subset. A truncated RIB would make "does peer X see prefix P" answer a
// confident no about a prefix the parser never read.
func TestParsePrefixesCapIsErrorNotTruncation(t *testing.T) {
	_, err := ParsePrefixes(fixture(t, "routes-too-many.json"), 3)
	if err == nil {
		t.Fatal("expected an error for a table over the prefix cap")
	}
	var tooMany ErrTooManyPrefixes
	if !errors.As(err, &tooMany) {
		t.Fatalf("error %v is not ErrTooManyPrefixes", err)
	}
	if tooMany.Total != 5 || tooMany.Cap != 3 {
		t.Errorf("ErrTooManyPrefixes = %+v, want Total=5 Cap=3", tooMany)
	}
	if !strings.Contains(err.Error(), "partial RIB") {
		t.Errorf("error %q does not explain the refusal", err)
	}

	// The exact cap is fine: the bound is "over the cap", not "at the cap".
	if _, err := ParsePrefixes(fixture(t, "routes-too-many.json"), 5); err != nil {
		t.Errorf("a table exactly at the cap was refused: %v", err)
	}
}

// TestParseBestPathPresent pins the bestpath single-prefix parser, whose document
// nests the path under `paths` with the AS path under `aspath.string`.
func TestParseBestPathPresent(t *testing.T) {
	bp, err := ParseBestPath(fixture(t, "bestpath-present.json"), "198.51.100.0/24")
	if err != nil {
		t.Fatalf("ParseBestPath: %v", err)
	}
	if !bp.Exists {
		t.Fatal("Exists = false for a prefix FRR holds")
	}
	if bp.Network != "198.51.100.0/24" || bp.PathCount != 1 {
		t.Errorf("network/pathCount = %q/%d", bp.Network, bp.PathCount)
	}
	if bp.Best == nil {
		t.Fatal("Best is nil for a single-path prefix")
	}
	if !bp.Best.Valid || bp.Best.ASPath != "64511 64498" || bp.Best.PeerID != "192.0.2.11" {
		t.Errorf("Best = %+v", bp.Best)
	}
}

// TestParseBestPathAbsent is the negative case: FRR answers `{}` for a prefix it
// does not hold. That is a valid answer (Exists=false), not an error — the
// difference between "not present" and "could not tell" matters.
func TestParseBestPathAbsent(t *testing.T) {
	bp, err := ParseBestPath(fixture(t, "bestpath-absent.json"), "192.0.2.200/32")
	if err != nil {
		t.Fatalf("ParseBestPath: %v", err)
	}
	if bp.Exists {
		t.Error("Exists = true for the empty object FRR returns for an unknown prefix")
	}
	if bp.PathCount != 0 || bp.Best != nil {
		t.Errorf("absent prefix = %+v, want no paths", bp)
	}
	if bp.Network != "192.0.2.200/32" {
		t.Errorf("Network = %q, want the queried prefix echoed back", bp.Network)
	}
}
