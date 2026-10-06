// Package bgpwatch polls a router's FRR BGP state over vtysh and turns it into
// typed observations (issue #4).
//
// It is READ-ONLY by construction. Every command it issues is a `show`
// command; there is no configure path in this package, so bgpwatch can never be
// the thing that changed a router. The wiring in internal/agent keeps the same
// property at the call site (see TestAgentIsObserveOnly), and TestSourceIssues-
// NoMutatingCommand enforces it here.
//
// Polling is bounded. The session view (`show bgp summary json`) is small and
// always parsed in full. The prefix-level views (`show bgp <af> unicast json`)
// are capped at config bgpwatch.max_prefixes: a table larger than the cap is a
// hard error, never a silent truncation, because a truncated RIB would make
// "does peer X see prefix P" answer a confident "no" about a prefix the parser
// simply never read. The cadence is floored at 1 Hz (config.MinBGPWatchInterval)
// because a full-table JSON dump is expensive on a 1 vCPU router.
//
// Every parser here is pinned to the FRR 10.7.1 `show ... json` shape by golden
// fixtures under testdata/. The fixtures are hand-written to match the
// documented field set (FRR docs + the shape the compose lab emits); no real
// capture is committed.
package bgpwatch

import "time"

// SessionState is one BGP neighbor's session state, as FRR reports it.
//
// FRR exposes two related strings: `state` is the machine state ("Established",
// "Idle (Admin)", "Active", ...) and `peerState` is a coarse human summary
// ("OK", "No route to peer", ...). The machine state is what carries meaning, so
// it is what a Session keeps; peerState is only a fallback for a build that
// omits `state`.
type SessionState string

const (
	// StateEstablished is the only state in which a session is usable.
	StateEstablished SessionState = "Established"
	// StateIdleAdmin is what `neighbor <ip> shutdown` produces: administratively
	// down. It is a distinct string from a general Idle so a drill can tell its
	// own injection from a real failure.
	StateIdleAdmin SessionState = "Idle (Admin)"
)

// Session is one neighbor's observed BGP session state.
type Session struct {
	// Neighbor is the peer address, the key in `show bgp summary json`.
	Neighbor string
	// State is the machine state (see SessionState).
	State SessionState
	// Up is the derived boolean the decision engine consumes: true only for
	// StateEstablished. Everything else — Idle, Active, Connect, a shutdown —
	// is not a usable session.
	Up bool
	// PfxRcvd is the prefix count received from this peer (pfxRcd), and PfxSnt
	// the count advertised to it. Both are diagnostics: a session that is up
	// with zero received prefixes is a different (and interesting) condition
	// from one with routes.
	PfxRcvd int
	PfxSnt  int
	// Uptime is the session uptime string as FRR prints it, e.g. "00:00:24".
	// It is reported raw, not parsed into a duration: FRR's format changes
	// across minors and a re-established session is detected by state, not by
	// parsing this.
	Uptime string
	// EstablishedAt is the epoch at which the session last established, from
	// peerUptimeEstablishedEpoch. Zero when the peer is not up.
	EstablishedAt time.Time
}

// Summary is the parsed `show bgp summary json` for one address family.
type Summary struct {
	// RouterID and LocalAS identify the router as BGP sees it.
	RouterID string
	LocalAS  int
	// Sessions is keyed by neighbor address.
	Sessions map[string]Session
}

// Prefix is one prefix in a prefix-level view, with the paths FRR holds for it.
type Prefix struct {
	// Network is the prefix in CIDR form, e.g. "198.51.100.0/24".
	Network string
	// Paths is every path FRR holds for this prefix (Adj-RIB-In plus locally
	// originated). A prefix present with zero paths is not representable: FRR
	// omits it entirely.
	Paths []Path
	// TotalPrefixes is the size of the whole table this prefix was parsed from,
	// whether or not the cap allowed all of it through. It lets a caller tell
	// "the table has 40k prefixes and we refused to parse it" from "the table
	// has 12 prefixes". On a refused parse there is no Prefix at all — the
	// error carries the count.
	TotalPrefixes int
}

// Path is one path for a prefix, from `show bgp <af> unicast json`.
type Path struct {
	// Valid is FRR's validity flag: the path is usable.
	Valid bool
	// BestPath is true for the path FRR selected.
	BestPath bool
	// ASPath is the AS path in FRR's space-joined string form, e.g. "64511 64498".
	// It is empty for a locally originated route.
	ASPath string
	// PeerID is the peer the path was learned from, or "" for a local route.
	PeerID string
	// NextHop is the first nexthop IP of the path, "" when FRR reports none.
	NextHop string
	// LocalPref is the path's LOCAL_PREF as FRR reports it (0 when absent).
	LocalPref int
}

// BestPath is the answer to `show bgp <af> <prefix> json`.
type BestPath struct {
	// Network is the queried prefix in CIDR form.
	Network string
	// Exists is false when FRR holds no path for the prefix at all (the query
	// returns {}), which is a legitimate answer, not an error.
	Exists bool
	// PathCount is the number of paths FRR holds for the prefix.
	PathCount int
	// Best is the selected path when one is marked bestpath; nil when PathCount
	// is 0.
	Best *Path
}
