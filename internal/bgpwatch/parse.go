package bgpwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrRateLimited is returned by a poll that arrived inside the 1 Hz window.
var ErrRateLimited = errors.New("bgpwatch: poll rate-limited (1 Hz cap)")

// ErrTooManyPrefixes is returned when a prefix-level view holds more prefixes
// than the configured cap. It is deliberately not a truncation: the caller gets
// no data and a count, so it cannot mistake "we did not read the whole table"
// for "the table does not contain the prefix".
type ErrTooManyPrefixes struct {
	// Total is the number of prefixes FRR reported.
	Total int
	// Cap is the configured maximum.
	Cap int
}

func (e ErrTooManyPrefixes) Error() string {
	return fmt.Sprintf("bgpwatch: table holds %d prefixes, over the configured cap of %d — refusing to parse a partial RIB (raise the bgpwatch prefix cap)", e.Total, e.Cap)
}

// summaryJSON mirrors the subset of `show bgp summary json` this package reads.
// Unknown keys are ignored by encoding/json, so an FRR minor that adds fields
// does not break the parser; the fields read here are pinned by the golden
// fixtures under testdata/.
type summaryJSON struct {
	IPv4Unicast afSummary `json:"ipv4Unicast"`
	IPv6Unicast afSummary `json:"ipv6Unicast"`
}

type afSummary struct {
	RouterID string              `json:"routerId"`
	AS       int                 `json:"as"`
	Peers    map[string]peerJSON `json:"peers"`
}

type peerJSON struct {
	State            string `json:"state"`
	PeerState        string `json:"peerState"`
	PfxRcvd          int    `json:"pfxRcd"`
	PfxSnt           int    `json:"pfxSnt"`
	PeerUptime       string `json:"peerUptime"`
	EstablishedEpoch int64  `json:"peerUptimeEstablishedEpoch"`
}

// ParseSummary parses `show bgp summary json` into the IPv4 unicast session
// view. The neighbor key is the map key FRR uses (the peer address), not a field
// in the peer object, so it is copied across explicitly.
//
// Every peer present in the JSON produces a Session, including ones in a down
// state — the absence of a session and the presence of a down session are
// different facts and only the second belongs to a configured neighbor.
func ParseSummary(raw string) (Summary, error) {
	var s summaryJSON
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return Summary{}, fmt.Errorf("bgpwatch: parsing `show bgp summary json`: %w", err)
	}
	out := Summary{
		RouterID: s.IPv4Unicast.RouterID,
		LocalAS:  s.IPv4Unicast.AS,
		Sessions: make(map[string]Session, len(s.IPv4Unicast.Peers)),
	}
	for addr, p := range s.IPv4Unicast.Peers {
		out.Sessions[addr] = sessionFrom(addr, p)
	}
	return out, nil
}

// ParseSummaryV6 parses the IPv6 unicast block of `show bgp summary json`.
func ParseSummaryV6(raw string) (Summary, error) {
	var s summaryJSON
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return Summary{}, fmt.Errorf("bgpwatch: parsing `show bgp summary json`: %w", err)
	}
	out := Summary{
		RouterID: s.IPv6Unicast.RouterID,
		LocalAS:  s.IPv6Unicast.AS,
		Sessions: make(map[string]Session, len(s.IPv6Unicast.Peers)),
	}
	for addr, p := range s.IPv6Unicast.Peers {
		out.Sessions[addr] = sessionFrom(addr, p)
	}
	return out, nil
}

// StateOK is the coarse peerState value FRR prints for a healthy session. It is
// only consulted when the machine `state` field is absent.
const StateOK SessionState = "OK"

// sessionFrom maps one peer object onto a Session. The machine state is
// preferred; `peerState` ("OK") is only a fallback for a build that omits
// `state`. Up is derived from the state string, so a state value this build does
// not know is treated as not-up rather than optimistically healthy.
func sessionFrom(addr string, p peerJSON) Session {
	state := SessionState(p.State)
	if state == "" {
		state = SessionState(p.PeerState)
	}
	s := Session{
		Neighbor: addr,
		State:    state,
		Up:       state == StateEstablished || state == StateOK,
		PfxRcvd:  p.PfxRcvd,
		PfxSnt:   p.PfxSnt,
		Uptime:   p.PeerUptime,
	}
	if p.EstablishedEpoch > 0 {
		s.EstablishedAt = time.Unix(p.EstablishedEpoch, 0)
	}
	return s
}

// routesJSON mirrors `show bgp <af> unicast json`. `routes` maps a CIDR prefix
// to the list of paths FRR holds for it.
type routesJSON struct {
	Routes map[string][]pathJSON `json:"routes"`
	// TotalRoutes is the table size FRR reports. When a `routes` key is present
	// it equals len(Routes); it is read separately so the cap check can fire on
	// the count FRR advertises even if the map were ever trimmed.
	TotalRoutes int `json:"totalRoutes"`
}

type pathJSON struct {
	Valid     bool        `json:"valid"`
	BestPath  bool        `json:"bestpath"`
	PeerID    string      `json:"peerId"`
	Path      string      `json:"path"`
	Nexthops  []nextHopJS `json:"nexthops"`
	LocalPref int         `json:"localPref"`
}

type nextHopJS struct {
	IP string `json:"ip"`
}

// ParsePrefixes parses `show bgp <af> unicast json` into a prefix list, refusing
// a table larger than cap with ErrTooManyPrefixes.
//
// The cap is checked against the larger of the advertised total and the number
// of keys actually present, so neither a huge table nor a mangled `totalRoutes`
// can slip past the bound.
func ParsePrefixes(raw string, cap int) ([]Prefix, error) {
	var r routesJSON
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("bgpwatch: parsing prefix view: %w", err)
	}
	total := r.TotalRoutes
	if n := len(r.Routes); n > total {
		total = n
	}
	if cap > 0 && total > cap {
		return nil, ErrTooManyPrefixes{Total: total, Cap: cap}
	}
	out := make([]Prefix, 0, len(r.Routes))
	for network, paths := range r.Routes {
		p := Prefix{Network: network, TotalPrefixes: total}
		for _, pj := range paths {
			p.Paths = append(p.Paths, pathFrom(pj))
		}
		out = append(out, p)
	}
	return out, nil
}

// FindPrefix returns the prefix with the given network from a parsed view.
func FindPrefix(prefixes []Prefix, network string) (Prefix, bool) {
	for _, p := range prefixes {
		if p.Network == network {
			return p, true
		}
	}
	return Prefix{}, false
}

// bestPathJSON mirrors `show bgp <af> <prefix> json`. A prefix FRR does not know
// about is the empty object `{}`, which decodes to the zero value here.
//
// This document's path shape differs from the prefix-level view's in two ways
// that matter: the AS path is nested under an `aspath` object with a `string`
// field rather than a flat `path`, and `bestpath` is an object (with an
// `overall` flag) rather than a boolean. The two views are therefore parsed with
// separate types rather than one shared struct with optional fields.
type bestPathJSON struct {
	Prefix    string             `json:"prefix"`
	PathCount int                `json:"pathCount"`
	Paths     []bestPathPathJSON `json:"paths"`
}

type bestPathPathJSON struct {
	ASPath struct {
		String string `json:"string"`
	} `json:"aspath"`
	Valid    bool `json:"valid"`
	BestPath struct {
		Overall bool `json:"overall"`
	} `json:"bestpath"`
	Nexthops []nextHopJS `json:"nexthops"`
	Peer     struct {
		PeerID string `json:"peerId"`
	} `json:"peer"`
}

// ParseBestPath parses the bestpath query for one prefix. A prefix with no paths
// is a valid answer (Exists=false), not an error: FRR answers `{}` for a prefix
// it does not hold.
func ParseBestPath(raw, prefix string) (BestPath, error) {
	trimmed := strings.TrimSpace(raw)
	bp := BestPath{Network: prefix}
	if trimmed == "" || trimmed == "{}" {
		return bp, nil
	}
	var j bestPathJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		return bp, fmt.Errorf("bgpwatch: parsing bestpath for %s: %w", prefix, err)
	}
	if j.Prefix != "" {
		bp.Network = j.Prefix
	}
	bp.PathCount = j.PathCount
	if n := len(j.Paths); n > bp.PathCount {
		bp.PathCount = n
	}
	bp.Exists = bp.PathCount > 0
	if len(j.Paths) > 0 {
		// The best path is the one FRR flags with bestpath.overall; if none is
		// flagged (a race with a withdraw), the first path is the fallback, since
		// FRR orders them by preference.
		best := pathFromBest(j.Paths[0])
		for _, pj := range j.Paths {
			if pj.BestPath.Overall {
				best = pathFromBest(pj)
				break
			}
		}
		bp.Best = &best
	}
	return bp, nil
}

// pathFromBest maps one path object from the bestpath view onto a Path.
func pathFromBest(p bestPathPathJSON) Path {
	out := Path{
		Valid:    p.Valid,
		ASPath:   p.ASPath.String,
		PeerID:   p.Peer.PeerID,
		BestPath: p.BestPath.Overall,
	}
	if len(p.Nexthops) > 0 {
		out.NextHop = p.Nexthops[0].IP
	}
	return out
}

// pathFrom maps one path object from either view onto a Path. NextHop takes the
// first nexthop FRR lists; LocalPref comes from the field of that name when
// present (the summary view omits it and it decodes to 0).
func pathFrom(p pathJSON) Path {
	out := Path{
		Valid:     p.Valid,
		BestPath:  p.BestPath,
		ASPath:    p.Path,
		PeerID:    p.PeerID,
		LocalPref: p.LocalPref,
	}
	if len(p.Nexthops) > 0 {
		out.NextHop = p.Nexthops[0].IP
	}
	return out
}

// ASPathContains reports whether any of the given paths carries asn in its AS
// path. It is the predicate behind "does peer X see prefix P via AS Y": the
// drill's announcement measurement (docs/design/feature-1-drill.md §5).
func ASPathContains(paths []Path, asn int) bool {
	want := strconv.Itoa(asn)
	for _, p := range paths {
		for _, field := range strings.Fields(p.ASPath) {
			if field == want {
				return true
			}
		}
	}
	return false
}
