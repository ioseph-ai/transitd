//go:build integration

// Package integration holds transitd's end-to-end tests. They are guarded by
// the `integration` build tag so `go test ./...` (the unit tier) never needs
// docker: only `go test -tags=integration ./test/...` runs them.
//
// The lab these tests drive lives in test/compose.yaml (r1 + r2 FRR, one
// exabgp injector). The tests bring the lab up themselves and always tear it
// down, so a developer or CI job only needs a docker daemon; nothing has to be
// started beforehand.
package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// convergenceTimeout bounds how long we wait for BGP to converge. FRR
	// normally converges in a couple of seconds; the budget is generous because
	// a CI runner is slow and image/network setup happens around it. A timeout
	// is a hard failure — a first miss is never treated as the answer.
	convergenceTimeout = 120 * time.Second

	// pollInterval is the wait-for-convergence poll period.
	pollInterval = 1 * time.Second

	// r1ASN is the iBGP ASN shared by the two routers (RFC 5398 doc range).
	r1ASN = 64496

	// injectorASN is exabgp's ASN in the lab (RFC 6996 doc range).
	injectorASN = 64511

	// injectedPrefix is what exabgp announces into r1 (RFC 5737 TEST-NET-2).
	injectedPrefix = "198.51.100.0/24"

	// r1OwnPrefix is the prefix r1 originates on its loopback (TEST-NET-3) and
	// redistributes to its iBGP peer r2.
	r1OwnPrefix = "203.0.113.1/32"

	// Lab peer addresses as seen on r1 (see test/compose.yaml, test/frr/r1/frr.conf).
	r1PeerR2     = "192.0.2.3"
	r1PeerInject = "192.0.2.11"

	// r1RouterID is r1's configured router-id.
	r1RouterID = "192.0.2.2"
)

// composeFile is the absolute path to the lab's compose file, derived from this
// source file so the tests work no matter which directory `go test` runs from.
var composeFile = func() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot locate seed_test.go via runtime.Caller")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "compose.yaml")
}()

// TestMain brings the compose lab up, runs the integration tests, and always
// tears the lab down (`down -v` also drops the lab's networks).
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "integration tests need a docker client on PATH:", err)
		os.Exit(1)
	}

	if out, err := compose("up", "-d", "--wait"); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose up failed: %v\n%s", err, out)
		_, _ = compose("down", "-v") // best-effort cleanup of a half-started lab
		os.Exit(1)
	}

	code := m.Run()

	if out, err := compose("down", "-v"); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose down failed (lab may need manual cleanup): %v\n%s", err, out)
	}
	os.Exit(code)
}

// TestBGPSessionEstablished seeds the integration tier: r1's BGP sessions —
// the iBGP session to r2 (proving router-to-router config) and the eBGP session
// to the exabgp injector (proving an external speaker connects) — must both
// reach Established within the convergence budget.
func TestBGPSessionEstablished(t *testing.T) {
	summary := waitForPeersEstablished(t, "r1", []string{r1PeerR2, r1PeerInject})

	if got := summary.IPv4Unicast.AS; got != r1ASN {
		t.Errorf("r1 local AS = %d, want %d", got, r1ASN)
	}
	if got := summary.IPv4Unicast.RouterID; got != r1RouterID {
		t.Errorf("r1 router-id = %q, want %q", got, r1RouterID)
	}
}

// TestR2SeesR1Prefix checks the iBGP direction: the prefix r1 originates on its
// loopback must be advertised to r2. (No AS-path assertion: an internal route
// legitimately has an empty path.)
func TestR2SeesR1Prefix(t *testing.T) {
	waitForPeersEstablished(t, "r1", []string{r1PeerR2})

	routes := waitForPrefix(t, "r2", r1OwnPrefix, 0)
	t.Logf("r2 sees %s with as-path %q", r1OwnPrefix, routes.Routes[r1OwnPrefix][0].Path)
}

// TestExabgpPrefixReachesR1 is the seed end-to-end assertion: the prefix the
// exabgp injector announces must appear in r1's Loc-RIB *and* carry the
// injector's ASN in its AS path. Parsing the vtysh JSON into the minimal structs
// below is also the seed for a future standalone vtysh parser package.
func TestExabgpPrefixReachesR1(t *testing.T) {
	waitForPeersEstablished(t, "r1", []string{r1PeerInject})

	routes := waitForPrefix(t, "r1", injectedPrefix, injectorASN)
	t.Logf("r1 received %s with as-path %q", injectedPrefix, routes.Routes[injectedPrefix][0].Path)
}

// bgpSummary is the minimal slice of `show bgp summary json` this package
// parses. It is deliberately small and documented. Unknown fields are ignored
// by encoding/json, so an FRR minor that adds keys does not break us; the
// fields we DO read are asserted by the tests above. The shape is pinned to the
// FRR minor in test/compose.yaml (10.7.1).
type bgpSummary struct {
	IPv4Unicast struct {
		RouterID string `json:"routerId"`
		AS       int    `json:"as"`
		Peers    map[string]struct {
			State string `json:"state"`
			// peerState is the human-readable variant ("OK"), not the
			// Established/Down machine state, but read it as a fallback in
			// case a minor drops `state`.
			PeerState string `json:"peerState"`
		} `json:"peers"`
	} `json:"ipv4Unicast"`
}

// peerState returns the state string for a peer, preferring the machine state.
func (s bgpSummary) peerState(addr string) (string, bool) {
	p, ok := s.IPv4Unicast.Peers[addr]
	if !ok {
		return "", false
	}
	if p.State != "" {
		return p.State, true
	}
	return p.PeerState, p.PeerState != ""
}

// bgpPath is one path for a prefix in `show bgp ipv4 unicast json`. The AS path
// arrives as the space-joined string in Path (e.g. "64511 64498").
type bgpPath struct {
	Valid  bool   `json:"valid"`
	Path   string `json:"path"`
	PeerID string `json:"peerId"`
}

// bgpRoutes is the minimal slice of `show bgp ipv4 unicast json`: each prefix
// maps to the list of paths FRR holds for it. FRR 10.7.1 returns a JSON array
// here even for a single path — this parser is pinned to that minor, which is
// why the image in test/compose.yaml is digest-locked.
type bgpRoutes struct {
	Routes map[string][]bgpPath `json:"routes"`
}

// showBGPSummary fetches and parses a container's BGP summary.
func showBGPSummary(container string) (bgpSummary, error) {
	var s bgpSummary
	out, err := vtysh(container, "show bgp summary json")
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return s, fmt.Errorf("parsing `show bgp summary json` from %s: %w (raw: %s)", container, err, truncate(out))
	}
	return s, nil
}

// waitForPeersEstablished polls `show bgp summary json` until every address in
// waitFor reports Established, and returns the last parsed summary. It fails on
// timeout (with the last observed state, so the failure is diagnosable) — a
// single miss is never fatal by itself.
func waitForPeersEstablished(t *testing.T, container string, waitFor []string) bgpSummary {
	t.Helper()

	deadline := time.Now().Add(convergenceTimeout)
	var lastErr error

	for {
		summary, err := showBGPSummary(container)
		if err == nil {
			allUp := true
			for _, addr := range waitFor {
				state, ok := summary.peerState(addr)
				if !ok {
					lastErr = fmt.Errorf("peer %s not in summary yet", addr)
					allUp = false
					break
				}
				if state != "Established" {
					lastErr = fmt.Errorf("peer %s state=%q", addr, state)
					allUp = false
					break
				}
			}
			if allUp {
				return summary
			}
		} else {
			lastErr = err
		}

		if time.Now().After(deadline) {
			t.Fatalf("BGP did not converge on %s within %s: %v", container, convergenceTimeout, lastErr)
		}
		time.Sleep(pollInterval)
	}
}

// waitForPrefix polls a container's IPv4 Loc-RIB until prefix is present and
// one of its paths has wantASN in the AS path (pass 0 to only require presence),
// then returns the parsed routes. Bounded by the same convergence timeout.
func waitForPrefix(t *testing.T, container, prefix string, wantASN int) bgpRoutes {
	t.Helper()

	deadline := time.Now().Add(convergenceTimeout)
	var lastErr error

	for {
		var routes bgpRoutes
		out, err := vtysh(container, "show bgp ipv4 unicast json")
		if err == nil {
			err = json.Unmarshal([]byte(out), &routes)
		}
		switch {
		case err != nil:
			lastErr = err
		default:
			paths, ok := routes.Routes[prefix]
			switch {
			case !ok || len(paths) == 0:
				lastErr = fmt.Errorf("prefix %s not in Loc-RIB yet (%d prefixes present)", prefix, len(routes.Routes))
			case wantASN != 0 && !asPathContains(paths, wantASN):
				lastErr = fmt.Errorf("prefix %s present with as-paths %v, missing AS%d", prefix, asPaths(paths), wantASN)
			default:
				return routes
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("prefix %s never appeared on %s within %s: %v", prefix, container, convergenceTimeout, lastErr)
		}
		time.Sleep(pollInterval)
	}
}

// asPathContains reports whether any of the prefix's paths includes asn.
func asPathContains(paths []bgpPath, asn int) bool {
	want := strconv.Itoa(asn)
	for _, p := range paths {
		for _, field := range strings.Fields(p.Path) {
			if field == want {
				return true
			}
		}
	}
	return false
}

// asPaths returns the AS-path strings of the given paths, for diagnostics.
func asPaths(paths []bgpPath) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p.Path)
	}
	return out
}

// compose runs `docker compose -f <composeFile> <args...>` and returns the
// combined output.
func compose(args ...string) (string, error) {
	full := append([]string{"compose", "-f", composeFile}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	return string(out), err
}

// vtysh runs `vtysh -c <cmd>` inside the named lab container and returns
// stdout. It uses `docker compose exec -T` (no TTY) so it works headless.
func vtysh(container, cmd string) (string, error) {
	full := []string{
		"compose", "-f", composeFile,
		"exec", "-T", container, "vtysh", "-c", cmd,
	}
	out, err := exec.Command("docker", full...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), fmt.Errorf("vtysh %q in %s: %w: %s", cmd, container, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return string(out), fmt.Errorf("vtysh %q in %s: %w", cmd, container, err)
	}
	return string(out), nil
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	const max = 500
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
