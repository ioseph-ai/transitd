//go:build integration

// Package pinverify holds the veth integration test for per-transit pin
// verification (issue #1).
//
// It lives in its own package, next to test/integration, because it needs
// nothing but NET_ADMIN: it builds two veth pairs, points a route lookup at each
// in turn and asserts that pinning.RouteVerifier reports the interface the kernel
// actually resolves. The FRR compose lab (test/integration) is irrelevant here —
// pin verification is a pure `ip route get` question — so this test does not
// start docker and does not share the slower tier's TestMain.
//
// The scenario is the one issue #1 describes: a probe source whose policy route
// leads somewhere other than the transit expects must be reported UNVERIFIED,
// with the observed interface surfaced. The second half proves the same verifier
// flips to verified once the route is corrected, so a green result is a real
// observation rather than a verifier that always says no.
//
// All addresses are RFC 5737 / RFC 3849 documentation ranges. Interface names and
// routing-table ids are test-local and deliberately unlike anything a real router
// uses.
package pinverify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/pinning"
)

const (
	// v4Target is the probe target (TEST-NET-3). It is deliberately not a
	// connected prefix on either veth, so before the policy rule is installed it
	// resolves through the default route — which is what makes the test prove
	// the rule is doing the pinning.
	v4Target = "203.0.113.200"
	// v4SrcFirst is the transit's own source address; the probe must egress the
	// first veth (TEST-NET-3).
	v4SrcFirst = "203.0.113.1"
	// v4SrcSecond is a second source used to show the same target can be pinned
	// elsewhere (TEST-NET-3).
	v4SrcSecond = "203.0.113.2"

	// v6Target / v6SrcFirst / v6SrcSecond are the IPv6 counterparts (RFC 3849).
	v6Target    = "2001:db8:ff::1"
	v6SrcFirst  = "2001:db8:1::1"
	v6SrcSecond = "2001:db8:2::1"
)

// routeTable is the policy-routing table the veth scenario installs its target
// route into. It is well outside the ranges the kernel or docker use.
const routeTable = 4511

// requireNetAdmin skips a test when the host cannot create links (no root, no
// passwordless sudo). The package deliberately has no TestMain: a per-test skip
// is visible in `go test -v` as SKIP, whereas a package-level os.Exit(0) would
// hide which tests actually ran. A genuine failure in a runnable environment
// still fails normally.
func requireNetAdmin(t *testing.T) {
	t.Helper()
	if !canUseNetAdmin() {
		t.Skip("needs root or passwordless sudo for `ip link add` (veth pairs)")
	}
}

// TestPinVerifyMisPinnedIsReportedUnverified is the core scenario from issue #1.
//
// Setup: a transit whose source is S, whose expected egress interface is the
// FIRST veth, but whose policy route sends S's traffic out the SECOND veth. The
// verifier must report Verified=false and name the observed (wrong) interface.
// Then the route is corrected and the same verifier must report Verified=true.
func TestPinVerifyMisPinnedIsReportedUnverified(t *testing.T) {
	lab := newLab(t, "tdv4", v4SrcFirst, v4SrcSecond)

	tr := config.Transit{
		Name:            "main",
		ProbeSource:     v4SrcFirst,
		ProbeTarget:     v4Target,
		EgressInterface: lab.first,
	}

	// Control: with no policy rule the target does not resolve to either veth,
	// so any later match is attributable to the rule this test installs.
	pre := lab.routeGet(t, "-4", v4Target, v4SrcFirst)
	if iface, err := pinning.ParseEgressInterface(pre); err == nil && (iface == lab.first || iface == lab.second) {
		t.Fatalf("target already resolves to a test interface %q before the rule was added; the test would not prove pinning", iface)
	}

	v := pinning.New()

	// Mis-pinned: the route table sends the target out the SECOND veth.
	lab.addRule(t, "-4", v4SrcFirst, routeTable)
	lab.addRoute(t, "-4", v4Target, lab.second, routeTable)

	got := v.Verify(context.Background(), tr)
	if got.Verified {
		t.Fatalf("Verified = true with traffic egressing %s, expected %s", lab.second, lab.first)
	}
	if got.EgressIf != lab.second {
		t.Errorf("EgressIf = %q, want the observed %q", got.EgressIf, lab.second)
	}
	if !strings.Contains(got.Reason, lab.second) {
		t.Errorf("Reason %q does not name the observed egress %q", got.Reason, lab.second)
	}

	// Corrected: repoint the same table at the FIRST veth.
	lab.addRoute(t, "-4", v4Target, lab.first, routeTable)
	lab.flushRouteCache(t)

	got = v.Verify(context.Background(), tr)
	if !got.Verified {
		t.Fatalf("Verified = false after the route was corrected: %+v", got)
	}
	if got.EgressIf != lab.first {
		t.Errorf("EgressIf = %q, want %q", got.EgressIf, lab.first)
	}
}

// TestPinVerifyV6 has the same shape over IPv6, proving the verifier and its
// parser are address-family agnostic (the pinning spec covers v4 and v6).
func TestPinVerifyV6(t *testing.T) {
	lab := newLabV6(t, "tdv6", v6SrcFirst, v6SrcSecond)

	tr := config.Transit{
		Name:            "main6",
		ProbeSource:     v6SrcFirst,
		ProbeTarget:     v6Target,
		EgressInterface: lab.first,
	}

	lab.addRule(t, "-6", v6SrcFirst, routeTable)
	lab.addRoute(t, "-6", v6Target, lab.second, routeTable)

	v := pinning.New()
	got := v.Verify(context.Background(), tr)
	if got.Verified {
		t.Fatalf("Verified = true over v6 with traffic egressing %s, expected %s", lab.second, lab.first)
	}
	if got.EgressIf != lab.second {
		t.Errorf("EgressIf = %q, want the observed %q", got.EgressIf, lab.second)
	}

	lab.addRoute(t, "-6", v6Target, lab.first, routeTable)
	lab.flushRouteCache(t)

	got = v.Verify(context.Background(), tr)
	if !got.Verified {
		t.Fatalf("Verified = false over v6 after correction: %+v", got)
	}
}

// TestPinVerifyUnknownSourceReportsUnverified checks the failure path a real
// router hits when a transit's source address is not present on the host: the
// kernel refuses the lookup, so the verifier must report unverified with an empty
// egress rather than a bogus interface.
func TestPinVerifyUnknownSourceReportsUnverified(t *testing.T) {
	lab := newLab(t, "tdv4b", v4SrcFirst, v4SrcSecond)
	_ = lab // create the links only so the test has a clean, isolated namespace

	tr := config.Transit{
		Name:            "ghost",
		ProbeSource:     "203.0.113.254", // not assigned to anything
		ProbeTarget:     v4Target,
		EgressInterface: lab.first,
	}

	got := pinning.New().Verify(context.Background(), tr)
	if got.Verified {
		t.Fatalf("Verified = true for a source address that is not local: %+v", got)
	}
	if got.EgressIf != "" {
		t.Errorf("EgressIf = %q, want empty when the lookup failed", got.EgressIf)
	}
	if got.Reason == "" {
		t.Error("Reason must explain the failure")
	}
}

// lab is one veth-pair scenario. The FIRST interface is the transit's expected
// egress; the SECOND is where the test mis-routes traffic.
type lab struct {
	first, second         string
	firstPeer, secondPeer string
	srcFirst, srcSecond   string
	v6                    bool
}

// newLab creates two veth pairs and assigns the v4 source addresses /32 to the
// pair ends named first and second. Cleanup is registered immediately, so a
// failing assertion still tears the links (and any rule/route on them) down.
func newLab(t *testing.T, prefix, srcFirst, srcSecond string) *lab {
	t.Helper()
	requireNetAdmin(t)
	t.Helper()
	first := prefix + "0"
	second := prefix + "1"
	l := &lab{
		first: first, second: second,
		firstPeer: first + "p", secondPeer: second + "p",
		srcFirst: srcFirst, srcSecond: srcSecond,
	}
	l.cleanupNow(t)
	t.Cleanup(func() { l.cleanupNow(t) })

	l.linkAdd(t, first, l.firstPeer)
	l.linkAdd(t, second, l.secondPeer)
	l.addrAdd(t, first, srcFirst+"/32")
	l.addrAdd(t, second, srcSecond+"/32")
	return l
}

// newLabV6 is newLab for IPv6 (nodad avoids the DAD wait on a fresh link).
func newLabV6(t *testing.T, prefix, srcFirst, srcSecond string) *lab {
	t.Helper()
	requireNetAdmin(t)
	t.Helper()
	first := prefix + "0"
	second := prefix + "1"
	l := &lab{
		first: first, second: second,
		firstPeer: first + "p", secondPeer: second + "p",
		srcFirst: srcFirst, srcSecond: srcSecond,
		v6: true,
	}
	l.cleanupNow(t)
	t.Cleanup(func() { l.cleanupNow(t) })

	l.linkAdd(t, first, l.firstPeer)
	l.linkAdd(t, second, l.secondPeer)
	l.addrAdd(t, first, srcFirst+"/64")
	l.addrAdd(t, second, srcSecond+"/64")
	return l
}

// cleanupNow removes every artifact this test could have created, best-effort.
// It runs twice: before setup (to clear debris from an aborted previous run) and
// again on cleanup. Every removal is idempotent.
func (l *lab) cleanupNow(t *testing.T) {
	t.Helper()
	l.deleteRule(t, "-4", l.srcFirst)
	l.deleteRule(t, "-4", l.srcSecond)
	l.deleteRule(t, "-6", l.srcFirst)
	l.deleteRule(t, "-6", l.srcSecond)
	l.flushTable(t, "-4")
	l.flushTable(t, "-6")
	l.linkDel(t, l.first)
	l.linkDel(t, l.second)
}

func (l *lab) linkAdd(t *testing.T, name, peer string) {
	t.Helper()
	l.ip(t, "link", "add", name, "type", "veth", "peer", "name", peer)
	l.ip(t, "link", "set", name, "up")
	l.ip(t, "link", "set", peer, "up")
}

func (l *lab) linkDel(t *testing.T, name string) {
	t.Helper()
	// Deleting one end of a veth pair deletes both; a missing link is fine.
	_, _ = l.ipCmd("link", "del", name)
}

func (l *lab) addrAdd(t *testing.T, iface, cidr string) {
	t.Helper()
	if l.v6 {
		l.ip(t, "-6", "addr", "add", cidr, "dev", iface, "nodad")
		return
	}
	l.ip(t, "addr", "add", cidr, "dev", iface)
}

func (l *lab) addRule(t *testing.T, fam, src string, table int) {
	t.Helper()
	l.ip(t, fam, "rule", "add", "from", src, "lookup", itoa(table), "priority", "1000")
}

func (l *lab) deleteRule(t *testing.T, fam, src string) {
	t.Helper()
	_, _ = l.ipCmd(fam, "rule", "del", "from", src, "lookup", itoa(routeTable))
}

func (l *lab) addRoute(t *testing.T, fam, target, iface string, table int) {
	t.Helper()
	// The target route must be a host route: /32 for v4, /128 for v6. A /32 on an
	// IPv6 target would install 2001:db8::/32 — a prefix that contains the source
	// addresses themselves, collapsing the scenario.
	prefix := "32"
	if l.v6 {
		prefix = "128"
	}
	l.ip(t, fam, "route", "replace", target+"/"+prefix, "dev", iface, "table", itoa(table))
}

func (l *lab) flushTable(t *testing.T, fam string) {
	t.Helper()
	_, _ = l.ipCmd(fam, "route", "flush", "table", itoa(routeTable))
}

// flushRouteCache clears cached route lookups so a repointed table is observed
// immediately (a stale `cache` line would otherwise report the old interface).
func (l *lab) flushRouteCache(t *testing.T) {
	t.Helper()
	_, _ = l.ipCmd("-4", "route", "flush", "cache")
	_, _ = l.ipCmd("-6", "route", "flush", "cache")
}

// routeGet runs the same lookup the verifier runs and returns its raw output.
func (l *lab) routeGet(t *testing.T, fam, target, src string) string {
	t.Helper()
	out, err := l.ipCmd(fam, "route", "get", target, "from", src)
	if err != nil {
		t.Fatalf("ip %s route get %s from %s: %v (%s)", fam, target, src, err, out)
	}
	return out
}

// ip runs an ip command and fails the test on error.
func (l *lab) ip(t *testing.T, args ...string) string {
	t.Helper()
	out, err := l.ipCmd(args...)
	if err != nil {
		t.Fatalf("ip %s: %v (%s)", strings.Join(args, " "), err, out)
	}
	return out
}

// ipCmd runs `ip <args>` (through sudo when not already root) and returns
// combined output.
func (l *lab) ipCmd(args ...string) (string, error) {
	cmd := exec.Command("ip", args...) //nolint:gosec // fixed binary, argv slice built by the test
	if os.Geteuid() != 0 {
		cmd = exec.Command("sudo", append([]string{"-n", "ip"}, args...)...) //nolint:gosec // same
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// canUseNetAdmin reports whether this process can create links: either it is
// root, or passwordless sudo is available.
func canUseNetAdmin() bool {
	if _, err := exec.LookPath("ip"); err != nil {
		return false
	}
	if os.Geteuid() == 0 {
		return true
	}
	return exec.Command("sudo", "-n", "true").Run() == nil //nolint:gosec // fixed probe
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
