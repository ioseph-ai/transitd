package act

import "fmt"

// Golden batches. Each is a named, apply/rollback-paired, runtime-only vtysh
// mutation with a cited source for its syntax. They are the batches issue #4's
// acceptance criteria name (neighbor shutdown, neighbor restore, tcp-mss clamp),
// and the shapes the drill (docs/design/feature-1-drill.md) and MTU probe
// (docs/design/feature-2-mtu-probe.md) will consume.

// NeighborShutdown builds the BGP neighbor-shutdown batch: the drill's default
// fault injection (docs/design/feature-1-drill.md §2).
//
// vtysh syntax (FRR 10.x, BGP):
//
//	router bgp <asn>
//	 neighbor <ip> shutdown
//
// The inverse is `no neighbor <ip> shutdown`. Both are runtime-only: `shutdown`
// changes the session's administrative state in the running configuration and is
// undone by its `no` form; neither writes a file. `shutdown` is idempotent (a
// second one is a no-op) and so is the `no` form, which is what makes the
// executor's double-rollback guarantee sound.
//
// asn is the LOCAL autonomous system (the `router bgp` number), not the peer's.
// neighbor is the peer address as it appears in `show bgp summary json`.
func NeighborShutdown(asn int, neighbor string) (Batch, error) {
	if asn <= 0 || asn > 4294967295 {
		return Batch{}, fmt.Errorf("act: neighbor shutdown: %d is not a valid local ASN", asn)
	}
	if neighbor == "" {
		return Batch{}, fmt.Errorf("act: neighbor shutdown: neighbor address is required")
	}
	if !neighborRe.MatchString(neighbor) {
		return Batch{}, fmt.Errorf("act: neighbor shutdown: %q is not an IP address", neighbor)
	}
	return Batch{
		Name: "neighbor-shutdown",
		Apply: []string{
			fmt.Sprintf("router bgp %d", asn),
			fmt.Sprintf("neighbor %s shutdown", neighbor),
		},
		Rollback: []string{
			fmt.Sprintf("router bgp %d", asn),
			fmt.Sprintf("no neighbor %s shutdown", neighbor),
		},
		Description: fmt.Sprintf("administratively shut down BGP neighbor %s (drill injection); runtime-only, restored by the textual inverse", neighbor),
	}, nil
}

// TCPMSSClamp builds a per-neighbor BGP TCP MSS clamp batch.
//
// WHY per-neighbor `neighbor <ip> tcp-mss <value>` and NOT an interface command:
// FRR has no interface-level TCP MSS clamp. The zebra interface command set
// (docs.frrouting.org/en/latest/zebra.html, "Interface Commands") is
// `ip address`, `ipv6 address`, `description`, `shutdown`, `bandwidth`,
// `multicast`, `mpls`, `link-detect` and the link-params subnode — there is no
// `ip tcp-mss-clamp` / `ip tcp adjust-mss` (that spelling is Cisco IOS). FRR's
// TCP MSS facility is a BGP feature, documented under "neighbor tcp-mss
// (1-65535)" in the BGP chapter (docs.frrouting.org/en/latest/bgp.html): it is
// configured in router-bgp mode and takes effect only after a hard reset of the
// neighbor. This was also verified against the FRR 10.7.1 container in the
// integration lab: `interface <if>` has no mss subcommand, while
// `neighbor <ip> tcp-mss 1400` is accepted and appears in `show running-config`.
//
// The clamp is therefore applied to the transit's BGP neighbor session, which is
// where FRR exposes it, and the MTU probe's per-transit MSS cap maps onto that
// neighbor.
//
// The inverse is the `no` form, which returns the session to the kernel's
// MTU-derived MSS. Both are runtime-only.
//
// value is the MSS in bytes; FRR accepts 1-65535.
func TCPMSSClamp(asn int, neighbor string, value int) (Batch, error) {
	if asn <= 0 || asn > 4294967295 {
		return Batch{}, fmt.Errorf("act: tcp-mss clamp: %d is not a valid local ASN", asn)
	}
	if neighbor == "" {
		return Batch{}, fmt.Errorf("act: tcp-mss clamp: neighbor address is required")
	}
	if !neighborRe.MatchString(neighbor) {
		return Batch{}, fmt.Errorf("act: tcp-mss clamp: %q is not an IP address", neighbor)
	}
	if value < 1 || value > 65535 {
		return Batch{}, fmt.Errorf("act: tcp-mss clamp: %d is outside FRR's accepted 1-65535 MSS range", value)
	}
	return Batch{
		Name: "tcp-mss-clamp",
		Apply: []string{
			fmt.Sprintf("router bgp %d", asn),
			fmt.Sprintf("neighbor %s tcp-mss %d", neighbor, value),
		},
		Rollback: []string{
			fmt.Sprintf("router bgp %d", asn),
			fmt.Sprintf("no neighbor %s tcp-mss %d", neighbor, value),
		},
		Description: fmt.Sprintf("clamp TCP MSS to %d on BGP neighbor %s (FRR per-neighbor tcp-mss); runtime-only, needs a hard reset to take effect", value, neighbor),
	}, nil
}
