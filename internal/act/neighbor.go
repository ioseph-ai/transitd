package act

import "regexp"

// neighborRe is the accepted shape of a BGP neighbor address in a batch. A
// neighbor address is interpolated into a vtysh command line, so it is validated
// as a bare IPv4/IPv6 literal here rather than trusted from config: a value
// carrying whitespace or a newline would otherwise be a second command. (Config
// validation already rejects a non-IP bgp_neighbor; this is the second, local
// gate the batch constructors run so a directly-constructed Batch is covered
// too.)
var neighborRe = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)
