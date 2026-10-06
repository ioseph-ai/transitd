// Package act applies runtime-only vtysh mutations and undoes them (issue #4).
//
// It is the ONLY package in transitd that reaches a router mutation path, and it
// is built around two invariants that issue #4's safety model depends on:
//
//  1. NEVER `write file`. The package holds no config-file code path and its
//     runner refuses any command that would persist the running configuration.
//     Every mutation is runtime-only, so any config-management re-apply cleanly
//     reverts it (docs/design.md "Runtime-only changes").
//
//  2. A Batch is apply/rollback PAIRED. There is no way to express a mutation
//     without its inverse, so a caller cannot construct an irreversible change.
//     The golden batches (neighbor shutdown, tcp-mss clamp) demonstrate the
//     pairing the drill and MTU features will consume.
//
// Applying a batch is audited: one structured log line plus
// transitd_act_ops{op,result}. The counter names no neighbor and no prefix, so
// its cardinality does not grow with the BGP table.
package act

import "fmt"

// Batch is one runtime-only mutation and its textual inverse.
//
// The commands are full vtysh command lines WITHOUT the `configure terminal` /
// `end` framing: the executor adds that framing when it writes the batch file,
// so a Batch is a description of a change, not of a vtysh session. The pairing is
// the point — a Batch that cannot be undone cannot be built.
type Batch struct {
	// Name is a short identifier for logs and audit ("neighbor-shutdown",
	// "tcp-mss-clamp"). It is not interpreted by the executor.
	Name string
	// Apply is the ordered vtysh command list that performs the mutation.
	Apply []string
	// Rollback is the ordered vtysh command list that undoes it. It must be the
	// textual inverse of Apply so that applying it twice is a no-op once the
	// first application has taken effect.
	Rollback []string
	// Description explains in prose what the batch does and why, for the audit
	// log. A mutation an operator cannot read the reason for is not auditable.
	Description string
}

// Validate rejects an unusable batch before anything is exec'd. It refuses an
// empty side (a mutation with no inverse is exactly what this type exists to
// prevent), any command that would persist configuration, and any command
// carrying a newline — vtysh reads the batch file line by line, so an embedded
// newline is a second command in disguise.
func (b Batch) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("act: batch name is required")
	}
	if len(b.Apply) == 0 {
		return fmt.Errorf("act: batch %q: Apply is empty — nothing to do", b.Name)
	}
	if len(b.Rollback) == 0 {
		return fmt.Errorf("act: batch %q: Rollback is empty — an irreversible mutation is not a Batch", b.Name)
	}
	for _, side := range []struct {
		which string
		cmds  []string
	}{{"Apply", b.Apply}, {"Rollback", b.Rollback}} {
		for i, c := range side.cmds {
			if err := validateCommand(c); err != nil {
				return fmt.Errorf("act: batch %q: %s[%d]: %w", b.Name, side.which, i, err)
			}
		}
	}
	return nil
}

// forbiddenVerbs are command substrings that would defeat the runtime-only
// guarantee. They are checked case-insensitively on the leading word(s) of a
// command, because that is where vtysh puts the verb. `write file` persists the
// running configuration; `copy` and `write` are its neighbours, and a
// `configure`/`end` inside a Batch would be framing the executor already owns.
var forbiddenVerbs = []string{
	"write file",
	"write memory",
	"write terminal",
	"copy running-config",
	"copy startup-config",
	"configure terminal",
	"configure",
	"end",
}

// validateCommand refuses a single command line that is not a safe runtime-only
// vtysh command.
func validateCommand(c string) error {
	if c == "" {
		return fmt.Errorf("empty command")
	}
	if len(c) > maxCommandLen {
		return fmt.Errorf("command is %d bytes, over the %d-byte cap", len(c), maxCommandLen)
	}
	if containsControl(c) {
		return fmt.Errorf("command contains a control character or newline")
	}
	// The check is prefix-anchored and case-insensitive: vtysh's parser is
	// case-sensitive, but refusing a differently-cased spelling of a persistence
	// verb costs nothing and closes an obvious bypass.
	if v := matchForbidden(c); v != "" {
		return fmt.Errorf("command %q contains the config-preserving verb %q — act is runtime-only and never persists configuration", c, v)
	}
	return nil
}

// maxCommandLen bounds one command line. A vtysh line is short; a very long one
// is a sign of a constructed string rather than a config change.
const maxCommandLen = 1024
