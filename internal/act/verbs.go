package act

import (
	"strings"
	"unicode"
)

// containsControl reports whether s holds a newline, carriage return, or any
// other control character. vtysh reads a batch file line by line and treats a
// line as one command, so an embedded newline would turn a validated command into
// two — the second of which would never be validated.
func containsControl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == 0 {
			return true
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// matchForbidden returns the first forbidden verb that s begins with (ignoring
// leading whitespace and case), or "" when the command is acceptable.
//
// The match is anchored at the start of the command and requires the match to
// end on a word boundary, so a legitimate command that merely contains a
// forbidden word in a value — a description string mentioning "write file", say
// — is not refused. What is refused is a command whose VERB is a persistence or
// framing verb.
func matchForbidden(s string) string {
	trimmed := strings.ToLower(strings.TrimLeft(s, " \t"))
	for _, v := range forbiddenVerbs {
		if !strings.HasPrefix(trimmed, v) {
			continue
		}
		if len(trimmed) == len(v) || !isWordChar(rune(trimmed[len(v)])) {
			return v
		}
	}
	return ""
}

// isWordChar reports whether r continues a word. Used for the word-boundary test
// above.
func isWordChar(r rune) bool {
	return r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
