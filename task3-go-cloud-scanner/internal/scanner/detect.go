package scanner

import (
	"net/netip"
	"strings"
)

// InternetSources lists the non-CIDR tokens that different providers use to mean
// "anywhere". Azure in particular expresses an open rule as "*", "Any" or the
// "Internet" service tag rather than as a CIDR, so matching on the literal
// string "0.0.0.0/0" alone would miss the majority of open NSG rules.
var internetTokens = map[string]bool{
	"*":         true,
	"any":       true,
	"internet":  true,
	"0.0.0.0":   true,
	"0.0.0.0/0": true,
	"::/0":      true,
	"::":        true,
}

// IsInternetSource reports whether a source expression admits the whole
// internet.
//
// The test is a zero-length prefix rather than a string comparison: 0.0.0.0/0
// and ::/0 both have prefix length 0 and are the only CIDRs that cover every
// address, so this is exact, and it also catches unusual spellings that a
// string match would not.
//
// Deliberately *not* treated as open: a wide but bounded range such as
// 10.0.0.0/8 or 0.0.0.0/1. Those are worth flagging in a real programme, but
// they are a different finding with a different severity, and conflating them
// would make this tool's output unusable as a merge gate. Widening the
// definition is a one-line change here (compare Bits() against a threshold).
func IsInternetSource(source string) bool {
	s := strings.TrimSpace(strings.ToLower(source))
	if s == "" {
		return false
	}
	if internetTokens[s] {
		return true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Bits() == 0
	}
	// A bare address is not a range, so it is never "the whole internet" unless
	// it is one of the tokens handled above.
	return false
}

// AnyInternetSource reports whether any entry in the list is internet-wide, and
// returns the first such entry so the finding can name the exact value that
// triggered it rather than a normalised stand-in.
func AnyInternetSource(sources []string) (string, bool) {
	for _, s := range sources {
		if IsInternetSource(s) {
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}

// NormalizeProtocol maps each provider's spelling onto a common vocabulary:
// lowercase names, or "*" for "every protocol".
//
//	AWS   "-1"          -> "*"
//	GCP   "all"         -> "*"
//	Azure "*" / "Any"   -> "*"
func NormalizeProtocol(p string) string {
	s := strings.TrimSpace(strings.ToLower(p))
	switch s {
	case "", "-1", "all", "any", "*":
		return "*"
	default:
		return s
	}
}

// IsAllProtocols reports whether the normalised protocol covers everything.
func IsAllProtocols(p string) bool { return NormalizeProtocol(p) == "*" }
