// Package controls carries framework control identifiers as first-class data
// rather than generating them in a report (roadmap 1.7, §3.6).
//
// The distinction matters. A report is written once against whatever the
// database happens to hold; a data model means every alert, check result,
// signed action and audit entry is tagged at the moment it is created, so
// control state can be reconstructed for any window afterwards. Retrofitting
// the tags later means re-tagging every record type. Doing it now costs a
// column and a lookup table.
//
// # Why 800-53 is the hub
//
// Mappings are declared against NIST SP 800-53 Rev 5 and CIS Controls v8, and
// every other framework reaches them through a crosswalk. CJIS Security Policy
// v6.0 is itself explicitly mapped to 800-53 Rev 5, and 800-171 derives from
// it, so one set of native mappings serves several frameworks. CJIS is an
// additional column, not additional architecture (§3.10).
//
// # Coverage is stated, not implied
//
// Every mapping carries how well DefendSec can actually evidence the control:
// fully, partly, or not at all. The catalog deliberately includes controls
// DefendSec cannot evidence, each with the reason, because a control that is
// silently absent from a compliance view reads as "no finding" to the person
// least able to notice the difference. An assessor is owed the breakdown, not
// a coverage percentage (§3.7, §3.10).
package controls

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Framework identifies a control catalog.
type Framework string

const (
	// NIST80053 is NIST SP 800-53 Rev 5, the hub every crosswalk targets.
	NIST80053 Framework = "nist-800-53"
	// NIST800171 is NIST SP 800-171 Rev 2, which CMMC 2.0 Level 2 adopts
	// wholesale — the same 110 requirements, so one mapping covers both.
	NIST800171 Framework = "nist-800-171"
	// CISv8 is CIS Controls v8. Note: the Controls, not the Benchmarks.
	// Benchmark content is a different and much worse fight (§3.1).
	CISv8 Framework = "cis-v8"
	// CJISv6 is the CJIS Security Policy v6.0, organised by policy area.
	CJISv6 Framework = "cjis-v6"
	// CMMCL2 is CMMC 2.0 Level 2, which is 800-171 by reference.
	CMMCL2 Framework = "cmmc-l2"
)

// Frameworks lists every framework the catalog can render, in the order
// §3.6 recommends being excellent at them.
func Frameworks() []Framework {
	return []Framework{CISv8, NIST800171, CMMCL2, NIST80053, CJISv6}
}

// FrameworkTitle is the full name, for a report header an assessor will read.
func FrameworkTitle(f Framework) string {
	switch f {
	case NIST80053:
		return "NIST SP 800-53 Rev 5"
	case NIST800171:
		return "NIST SP 800-171 Rev 2"
	case CISv8:
		return "CIS Controls v8"
	case CJISv6:
		return "CJIS Security Policy v6.0"
	case CMMCL2:
		return "CMMC 2.0 Level 2"
	default:
		return string(f)
	}
}

// KnownFramework reports whether f is one the catalog understands. Unknown
// frameworks are rejected rather than stored, so a typo cannot create a
// second, invisible catalog that never matches anything.
func KnownFramework(f Framework) bool {
	for _, known := range Frameworks() {
		if f == known {
			return true
		}
	}
	return false
}

// ID is a control identifier in canonical "framework:control" form, for
// example "nist-800-53:AU-9(3)" or "cis-v8:5.4".
type ID string

// controlPattern is deliberately permissive about the control part: catalogs
// use dots, dashes, parentheses and periods in ways that differ per framework,
// and rejecting a valid identifier is worse than accepting an odd one.
var controlPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.()\-_]*$`)

// ParseID validates and normalises an identifier.
//
// The framework half is lowercased because it is ours; the control half keeps
// its case because it is the catalog's, and "AU-9(3)" is how 800-53 writes it.
func ParseID(raw string) (ID, error) {
	s := strings.TrimSpace(raw)
	framework, control, ok := strings.Cut(s, ":")
	if !ok {
		return "", fmt.Errorf("control id %q is missing its framework prefix, expected e.g. nist-800-53:AU-9(3)", raw)
	}
	framework = strings.ToLower(strings.TrimSpace(framework))
	control = strings.TrimSpace(control)
	if framework == "" || control == "" {
		return "", fmt.Errorf("control id %q has an empty framework or control part", raw)
	}
	if !KnownFramework(Framework(framework)) {
		return "", fmt.Errorf("control id %q names unknown framework %q", raw, framework)
	}
	if !controlPattern.MatchString(control) {
		return "", fmt.Errorf("control id %q has an unusable control part %q", raw, control)
	}
	return ID(framework + ":" + control), nil
}

// MustParseID is ParseID for compiled-in constants, where a bad identifier is
// a programming error that should stop the process at startup rather than
// produce a compliance view with a silently missing control.
func MustParseID(raw string) ID {
	id, err := ParseID(raw)
	if err != nil {
		panic(err)
	}
	return id
}

// Framework returns the framework half.
func (id ID) Framework() Framework {
	framework, _, _ := strings.Cut(string(id), ":")
	return Framework(framework)
}

// Control returns the control half.
func (id ID) Control() string {
	_, control, _ := strings.Cut(string(id), ":")
	return control
}

// String makes ID printable and usable as a database value.
func (id ID) String() string { return string(id) }

// ParseIDs normalises a list, reporting every bad entry rather than the first,
// so a mis-tagged pack is fixed in one pass.
func ParseIDs(raw []string) ([]ID, error) {
	out := make([]ID, 0, len(raw))
	var bad []string
	seen := map[ID]bool{}
	for _, r := range raw {
		if strings.TrimSpace(r) == "" {
			continue
		}
		id, err := ParseID(r)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%d unusable control ids: %s", len(bad), strings.Join(bad, "; "))
	}
	return out, nil
}

// SortIDs orders identifiers for stable output, which matters because these
// end up in signed evidence bundles: an unstable order changes a hash for no
// substantive reason.
func SortIDs(ids []ID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
}

// Strings renders identifiers for storage or JSON.
func Strings(ids []ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}
