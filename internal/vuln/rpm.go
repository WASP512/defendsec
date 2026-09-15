package vuln

import (
	"strconv"
	"strings"
)

// RPM version comparison, ported from rpm's rpmvercmp() in lib/rpmvercmp.c.
//
// An RPM version is [epoch:]version[-release] (an "EVR"). Within a component,
// comparison walks alternating alphabetic and numeric segments, skipping any
// other separator. Two markers are special: '~' sorts before everything
// (pre-releases), and '^' sorts after a bare version but before the next
// release (post-release snapshots).

func isASCIIDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isRPMAlnum(c byte) bool    { return isASCIIDigit(c) || isASCIILetter(c) }

func normalizeSign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// rpmVerCmp compares a single EVR component.
func rpmVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	for one < len(a) || two < len(b) {
		// Skip separators, but never skip the '~' and '^' markers.
		for one < len(a) && !isRPMAlnum(a[one]) && a[one] != '~' && a[one] != '^' {
			one++
		}
		for two < len(b) && !isRPMAlnum(b[two]) && b[two] != '~' && b[two] != '^' {
			two++
		}

		// '~' sorts before everything, so 1.0~rc1 < 1.0.
		aTilde := one < len(a) && a[one] == '~'
		bTilde := two < len(b) && b[two] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			one++
			two++
			continue
		}

		// '^' is the inverse: a bare version sorts before version^snapshot.
		aCaret := one < len(a) && a[one] == '^'
		bCaret := two < len(b) && b[two] == '^'
		if aCaret || bCaret {
			if one >= len(a) {
				return -1
			}
			if two >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			one++
			two++
			continue
		}

		// One side ran out; the trailing check below decides.
		if one >= len(a) || two >= len(b) {
			break
		}

		// Take the next wholly-numeric or wholly-alphabetic segment.
		s1, s2 := one, two
		isNum := isASCIIDigit(a[s1])
		if isNum {
			for s1 < len(a) && isASCIIDigit(a[s1]) {
				s1++
			}
			for s2 < len(b) && isASCIIDigit(b[s2]) {
				s2++
			}
		} else {
			for s1 < len(a) && isASCIILetter(a[s1]) {
				s1++
			}
			for s2 < len(b) && isASCIILetter(b[s2]) {
				s2++
			}
		}

		segA, segB := a[one:s1], b[two:s2]
		if len(segB) == 0 {
			// Segments are of different types. A numeric segment is always
			// newer than an alphabetic one.
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				// Whichever number has more digits wins, without overflowing.
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return normalizeSign(c)
		}
		one, two = s1, s2
	}

	switch {
	case one >= len(a) && two >= len(b):
		return 0
	case one >= len(a):
		return -1
	default:
		return 1
	}
}

// RPMVersion is a parsed RPM EVR.
type RPMVersion struct {
	Epoch   int
	Version string
	Release string
}

// HasRelease reports whether the version carries an RPM release field, which
// is where RHEL-family distros record backported security fixes.
func (v RPMVersion) HasRelease() bool { return v.Release != "" }

// ParseRPM splits [epoch:]version[-release].
func ParseRPM(raw string) RPMVersion {
	s := strings.TrimSpace(raw)
	v := RPMVersion{}
	if i := strings.Index(s, ":"); i > 0 {
		if n, err := strconv.Atoi(s[:i]); err == nil && n >= 0 {
			v.Epoch = n
			s = s[i+1:]
		}
	}
	if i := strings.Index(s, "-"); i >= 0 {
		v.Version = s[:i]
		v.Release = s[i+1:]
	} else {
		v.Version = s
	}
	return v
}

// CompareRPM returns -1, 0 or 1 as a sorts before, equal to, or after b under
// RPM EVR ordering.
func CompareRPM(a, b string) int {
	va, vb := ParseRPM(a), ParseRPM(b)
	if va.Epoch != vb.Epoch {
		if va.Epoch < vb.Epoch {
			return -1
		}
		return 1
	}
	if c := rpmVerCmp(va.Version, vb.Version); c != 0 {
		return c
	}
	return rpmVerCmp(va.Release, vb.Release)
}
