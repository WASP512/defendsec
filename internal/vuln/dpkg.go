package vuln

import (
	"strconv"
	"strings"
)

// Debian version comparison, ported from dpkg's lib/dpkg/version.c.
//
// A Debian version is [epoch:]upstream-version[-debian-revision]. Epoch is
// compared numerically; upstream and revision are compared with verrevcmp,
// which alternates between non-digit and digit runs. The property that matters
// most in practice is that '~' sorts before everything, including the end of a
// string, so 1.0~rc1 < 1.0.

// dpkgOrder mirrors order() in dpkg. Digits are handled by the caller, so they
// order as 0 here. Letters keep their ASCII value, '~' sorts below everything,
// and every other byte sorts above the letters.
func dpkgOrder(c byte) int {
	switch {
	case isASCIIDigit(c):
		return 0
	case isASCIILetter(c):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// byteAt emulates C string indexing, where reading at or past the terminator
// yields NUL. The ported algorithm relies on that behaviour.
func byteAt(s string, i int) byte {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return 0
}

// dpkgVerRevCmp compares a single version component (upstream or revision).
func dpkgVerRevCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0

		// Compare the leading run of non-digits bytewise under dpkgOrder.
		for (byteAt(a, i) != 0 && !isASCIIDigit(byteAt(a, i))) ||
			(byteAt(b, j) != 0 && !isASCIIDigit(byteAt(b, j))) {
			ac := dpkgOrder(byteAt(a, i))
			bc := dpkgOrder(byteAt(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}

		// Leading zeros carry no value.
		for byteAt(a, i) == '0' {
			i++
		}
		for byteAt(b, j) == '0' {
			j++
		}

		// Compare the digit run. The longer run wins; otherwise the first
		// differing digit decides.
		for isASCIIDigit(byteAt(a, i)) && isASCIIDigit(byteAt(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(byteAt(a, i)) - int(byteAt(b, j))
			}
			i++
			j++
		}
		if isASCIIDigit(byteAt(a, i)) {
			return 1
		}
		if isASCIIDigit(byteAt(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// DpkgVersion is a parsed Debian version.
type DpkgVersion struct {
	Epoch    int
	Upstream string
	Revision string
}

// HasRevision reports whether the version carries a Debian/Ubuntu revision,
// which is the marker of a distro-packaged build rather than an upstream one.
func (v DpkgVersion) HasRevision() bool { return v.Revision != "" }

// ParseDpkg splits [epoch:]upstream[-revision]. A non-numeric prefix before a
// colon is treated as part of the upstream version rather than rejected, so a
// malformed record degrades instead of failing the whole comparison.
func ParseDpkg(raw string) DpkgVersion {
	s := strings.TrimSpace(raw)
	v := DpkgVersion{}
	if i := strings.Index(s, ":"); i > 0 {
		if n, err := strconv.Atoi(s[:i]); err == nil && n >= 0 {
			v.Epoch = n
			s = s[i+1:]
		}
	}
	if i := strings.LastIndex(s, "-"); i >= 0 {
		v.Upstream = s[:i]
		v.Revision = s[i+1:]
	} else {
		v.Upstream = s
	}
	return v
}

// CompareDpkg returns -1, 0 or 1 as a sorts before, equal to, or after b under
// Debian version ordering.
func CompareDpkg(a, b string) int {
	va, vb := ParseDpkg(a), ParseDpkg(b)
	if va.Epoch != vb.Epoch {
		if va.Epoch < vb.Epoch {
			return -1
		}
		return 1
	}
	if c := dpkgVerRevCmp(va.Upstream, vb.Upstream); c != 0 {
		return normalizeSign(c)
	}
	return normalizeSign(dpkgVerRevCmp(va.Revision, vb.Revision))
}
