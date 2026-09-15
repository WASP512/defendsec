package vuln

import "testing"

// Vectors ported from dpkg's own version test suite. The cases that matter for
// advisory matching are the ones the previous integer-segment comparator got
// wrong: alphabetic suffixes, '~' pre-release ordering, and epochs.
func TestCompareDpkgVectors(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0.0", "1.0", 1},
		{"0:1.0", "1.0", 0},

		// Epochs dominate everything else.
		{"1:1.0", "2.0", 1},
		{"2.0", "1:1.0", -1},
		{"1:1.0", "1:1.0", 0},

		// Alphabetic suffixes. The old comparator stripped these and called
		// every one of these pairs equal.
		{"1.1.1a", "1.1.1g", -1},
		{"1.1.1g", "1.1.1a", 1},
		{"1.1.1", "1.1.1a", -1},
		{"1a", "1", 1},

		// '~' sorts before everything, including end-of-string.
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"2.2~rc-4", "2.2-1", -1},
		{"1.0-1~deb10u1", "1.0-1", -1},

		// Revisions.
		{"1.0-1", "1.0-2", -1},
		{"1.0-2", "1.0-1", 1},
		{"1.0", "1.0-0", 0},

		// Leading zeros carry no value.
		{"1.01", "1.1", 0},
		{"1.010", "1.10", 0},
	}
	for _, tc := range cases {
		if got := CompareDpkg(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// Vectors ported from rpm's tests/rpmvercmp.at.
func TestCompareRPMVectors(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1},

		{"2.0.1a", "2.0.1a", 0},
		{"2.0.1a", "2.0.1", 1},
		{"2.0.1", "2.0.1a", -1},

		{"5.5p1", "5.5p1", 0},
		{"5.5p1", "5.5p2", -1},
		{"5.5p1", "5.5p10", -1},
		{"5.5p10", "5.5p10", 0},

		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10", 0},
		{"xyz10", "xyz10.1", -1},

		// A numeric segment always outranks an alphabetic one.
		{"xyz.4", "8", -1},
		{"8", "xyz.4", 1},
		{"xyz.4", "2", -1},

		{"20101121", "20101122", -1},

		// Separators are not significant.
		{"2.0", "2_0", 0},
		{"2_0", "2.0", 0},
		{"a+", "a_", 0},
		{"+a", "_a", 0},

		// '~' sorts before everything.
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},

		// '^' sorts after a bare version but below the next release.
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git1", "1.01", -1},
		{"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0.1", -1},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0^git1~pre", "1.0^git1", -1},

		// Epoch and release.
		{"1:1.0", "2.0", 1},
		{"1.0-1", "1.0-2", -1},
		{"3.0.7-18.el8", "3.0.7-18.el8", 0},
		{"3.0.7-18.el8", "3.0.7-19.el8", -1},
	}
	for _, tc := range cases {
		if got := CompareRPM(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareIsAntisymmetric(t *testing.T) {
	versions := []string{
		"1.0", "1.0~rc1", "1.0-1", "1:1.0", "1.1.1f-1ubuntu2.19",
		"3.0.7-18.el8", "2.0.1a", "1.0^git1", "20101121", "5.5p10",
	}
	for _, scheme := range []Scheme{SchemeDpkg, SchemeRPM} {
		for _, a := range versions {
			for _, b := range versions {
				ab := Compare(a, b, scheme)
				ba := Compare(b, a, scheme)
				if ab != -ba {
					t.Errorf("scheme %d: Compare(%q,%q)=%d but Compare(%q,%q)=%d", scheme, a, b, ab, b, a, ba)
				}
			}
		}
	}
}

func TestParseDpkgAndRPM(t *testing.T) {
	d := ParseDpkg("1:8.9p1-3ubuntu0.11")
	if d.Epoch != 1 || d.Upstream != "8.9p1" || d.Revision != "3ubuntu0.11" {
		t.Errorf("ParseDpkg = %+v", d)
	}
	if !d.HasRevision() {
		t.Error("expected a Debian revision")
	}
	if ParseDpkg("9.8p1").HasRevision() {
		t.Error("a bare upstream version has no revision")
	}

	// A Debian upstream version may itself contain hyphens; the revision is
	// whatever follows the last one.
	if got := ParseDpkg("1.2-3-4").Revision; got != "4" {
		t.Errorf("revision = %q, want 4", got)
	}

	r := ParseRPM("1:3.0.7-18.el8")
	if r.Epoch != 1 || r.Version != "3.0.7" || r.Release != "18.el8" {
		t.Errorf("ParseRPM = %+v", r)
	}
	if !r.HasRelease() {
		t.Error("expected an RPM release")
	}
}

func TestDetectScheme(t *testing.T) {
	if got := DetectScheme("3.0.7-18.el8", "3.0.8"); got != SchemeRPM {
		t.Errorf("el8 release should detect as RPM, got %d", got)
	}
	if got := DetectScheme("1.1.1f-1ubuntu2.19", "1.1.1k"); got != SchemeDpkg {
		t.Errorf("ubuntu revision should detect as dpkg, got %d", got)
	}
	if got := DetectScheme("1.2.3", "1.2.4"); got != SchemeDpkg {
		t.Errorf("plain versions should fall back to dpkg, got %d", got)
	}
}
