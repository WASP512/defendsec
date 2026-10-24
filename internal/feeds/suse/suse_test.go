package suse

import (
	"io"
	"os"
	"testing"

	"defendsec/internal/feeds"
)

func open() (io.ReadCloser, error) { return os.Open("testdata/leap16.oval.xml") }

func collect(t *testing.T) (map[string]feeds.Advisory, feeds.Stats) {
	t.Helper()
	got := map[string]feeds.Advisory{}
	st, err := Parse(open, "opensuse-leap", "16.0", func(a feeds.Advisory) error {
		got[a.ID] = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func rangeFor(a feeds.Advisory, pkg string) (feeds.Range, bool) {
	for _, r := range a.Ranges {
		if r.Package == pkg {
			return r, true
		}
	}
	return feeds.Range{}, false
}

func TestParseFixture(t *testing.T) {
	got, st := collect(t)
	// 5 definitions: fixed, affected, not-affected, mixed, and one with no
	// package criteria at all (skipped).
	if st.Advisories != 4 || len(got) != 4 {
		t.Fatalf("advisories = %d / %d, want 4", st.Advisories, len(got))
	}
	if st.Skipped["CVE without package ranges"] != 1 {
		t.Errorf("skipped = %v", st.Skipped)
	}

	fixed := got["CVE-2006-10002"]
	r, ok := rangeFor(fixed, "perl-XML-Parser")
	if !ok || r.State != feeds.Fixed || r.Fixed != "0:2.470.0-160000.3.1" ||
		r.Distro != "opensuse-leap" || r.Release != "16.0" || r.Ecosystem != "openSUSE" {
		t.Errorf("fixed range = %+v ok=%v", r, ok)
	}
	if fixed.Severity != "high" || fixed.CVSSScore == nil {
		t.Errorf("fixed severity/cvss = %q %v", fixed.Severity, fixed.CVSSScore)
	}

	aff, ok := rangeFor(got["CVE-2021-3521"], "rpm")
	if !ok || aff.State != feeds.Affected || aff.Fixed != "" {
		t.Errorf("affected range = %+v ok=%v", aff, ok)
	}

	na, ok := rangeFor(got["CVE-2005-4886"], "kernel-source")
	if !ok || na.State != feeds.NotAffected {
		t.Errorf("not-affected range = %+v ok=%v", na, ok)
	}
	if got["CVE-2005-4886"].CVSSScore != nil {
		t.Errorf("CVE-2005-4886 has no cvss3 in the feed but got %v", *got["CVE-2005-4886"].CVSSScore)
	}

	// One CVE can say "fixed in X" for some packages and "not affected" for
	// another; both survive.
	mixed := got["CVE-2023-39327"]
	if r, ok := rangeFor(mixed, "ghostscript"); !ok || r.State != feeds.NotAffected {
		t.Errorf("mixed ghostscript = %+v ok=%v", r, ok)
	}
	if r, ok := rangeFor(mixed, "openjpeg2"); !ok || r.State != feeds.Fixed || r.Fixed != "0:2.5.3-160000.3.1" {
		t.Errorf("mixed openjpeg2 = %+v ok=%v", r, ok)
	}
	if len(mixed.Ranges) != 6 {
		t.Errorf("mixed ranges = %d, want 6 (5 fixed binaries + 1 not affected; release and signature tests excluded)", len(mixed.Ranges))
	}
}

func TestRollingReleaseHasNoVersion(t *testing.T) {
	got := map[string]feeds.Advisory{}
	_, err := Parse(open, "opensuse-tumbleweed", "", func(a feeds.Advisory) error { got[a.ID] = a; return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range got {
		for _, r := range a.Ranges {
			if r.Distro != "opensuse-tumbleweed" || r.Release != "" {
				t.Fatalf("range = %+v", r)
			}
		}
	}
}

func TestMalformedXML(t *testing.T) {
	_, err := Parse(func() (io.ReadCloser, error) { return os.Open("suse.go") }, "opensuse-leap", "16.0", func(feeds.Advisory) error { return nil })
	if err == nil {
		t.Fatal("non-XML input parsed without error")
	}
}
