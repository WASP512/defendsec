package rhel

import (
	"io"
	"os"
	"testing"

	"defendsec/internal/feeds"
)

func open() (io.ReadCloser, error) { return os.Open("testdata/rhel9.oval.xml") }

func collect(t *testing.T) (map[string]feeds.Advisory, feeds.Stats) {
	t.Helper()
	got := map[string]feeds.Advisory{}
	st, err := Parse(open, "9", func(a feeds.Advisory) error {
		if _, dup := got[a.ID]; dup {
			t.Errorf("%s emitted twice", a.ID)
		}
		got[a.ID] = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func TestParseFixture(t *testing.T) {
	got, st := collect(t)

	// openssl RHSA: 2 CVEs; curl RHSA: 4 CVEs; nodejs:18 RHSA is module-scoped.
	if st.Advisories != 6 || len(got) != 6 {
		t.Fatalf("advisories = %d / %d, want 6", st.Advisories, len(got))
	}

	a := got["CVE-2022-3602"]
	if a.Severity != "high" { // RHSA impact "important"
		t.Errorf("severity = %q", a.Severity)
	}
	if a.CVSSScore == nil || *a.CVSSScore != 7.5 || a.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Errorf("cvss = %v %q", a.CVSSScore, a.CVSSVector)
	}
	if len(a.CWE) != 1 || a.CWE[0] != "CWE-805" {
		t.Errorf("cwe = %v", a.CWE)
	}
	if a.Summary != "RHSA-2022:7288: openssl security update (Important)" {
		t.Errorf("summary = %q", a.Summary)
	}
	pk := map[string]string{}
	for _, r := range a.Ranges {
		if r.Ecosystem != "Red Hat" || r.Distro != "rhel" || r.Release != "9" || r.State != feeds.Fixed {
			t.Errorf("range = %+v", r)
		}
		pk[r.Package] = r.Fixed
	}
	// Epoch is kept as published: "1:" is part of the version.
	for _, p := range []string{"openssl", "openssl-libs", "openssl-devel", "openssl-perl"} {
		if pk[p] != "1:3.0.1-43.el9_0" {
			t.Errorf("%s fixed = %q", p, pk[p])
		}
	}
	if len(a.Ranges) != 4 {
		t.Errorf("ranges = %d, want 4 (signature and install-check tests must not become ranges)", len(a.Ranges))
	}

	c := got["CVE-2022-27774"]
	if c.Severity != "medium" || len(c.Ranges) != 5 {
		t.Errorf("curl: severity %q ranges %d", c.Severity, len(c.Ranges))
	}
}

func TestModularErrataAreSkippedAndCounted(t *testing.T) {
	got, st := collect(t)
	// nodejs:18 only applies with the module stream enabled; we do not track
	// streams, so it must not become an advisory.
	for id := range got {
		if id == "CVE-2022-3517" || id == "CVE-2022-43548" {
			t.Errorf("module-scoped CVE %s produced an advisory", id)
		}
	}
	if st.Skipped["module-stream range"] == 0 {
		t.Errorf("skipped = %v, want module-stream ranges counted", st.Skipped)
	}
}

func TestMalformedXML(t *testing.T) {
	_, err := Parse(func() (io.ReadCloser, error) { return os.Open("rhel.go") }, "9", func(feeds.Advisory) error { return nil })
	if err == nil {
		t.Fatal("non-XML input parsed without error")
	}
}
