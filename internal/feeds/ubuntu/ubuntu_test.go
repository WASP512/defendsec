package ubuntu

import (
	"io"
	"os"
	"testing"

	"defendsec/internal/feeds"
)

func open(path string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return os.Open(path) }
}

func collect(t *testing.T) (map[string][]feeds.Advisory, feeds.Stats) {
	t.Helper()
	got := map[string][]feeds.Advisory{}
	st, err := Parse(open("testdata/jammy.oval.xml"), "22.04", func(a feeds.Advisory) error {
		got[a.ID] = append(got[a.ID], a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func TestParseFixture(t *testing.T) {
	got, st := collect(t)

	// 1 CVE in the jQuery UI USN + 4 in OpenSSL; the kernel USN yields none.
	if st.Advisories != 5 {
		t.Fatalf("advisories = %d, want 5 (%v)", st.Advisories, got)
	}

	jq := got["CVE-2022-31160"]
	if len(jq) != 1 {
		t.Fatalf("CVE-2022-31160 emitted %d times", len(jq))
	}
	a := jq[0]
	if a.Severity != "medium" || a.CVSSScore == nil || *a.CVSSScore != 6.1 || a.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" {
		t.Errorf("severity/cvss = %q %v %q", a.Severity, a.CVSSScore, a.CVSSVector)
	}
	if a.Summary != "USN-5181-1 -- jQuery UI vulnerability" {
		t.Errorf("summary = %q", a.Summary)
	}
	if len(a.Ranges) != 3 {
		t.Fatalf("ranges = %+v", a.Ranges)
	}
	for _, r := range a.Ranges {
		// "esm-apps/jammy" pocket and a ~esm version: Pro-only fix.
		if r.Ecosystem != "Ubuntu:Pro" || r.Distro != "ubuntu" || r.Release != "22.04" ||
			r.SourcePackage != "jqueryui" || r.Fixed != "1.13.1+dfsg-1ubuntu0.1~esm1" || r.State != feeds.Fixed {
			t.Errorf("range = %+v", r)
		}
	}
	names := map[string]bool{}
	for _, r := range a.Ranges {
		names[r.Package] = true
	}
	for _, want := range []string{"libjs-jquery-ui", "libjs-jquery-ui-docs", "node-jquery-ui"} {
		if !names[want] {
			t.Errorf("missing binary package %s", want)
		}
	}

	// OpenSSL: a regular (non-Pro) fix over two binary packages, per-CVE severity
	// from the CVE's own priority.
	crit := got["CVE-2022-1292"][0]
	if crit.Severity != "medium" || *crit.CVSSScore != 9.8 {
		t.Errorf("CVE-2022-1292 severity %q score %v (priority is medium, cvss 9.8: both kept as published)", crit.Severity, *crit.CVSSScore)
	}
	if got["CVE-2022-1434"][0].Severity != "low" {
		t.Errorf("CVE-2022-1434 severity = %q", got["CVE-2022-1434"][0].Severity)
	}
	if len(crit.Ranges) != 2 {
		t.Fatalf("openssl ranges = %+v", crit.Ranges)
	}
	for _, r := range crit.Ranges {
		if r.Ecosystem != "Ubuntu" || r.SourcePackage != "openssl" || r.Fixed != "3.0.2-0ubuntu1.1" {
			t.Errorf("openssl range = %+v", r)
		}
	}
}

func TestKernelDefinitionsAreSkippedAndCounted(t *testing.T) {
	got, st := collect(t)
	for id := range got {
		if id == "CVE-2022-1015" || id == "CVE-2022-1016" || id == "CVE-2022-26490" {
			t.Errorf("kernel-only CVE %s produced an advisory", id)
		}
	}
	if st.Skipped["kernel running-version test"] != 1 {
		t.Errorf("skipped = %v, want 1 (one kernel definition)", st.Skipped)
	}
}

func TestEmitErrorStopsParse(t *testing.T) {
	n := 0
	_, err := Parse(open("testdata/jammy.oval.xml"), "22.04", func(feeds.Advisory) error {
		n++
		return io.ErrClosedPipe
	})
	if err != io.ErrClosedPipe || n != 1 {
		t.Fatalf("err=%v n=%d", err, n)
	}
}

func TestMalformedXML(t *testing.T) {
	_, err := Parse(func() (io.ReadCloser, error) { return os.Open("ubuntu.go") }, "22.04", func(feeds.Advisory) error { return nil })
	if err == nil {
		t.Fatal("non-XML input parsed without error")
	}
}
