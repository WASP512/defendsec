package alma

import (
	"os"
	"strings"
	"testing"

	"defendsec/internal/feeds"
)

func parseFixture(t *testing.T) (map[string][]feeds.Advisory, feeds.Stats) {
	t.Helper()
	f, err := os.Open("testdata/errata9.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string][]feeds.Advisory{}
	st, err := Parse(f, "9", func(a feeds.Advisory) error {
		got[a.ID] = append(got[a.ID], a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func TestParseFixture(t *testing.T) {
	got, st := parseFixture(t)
	// kernel erratum: 2 CVEs; openssl: 1 valid CVE; module erratum and the bug
	// fix emit nothing.
	if st.Advisories != 3 {
		t.Fatalf("advisories = %d, want 3 (got %v)", st.Advisories, got)
	}
	k := got["CVE-2026-31678"]
	if len(k) != 1 {
		t.Fatalf("CVE-2026-31678 emitted %d times", len(k))
	}
	a := k[0]
	if a.Severity != "high" || a.Summary != "ALSA-2026:86033: Important: kernel security update" {
		t.Errorf("severity %q summary %q", a.Severity, a.Summary)
	}
	fixed := map[string]string{}
	for _, r := range a.Ranges {
		if r.Distro != "almalinux" || r.Release != "9" || r.Ecosystem != "AlmaLinux" || r.State != feeds.Fixed {
			t.Errorf("range = %+v", r)
		}
		if r.Issued != "2026-10-20" {
			t.Errorf("issued = %q, want the erratum's issue date 2026-10-20", r.Issued)
		}
		fixed[r.Package] = r.Fixed
	}
	// The same build for x86_64 and aarch64 is one range; epoch is always written.
	if len(a.Ranges) != 3 {
		t.Errorf("ranges = %d, want 3 (kernel, kernel-core, kernel-doc): %+v", len(a.Ranges), a.Ranges)
	}
	if fixed["kernel"] != "0:5.14.0-687.59.1.el9_8" {
		t.Errorf("kernel fixed = %q", fixed["kernel"])
	}
	if o := got["CVE-2022-3602"]; len(o) != 1 || len(o[0].Ranges) != 2 || o[0].Ranges[0].Fixed != "1:3.0.1-43.el9_0.alma" {
		t.Errorf("openssl = %+v", o)
	}
	if _, ok := got["not-a-cve"]; ok {
		t.Error("a malformed CVE reference became an advisory")
	}
}

func TestSkipsAreCounted(t *testing.T) {
	got, st := parseFixture(t)
	if _, ok := got["CVE-2022-3517"]; ok {
		t.Error("a module-stream erratum produced an advisory")
	}
	if st.Skipped["module-stream range"] != 1 {
		t.Errorf("skipped = %v, want one module-stream range", st.Skipped)
	}
	if st.Skipped["erratum without CVE"] != 1 {
		t.Errorf("skipped = %v, want the bug fix counted as an erratum without CVE", st.Skipped)
	}
}

func TestRejectsWrongDocuments(t *testing.T) {
	for name, body := range map[string]string{
		"html":        "<html>502 Bad Gateway</html>",
		"empty":       "",
		"no data":     `{"schema_version":"1.0"}`,
		"no errata":   `{"schema_version":"1.0","data":[]}`,
		"truncated":   `{"schema_version":"1.0","data":[{"id":"ALSA-1","type":"security"`,
		"wrong shape": `[]`,
	} {
		if _, err := Parse(strings.NewReader(body), "9", func(feeds.Advisory) error { return nil }); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}
