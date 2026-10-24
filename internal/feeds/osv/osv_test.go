package osv

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"defendsec/internal/feeds"
)

// buildZip packs testdata/*.json (plus extras) into an in-memory all.zip, so no
// binary fixture is committed.
func buildZip(t *testing.T, extra map[string]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, body []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(body)
	}
	files, _ := filepath.Glob("testdata/*.json")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		add(filepath.Base(f), b)
	}
	for n, b := range extra {
		add(n, []byte(b))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func parse(t *testing.T, zr *bytes.Reader, eco string) (map[string]feeds.Advisory, feeds.Stats, error) {
	t.Helper()
	got := map[string]feeds.Advisory{}
	st, err := Parse(zr, zr.Size(), eco, func(a feeds.Advisory) error { got[a.ID] = a; return nil })
	return got, st, err
}

func TestParseFixture(t *testing.T) {
	got, st, err := parse(t, buildZip(t, nil), "PyPI")
	if err != nil {
		t.Fatal(err)
	}
	// flask (fixed ranges), leftpad-py (open range), lastaff (all ranges skipped)
	// and the withdrawn one yield 2 advisories.
	if len(got) != 2 || st.Advisories != 2 {
		t.Fatalf("advisories = %d, want 2: %v", len(got), got)
	}

	f, ok := got["CVE-2023-30861"] // the CVE alias becomes the id
	if !ok {
		t.Fatalf("flask not keyed by CVE alias: %v", got)
	}
	if f.CVE != "CVE-2023-30861" || f.Severity != "high" || f.Summary != "Flask session cookie disclosure" {
		t.Errorf("flask = %+v", f)
	}
	if f.CVSSVector != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" || len(f.CWE) != 1 || f.CWE[0] != "CWE-539" {
		t.Errorf("flask cvss/cwe = %q %v", f.CVSSVector, f.CWE)
	}
	if len(f.Ranges) != 2 {
		t.Fatalf("flask ranges = %+v", f.Ranges)
	}
	r0, r1 := f.Ranges[0], f.Ranges[1]
	if r0.Introduced != "" || r0.Fixed != "2.2.5" || r0.State != feeds.Fixed || r0.Ecosystem != "PyPI" || r0.Distro != "" || r0.Package != "flask" {
		t.Errorf("range 0 = %+v (introduced \"0\" must become empty = from the first version)", r0)
	}
	if r1.Introduced != "2.3.0" || r1.Fixed != "2.3.2" {
		t.Errorf("range 1 = %+v", r1)
	}

	// No CVE alias: the OSV id is the advisory id. No fix: state affected.
	l := got["PYSEC-2024-1"]
	if l.CVE != "" || len(l.Ranges) != 1 {
		t.Fatalf("leftpad = %+v", l)
	}
	if r := l.Ranges[0]; r.State != feeds.Affected || r.Fixed != "" || r.Introduced != "1.0" || r.Package != "leftpad-py" {
		t.Errorf("leftpad range = %+v", r)
	}
	if !strings.HasPrefix(l.Summary, "No fix published") || l.Severity != "unknown" {
		t.Errorf("summary/severity = %q %q", l.Summary, l.Severity)
	}
	// The npm entry inside a PyPI record is not ours.
	for _, r := range l.Ranges {
		if r.Package == "not-this-ecosystem" {
			t.Error("foreign-ecosystem package leaked in")
		}
	}

	if st.Skipped["withdrawn"] != 1 || st.Skipped["last_affected event"] != 1 || st.Skipped["range type GIT"] != 1 {
		t.Errorf("skipped = %v", st.Skipped)
	}
}

func TestOtherEcosystemSelectsOtherRecords(t *testing.T) {
	got, _, err := parse(t, buildZip(t, nil), "npm")
	if err != nil {
		t.Fatal(err)
	}
	r := got["PYSEC-2024-1"]
	if len(got) != 1 || len(r.Ranges) != 1 || r.Ranges[0].Package != "not-this-ecosystem" || r.Ranges[0].Fixed != "9.9.9" {
		t.Fatalf("got %+v", got)
	}
}

func TestBadArchives(t *testing.T) {
	if _, _, err := parse(t, bytes.NewReader([]byte("not a zip")), "PyPI"); err == nil {
		t.Error("non-zip accepted")
	}
	if _, _, err := parse(t, buildZip(t, map[string]string{"broken.json": "{"}), "PyPI"); err == nil || !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("broken record error = %v", err)
	}
}
