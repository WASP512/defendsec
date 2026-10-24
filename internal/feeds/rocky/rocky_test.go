package rocky

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"defendsec/internal/feeds"
)

func parseFixture(t *testing.T) (map[string]feeds.Advisory, feeds.Stats) {
	t.Helper()
	raw, err := os.ReadFile("testdata/advisories9.json")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]feeds.Advisory{}
	st, err := Parse(raw, "9", func(a feeds.Advisory) error {
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
	got, st := parseFixture(t)
	// kernel: 2 CVEs, openssl: 1. The module advisory, the bug fix and the
	// release-8-only advisory emit nothing for release 9.
	if st.Advisories != 3 || len(got) != 3 {
		t.Fatalf("advisories = %d / %d, want 3: %v", st.Advisories, len(got), got)
	}
	k := got["CVE-2026-31678"]
	if k.Severity != "high" || k.Summary != "RLSA-2026:86033: Important: kernel security update" {
		t.Errorf("severity %q summary %q", k.Severity, k.Summary)
	}
	if k.CVSSScore == nil || *k.CVSSScore != 7.8 || !strings.HasPrefix(k.CVSSVector, "CVSS:3.1/") || len(k.CWE) != 1 {
		t.Errorf("cvss %v %q cwe %v", k.CVSSScore, k.CVSSVector, k.CWE)
	}
	if got["CVE-2026-52935"].CVSSScore != nil {
		t.Error("an empty score became a CVSS value")
	}
	fixed := map[string]string{}
	for _, r := range k.Ranges {
		if r.Distro != "rocky" || r.Release != "9" || r.Ecosystem != "Rocky Linux" || r.State != feeds.Fixed {
			t.Errorf("range = %+v", r)
		}
		if r.Issued != "2026-10-22" {
			t.Errorf("issued = %q", r.Issued)
		}
		fixed[r.Package] = r.Fixed
	}
	// kernel, kernel-core and kernel-debuginfo: the source RPM is not a package
	// a host has, and two architectures of one build are one range.
	if len(k.Ranges) != 3 || fixed["kernel"] != "0:5.14.0-687.59.1.el9_8" || fixed["kernel-core"] == "" {
		t.Errorf("ranges = %+v", k.Ranges)
	}
	o := got["CVE-2022-3602"]
	if len(o.Ranges) != 2 {
		t.Fatalf("openssl ranges = %+v, want openssl and openssl-libs, release 9 builds only", o.Ranges)
	}
	for _, r := range o.Ranges {
		if !strings.HasPrefix(r.Fixed, "1:3.0.1-") {
			t.Errorf("release 8 build leaked into release 9: %+v", r)
		}
	}
}

func TestReleaseSelectsItsOwnProduct(t *testing.T) {
	raw, _ := os.ReadFile("testdata/advisories9.json")
	got := map[string]feeds.Advisory{}
	if _, err := Parse(raw, "8", func(a feeds.Advisory) error { got[a.ID] = a; return nil }); err != nil {
		t.Fatal(err)
	}
	if o := got["CVE-2022-3602"]; len(o.Ranges) != 1 || o.Ranges[0].Fixed != "1:1.1.1k-9.el8_7" || o.Ranges[0].Release != "8" {
		t.Errorf("release 8 openssl = %+v", o)
	}
	if _, ok := got["CVE-2022-0001"]; !ok {
		t.Error("the release-8-only advisory is missing for release 8")
	}
}

func TestSkipsAreCounted(t *testing.T) {
	_, st := parseFixture(t)
	if st.Skipped["module-stream range"] != 1 {
		t.Errorf("skipped = %v, want the module build counted", st.Skipped)
	}
	if st.Skipped["not a security advisory"] != 1 {
		t.Errorf("skipped = %v, want the bug fix counted", st.Skipped)
	}
}

func TestRejectsWrongDocuments(t *testing.T) {
	for name, body := range map[string]string{
		"html":     "<html>502</html>",
		"empty":    "",
		"no items": `{"advisories":[]}`,
		"array":    `[]`,
	} {
		if _, err := Parse([]byte(body), "9", func(feeds.Advisory) error { return nil }); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

// Apollo lists the CVEs and packages of an advisory in a different order on
// each request. The stored form must not depend on it, or every sync would see
// a "changed" feed.
func TestNormalizeIsOrderIndependentAndKeepsWhatParseNeeds(t *testing.T) {
	a := `{"type":"TYPE_SECURITY","name":"RLSA-1","synopsis":"s","severity":"SEVERITY_LOW","description":"long text","topic":"t",
	  "fixes":[{"ticket":"1"}],"publishedAt":"2026-10-22T00:00:00Z",
	  "cves":[{"name":"CVE-2026-0002","cvss3BaseScore":"5.0","cvss3ScoringVector":"V","cwe":"CWE-1","sourceBy":"MITRE"},{"name":"CVE-2026-0001"}],
	  "rpms":{"Rocky Linux 9":{"nvras":["b-0:1-1.el9.x86_64.rpm","a-0:1-1.el9.x86_64.rpm"]}}}`
	b := `{"rpms":{"Rocky Linux 9":{"nvras":["a-0:1-1.el9.x86_64.rpm","b-0:1-1.el9.x86_64.rpm"]}},"publishedAt":"2026-10-22T00:00:00Z",
	  "cves":[{"name":"CVE-2026-0001"},{"name":"CVE-2026-0002","cvss3BaseScore":"5.0","cvss3ScoringVector":"V","cwe":"CWE-1"}],
	  "severity":"SEVERITY_LOW","synopsis":"s","name":"RLSA-1","type":"TYPE_SECURITY","references":[1,2,3]}`
	na, err := normalize([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	nb, err := normalize([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if string(na) != string(nb) {
		t.Errorf("same advisory, different stored bytes:\n%s\n%s", na, nb)
	}
	for _, dropped := range []string{"description", "topic", "fixes", "references", "sourceBy"} {
		if strings.Contains(string(na), dropped) {
			t.Errorf("normalized form still carries %q: %s", dropped, na)
		}
	}
	// And what Parse needs survives: the round trip through the stored form.
	var got []feeds.Advisory
	doc := `{"advisories":[` + string(na) + `]}`
	if _, err := Parse([]byte(doc), "9", func(x feeds.Advisory) error { got = append(got, x); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "CVE-2026-0001" || len(got[0].Ranges) != 2 || got[1].CVSSScore == nil || got[0].Ranges[0].Issued != "2026-10-22" {
		t.Errorf("parsed %+v", got)
	}
	if _, err := normalize([]byte(`[1]`)); err == nil {
		t.Error("a non-object record was accepted")
	}
}

func TestPagerAsksForOneReleaseWithNothingAboutTheFleet(t *testing.T) {
	p := Pager("https://apollo.build.resf.org/v2/advisories", "9")
	u, err := url.Parse(p.URL(3))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "apollo.build.resf.org" || u.Path != "/v2/advisories" {
		t.Errorf("url = %s", u)
	}
	want := map[string]string{"filters.product": "Rocky Linux 9", "filters.type": "TYPE_SECURITY", "limit": "100", "page": "3"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if len(q) != len(want) {
		t.Errorf("query has extra parameters: %v", q)
	}
	recs, total, err := p.Records([]byte(`{"advisories":[{"name":"RLSA-1"},{"name":"RLSA-2"}],"total":7}`))
	if err != nil || len(recs) != 2 || total != 7 {
		t.Fatalf("Records = %d, %d, %v", len(recs), total, err)
	}
	if k, err := p.Key(recs[1]); err != nil || k != "RLSA-2" {
		t.Errorf("Key = %q, %v", k, err)
	}
	if _, err := p.Key([]byte(`{}`)); err == nil {
		t.Error("a record without a name was accepted")
	}
	// A mirror's own query parameters survive.
	m := Pager("https://mirror.example/v2/advisories?token=abc", "8")
	if mu, _ := url.Parse(m.URL(0)); mu.Query().Get("token") != "abc" || mu.Query().Get("filters.product") != "Rocky Linux 8" {
		t.Errorf("mirror url = %s", mu)
	}
}
