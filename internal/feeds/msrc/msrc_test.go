package msrc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/fetch"
)

func readTD(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReduceKeepsOnlyCVEsWithAKB(t *testing.T) {
	up, err := Reduce(strings.NewReader(string(readTD(t, "cvrf_2099-Jan.json"))))
	if err != nil {
		t.Fatal(err)
	}
	if up.ID != "2099-Jan" || up.Released != "2099-01-12" {
		t.Fatalf("update = %+v", up)
	}
	// CVE-2099-0003 (Azure Linux release notes), ADV990001 (not a CVE) and
	// CVE-2099-0004 (no numeric KB) are dropped.
	if len(up.CVEs) != 2 || up.CVEs[0].CVE != "CVE-2099-0001" || up.CVEs[1].CVE != "CVE-2099-0002" {
		t.Fatalf("cves = %+v", up.CVEs)
	}
	c := up.CVEs[0]
	// The highest severity and CVSS score across products win, and the vector goes with the score.
	if c.Severity != "Critical" || c.CVSS == nil || *c.CVSS != 8.8 || !strings.Contains(c.Vector, "AV:N") {
		t.Errorf("severity/cvss: %+v", c)
	}
	if c.Title != "Windows Kernel Elevation of Privilege Vulnerability" {
		t.Errorf("title = %q", c.Title)
	}
	if len(c.KBs) != 2 || c.KBs[0].KB != "KB5000001" || c.KBs[1].KB != "KB5000003" {
		t.Fatalf("kbs = %+v", c.KBs)
	}
	if c.KBs[0].Supersedes != "KB4990001" {
		t.Errorf("supersedes = %q", c.KBs[0].Supersedes)
	}
	if got := strings.Join(c.KBs[0].Products, "|"); got != "Windows 10 Version 22H2 for x64-based Systems|Windows 11 Version 24H2 for x64-based Systems" {
		t.Errorf("products = %q", got)
	}
	if got := strings.Join(c.KBs[1].Products, "|"); got != "Windows 10 Version 1809 for x64-based Systems|Windows Server 2019" {
		t.Errorf("products of the second KB = %q", got)
	}
	if up.CVEs[1].CVSS == nil || *up.CVEs[1].CVSS != 5.5 || up.CVEs[1].Severity != "Moderate" {
		t.Errorf("second cve = %+v", up.CVEs[1])
	}
}

func TestReduceRefusesWhatIsNotACVRFMonth(t *testing.T) {
	for name, doc := range map[string]string{
		"garbage":        `<html>`,
		"no id":          `{"DocumentTracking":{"InitialReleaseDate":"2099-01-12T08:00:00"}}`,
		"id not a month": `{"DocumentTracking":{"Identification":{"ID":{"Value":"../etc"}},"InitialReleaseDate":"2099-01-12T08:00:00"}}`,
		"no date":        `{"DocumentTracking":{"Identification":{"ID":{"Value":"2099-Jan"}}}}`,
	} {
		if _, err := Reduce(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSelectMonths(t *testing.T) {
	now := time.Date(2099, 2, 1, 0, 0, 0, 0, time.UTC)
	m, err := SelectMonths(readTD(t, "updates.json"), 12, now)
	if err != nil {
		t.Fatal(err)
	}
	// Mariner notes, the month that has not been released, and the malformed id are out.
	var ids []string
	for _, x := range m {
		ids = append(ids, x.ID)
	}
	if strings.Join(ids, ",") != "2099-Jan,2098-Dec,2098-Nov" {
		t.Fatalf("months = %v", ids)
	}
	m, _ = SelectMonths(readTD(t, "updates.json"), 2, now)
	if len(m) != 2 || m[0].ID != "2099-Jan" {
		t.Fatalf("limited months = %+v", m)
	}
	if _, err := SelectMonths([]byte(`{"value":[]}`), 12, now); err == nil {
		t.Error("an empty listing was accepted")
	}
	if _, err := SelectMonths([]byte(`nope`), 12, now); err == nil {
		t.Error("garbage accepted")
	}
}

type mirror struct {
	*httptest.Server
	mu      sync.Mutex
	hits    map[string]int
	current map[string]string // ID -> CurrentReleaseDate to advertise
	failID  string
}

func newMirror(t *testing.T) *mirror {
	t.Helper()
	m := &mirror{hits: map[string]int{}, current: map[string]string{}}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits[r.URL.Path]++
		m.mu.Unlock()
		switch {
		case r.URL.Path == "/updates":
			var l map[string]any
			_ = json.Unmarshal(readTD(t, "updates.json"), &l)
			for _, e := range l["value"].([]any) {
				em := e.(map[string]any)
				m.mu.Lock()
				if c, ok := m.current[em["ID"].(string)]; ok {
					em["CurrentReleaseDate"] = c
				}
				m.mu.Unlock()
			}
			b, _ := json.Marshal(l)
			w.Write(b) //nolint:errcheck
		case strings.HasPrefix(r.URL.Path, "/cvrf/"):
			id := strings.TrimPrefix(r.URL.Path, "/cvrf/")
			if id == m.failID {
				http.Error(w, "boom", http.StatusBadRequest)
				return
			}
			b, err := os.ReadFile(filepath.Join("testdata", "cvrf_"+id+".json"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Write(b) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *mirror) count(path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits[path]
}

func newFetcher(t *testing.T) *fetch.Fetcher {
	return &fetch.Fetcher{Cache: fetch.Cache{Dir: t.TempDir()}, Now: func() time.Time { return time.Date(2099, 2, 1, 0, 0, 0, 0, time.UTC) }}
}

func TestFetchDownloadsOnlyRevisedMonthsAndKeepsADigest(t *testing.T) {
	m := newMirror(t)
	f := newFetcher(t)
	ctx := context.Background()

	res, err := Fetch(ctx, f, "msrc", m.URL, 12)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"2099-Jan", "2098-Dec", "2098-Nov"} {
		if n := m.count("/cvrf/" + id); n != 1 {
			t.Errorf("%s downloaded %d times on the first sync", id, n)
		}
	}
	if !res.Changed || res.Size == 0 {
		t.Errorf("result = %+v", res)
	}
	first := res.SHA256

	// Nothing revised: only the listing is asked for, and the digest is the same.
	res, err = Fetch(ctx, f, "msrc", m.URL, 12)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"2099-Jan", "2098-Dec", "2098-Nov"} {
		if n := m.count("/cvrf/" + id); n != 1 {
			t.Errorf("%s downloaded again (%d) though Microsoft had not revised it", id, n)
		}
	}
	if res.SHA256 != first || res.Changed {
		t.Errorf("an unchanged upstream changed the digest: %s vs %s changed=%v", res.SHA256, first, res.Changed)
	}

	// Microsoft revises December: that month, and only that month, is fetched again.
	m.current["2098-Dec"] = "2098-12-20T10:00:00Z"
	if _, err = Fetch(ctx, f, "msrc", m.URL, 12); err != nil {
		t.Fatal(err)
	}
	if m.count("/cvrf/2098-Dec") != 2 || m.count("/cvrf/2099-Jan") != 1 || m.count("/cvrf/2098-Nov") != 1 {
		t.Errorf("hits: dec %d jan %d nov %d", m.count("/cvrf/2098-Dec"), m.count("/cvrf/2099-Jan"), m.count("/cvrf/2098-Nov"))
	}

	// A smaller window drops the oldest month from the cache and from the file.
	res, err = Fetch(ctx, f, "msrc", m.URL, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.Cache.Dir, "msrc", "months", "2098-Nov.json")); err == nil {
		t.Error("a month outside the window was kept in the cache")
	}
	raw, _ := os.ReadFile(res.Path)
	if strings.Contains(string(raw), "CVE-2098-0900") || !strings.Contains(string(raw), "CVE-2098-1000") {
		t.Errorf("window not applied to the stored file: %s", raw)
	}
}

func TestFetchFailsWholeWhenAMonthCannotBeRead(t *testing.T) {
	m := newMirror(t)
	f := newFetcher(t)
	m.failID = "2098-Dec"
	if _, err := Fetch(context.Background(), f, "msrc", m.URL, 12); err == nil {
		t.Fatal("a feed missing a month was stored as if complete")
	}
	if _, ok, _ := f.Cache.LoadMeta("msrc"); ok {
		t.Error("a half-fetched feed became the cached copy")
	}
}

func TestParseEmitsOneRangePerKB(t *testing.T) {
	m := newMirror(t)
	f := newFetcher(t)
	res, err := Fetch(context.Background(), f, "msrc", m.URL, 12)
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	got := map[string]feeds.Advisory{}
	st, err := Parse(fh, func(a feeds.Advisory) error { got[a.ID] = a; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if st.Advisories != 4 || st.Ranges != 5 {
		t.Errorf("stats = %+v", st)
	}
	a := got["CVE-2099-0001"]
	if a.Severity != "critical" || a.CVSSScore == nil || *a.CVSSScore != 8.8 || a.Summary == "" || a.CVE != "CVE-2099-0001" {
		t.Errorf("advisory = %+v", a)
	}
	if len(a.Ranges) != 2 {
		t.Fatalf("ranges = %+v", a.Ranges)
	}
	r := a.Ranges[0]
	if r.Ecosystem != "MSRC" || r.Distro != "windows" || r.Release != "" || r.Package != "KB5000001" || r.Fixed != "KB5000001" ||
		r.State != feeds.Fixed || r.Issued != "2099-01-12" {
		t.Errorf("range = %+v", r)
	}
	if got["CVE-2099-0002"].Severity != "medium" || got["CVE-2098-1000"].Ranges[0].Issued != "2098-12-08" {
		t.Errorf("others = %+v %+v", got["CVE-2099-0002"], got["CVE-2098-1000"])
	}
}

func TestParseRefusesEmptyAndGarbage(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"updates":[]}`), func(feeds.Advisory) error { return nil }); err == nil {
		t.Error("an empty feed file was accepted")
	}
	if _, err := Parse(strings.NewReader(`zzz`), func(feeds.Advisory) error { return nil }); err == nil {
		t.Error("garbage accepted")
	}
}
