package runner

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Microsoft feed in the real pipeline: fetched from a mirror (a listing and
// monthly documents), loaded as ranges in the "windows" scope, then enriched by
// KEV exactly like a distro feed.
func TestMSRCFeedLoadsKBRangesAndKEVEnrichesThem(t *testing.T) {
	store, pool := tempDB(t)
	u := newUpstream(t)
	u.set("/msrc/updates", readFile(t, "../msrc/testdata/updates.json"))
	for _, id := range []string{"2099-Jan", "2098-Dec", "2098-Nov"} {
		id := id
		u.custom["/msrc/cvrf/"+id] = func(w http.ResponseWriter, r *http.Request) {
			b, err := os.ReadFile(filepath.Join("..", "msrc", "testdata", "cvrf_"+id+".json"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Write(b) //nolint:errcheck
		}
	}
	u.set("/kev.json", []byte(`{"title":"fixture","catalogVersion":"2099.01.15","dateReleased":"2099-01-15T00:00:00Z","count":1,"vulnerabilities":[
{"cveID":"CVE-2099-0001","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Windows Kernel EoP","dateAdded":"2099-01-14","shortDescription":"fixture","requiredAction":"Apply updates","dueDate":"2099-02-04","knownRansomwareCampaignUse":"Unknown"}]}`))
	cfg := Config{
		CacheDir: t.TempDir(), DataDir: t.TempDir(), FetchTimeout: time.Minute, MSRCMonths: 12,
		Enabled:      []string{"msrc", "kev"},
		URLOverrides: map[string]string{"msrc": u.URL + "/msrc", "kev": u.URL + "/kev.json"},
	}
	r := newRunner(t, cfg, store)
	now := time.Date(2099, 2, 1, 0, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return now }
	r.Fetcher.Now = r.Now
	ctx := context.Background()

	results, err := r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := byName(results)
	if got["msrc"].Status != StatusLoaded || got["msrc"].Err != nil {
		t.Fatalf("msrc: status %q err %v", got["msrc"].Status, got["msrc"].Err)
	}
	if got["msrc"].Records != 5 || got["msrc"].Advisories != 4 {
		t.Errorf("msrc records %d advisories %d", got["msrc"].Records, got["msrc"].Advisories)
	}
	if got["kev"].Status != StatusLoaded {
		t.Fatalf("kev: %q %v", got["kev"].Status, got["kev"].Err)
	}
	// One range per (CVE, KB), all in the windows scope with the month's date.
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='windows' AND release IS NULL AND ecosystem='MSRC' AND package = fixed AND package LIKE 'KB%' AND fix_state='fixed'`); n != 5 {
		t.Errorf("windows ranges = %d, want 5", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='windows' AND package='KB5000001' AND issued = DATE '2099-01-12'`); n != 2 {
		t.Errorf("KB5000001 ranges with the month's date = %d, want 2 (two CVEs)", n)
	}
	// The advisory carries Microsoft's severity and CVSS, and KEV marked it.
	var kev bool
	var sev string
	var cvss float64
	if err := pool.QueryRow(ctx, `SELECT kev, severity, cvss_score FROM advisories WHERE id='CVE-2099-0001'`).Scan(&kev, &sev, &cvss); err != nil {
		t.Fatal(err)
	}
	if !kev || sev != "critical" || cvss != 8.8 {
		t.Errorf("advisory kev=%v severity=%s cvss=%v", kev, sev, cvss)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisories WHERE kev AND id <> 'CVE-2099-0001'`); n != 0 {
		t.Errorf("%d other advisories marked KEV", n)
	}

	// A second sync with nothing revised re-reads the listing, not the months, and is unchanged.
	hitsBefore := u.hits["/msrc/cvrf/2099-Jan"]
	results, err = r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st := byName(results)["msrc"].Status; st != StatusUnchanged {
		t.Errorf("second msrc sync = %q, want unchanged", st)
	}
	if u.hits["/msrc/cvrf/2099-Jan"] != hitsBefore {
		t.Errorf("an unrevised month was downloaded again")
	}
}

func TestMSRCIsOptInAndConfigured(t *testing.T) {
	c, err := ConfigFromEnv(func(k string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range c.Enabled {
		if name == "msrc" {
			t.Error("msrc is in the default feed set; a client with no Windows devices should not download it")
		}
	}
	if c.MSRCMonths != 12 {
		t.Errorf("default months = %d", c.MSRCMonths)
	}
	found := false
	for _, s := range Catalog(c) {
		if s.Name == "msrc" && s.Kind == KindMSRC && strings.HasPrefix(s.URL, "https://api.msrc.microsoft.com/") {
			found = true
			sc := s.Scopes()
			if len(sc) != 1 || sc[0].Distro != "windows" || sc[0].Release != "" {
				t.Errorf("scopes = %+v", sc)
			}
		}
	}
	if !found {
		t.Error("msrc is not in the catalog")
	}
	for _, bad := range []string{"0", "37", "x", "-1"} {
		if _, err := ConfigFromEnv(func(k string) string {
			if k == "DEFENDSEC_FEEDS_MSRC_MONTHS" {
				return bad
			}
			return ""
		}); err == nil {
			t.Errorf("months %q accepted", bad)
		}
	}
}
