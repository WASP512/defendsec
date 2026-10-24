package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"defendsec/internal/feeds/rocky"
	"defendsec/internal/sign"
)

// rockyPager serves Apollo's /v2/advisories the way the real service does for
// the query the runner sends: the fixture's advisories, `limit` per page,
// {"advisories":[...],"total":N}, an empty list past the end. It records the
// queries it saw so a test can assert nothing but the release filter and the
// page number was sent.
func rockyPager(t *testing.T, u *upstream, fixture string) *[]url.Values {
	t.Helper()
	var doc struct {
		Advisories []json.RawMessage `json:"advisories"`
	}
	if err := json.Unmarshal(readFile(t, fixture), &doc); err != nil {
		t.Fatal(err)
	}
	var seen []url.Values
	u.custom["/v2/advisories"] = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		seen = append(seen, q)
		page, _ := strconv.Atoi(q.Get("page"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		var out []json.RawMessage
		for i := page * limit; i < (page+1)*limit && i < len(doc.Advisories); i++ {
			out = append(out, doc.Advisories[i])
		}
		if out == nil {
			out = []json.RawMessage{}
		}
		json.NewEncoder(w).Encode(map[string]any{"advisories": out, "total": len(doc.Advisories)})
	}
	return &seen
}

func rebuildFeeds(t *testing.T) (*upstream, Config, *[]url.Values) {
	t.Helper()
	u := newUpstream(t)
	seen := rockyPager(t, u, "../rocky/testdata/advisories9.json")
	u.set("/errata9.json", readFile(t, "../alma/testdata/errata9.json"))
	u.set("/rhel9.xml", readFile(t, "../rhel/testdata/rhel9.oval.xml"))
	cfg := Config{
		CacheDir: t.TempDir(), DataDir: t.TempDir(), FetchTimeout: time.Minute,
		Enabled: []string{"rhel-9", "rocky-9", "almalinux-9"},
		URLOverrides: map[string]string{
			"rhel-9": u.URL + "/rhel9.xml", "rocky-9": u.URL + "/v2/advisories", "almalinux-9": u.URL + "/errata9.json",
		},
	}
	return u, cfg, seen
}

func TestRebuildFeedsSyncExportImport(t *testing.T) {
	storeA, poolA := tempDB(t)
	storeB, poolB := tempDB(t)
	_, cfgA, seen := rebuildFeeds(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)

	keyA, err := sign.LoadOrCreate(filepath.Join(cfgA.DataDir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	a := newRunner(t, cfgA, storeA)
	a.Now = func() time.Time { return t0 }
	a.Fetcher.Now = a.Now
	results, err := a.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := byName(results)
	for _, name := range []string{"rhel-9", "rocky-9", "almalinux-9"} {
		if got[name].Status != StatusLoaded || got[name].Err != nil {
			t.Fatalf("%s: status %q err %v", name, got[name].Status, got[name].Err)
		}
	}

	// Rocky: the release filter and a page number, nothing else.
	if len(*seen) == 0 {
		t.Fatal("Rocky's errata service was never asked")
	}
	for _, q := range *seen {
		for k := range q {
			switch k {
			case "filters.product", "filters.type", "limit", "page":
			default:
				t.Errorf("unexpected query parameter %q sent to the errata service", k)
			}
		}
		if q.Get("filters.product") != "Rocky Linux 9" || q.Get("filters.type") != "TYPE_SECURITY" {
			t.Errorf("query = %v", q)
		}
	}
	if got["rocky-9"].URL != a.Specs[1].URL && !strings.HasSuffix(got["rocky-9"].URL, "/v2/advisories") {
		t.Errorf("recorded url %q should be the service URL without a query", got["rocky-9"].URL)
	}

	// Each rebuild's ranges are in its own scope, with the erratum date.
	for _, c := range []struct {
		distro string
		want   int64
	}{{"rocky", got["rocky-9"].Records}, {"almalinux", got["almalinux-9"].Records}} {
		if n := count(t, poolA, `SELECT count(*) FROM advisory_ranges WHERE distro=$1 AND release='9'`, c.distro); int64(n) != c.want || n == 0 {
			t.Errorf("%s: %d rows in db, feed reported %d", c.distro, n, c.want)
		}
		if n := count(t, poolA, `SELECT count(*) FROM advisory_ranges WHERE distro=$1 AND issued IS NULL`, c.distro); n != 0 {
			t.Errorf("%s: %d ranges without an issue date", c.distro, n)
		}
	}
	if n := count(t, poolA, `SELECT count(*) FROM advisory_ranges WHERE distro='rhel' AND issued = DATE '2022-11-01'`); n == 0 {
		t.Error("Red Hat's ranges lost the advisory issue date")
	}
	adv, err := storeA.GetAdvisory(ctx, "CVE-2026-31678")
	if err != nil {
		t.Fatal(err)
	}
	var rockyKernel, almaKernel string
	for _, r := range adv.Ranges {
		if r.Package == "kernel" && r.Distro == "rocky" {
			rockyKernel = r.Fixed + " " + r.Issued + " " + r.Feed
		}
		if r.Package == "kernel" && r.Distro == "almalinux" {
			almaKernel = r.Fixed + " " + r.Issued + " " + r.Feed
		}
	}
	if rockyKernel != "0:5.14.0-687.59.1.el9_8 2026-10-22 rocky-9" || almaKernel != "0:5.14.0-687.59.1.el9_8 2026-10-20 almalinux-9" {
		t.Errorf("kernel ranges: rocky %q alma %q", rockyKernel, almaKernel)
	}

	// The snapshot records every rebuild feed with its own digest.
	snap, ok, err := storeA.LatestFeedSnapshot(ctx)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	refs := map[string]string{}
	for _, f := range snap.Feeds {
		refs[f.Name] = f.SHA256
	}
	for _, n := range []string{"rhel-9", "rocky-9", "almalinux-9"} {
		if len(refs[n]) != 64 || refs[n] != got[n].SHA256 {
			t.Errorf("snapshot digest for %s = %q, run said %q", n, refs[n], got[n].SHA256)
		}
	}

	// A second sync with identical upstream data is a no-op for the walked feed
	// too: the stored file is byte-for-byte the same, so the digest matches.
	again, err := a.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rhel-9", "rocky-9", "almalinux-9"} {
		if s := byName(again)[name].Status; s != StatusUnchanged {
			t.Errorf("second sync %s: %q, want unchanged", name, s)
		}
	}

	// Offline: export the cache, import it on a box with no network.
	bundlePath := filepath.Join(t.TempDir(), "feeds.tar")
	names, err := a.Export(bundlePath)
	if err != nil || len(names) != 3 {
		t.Fatalf("export %v: %v", names, err)
	}
	cfgB := cfgA
	cfgB.CacheDir, cfgB.DataDir = t.TempDir(), t.TempDir()
	cfgB.URLOverrides = map[string]string{}
	if _, err := sign.LoadOrCreate(filepath.Join(cfgB.DataDir, "pki")); err != nil {
		t.Fatal(err)
	}
	b := newRunner(t, cfgB, storeB)
	b.Now = func() time.Time { return t0.Add(time.Hour) }
	pubA := filepath.Join(t.TempDir(), "a.pub")
	os.WriteFile(pubA, keyA.PublicPEM(), 0o644)
	imported, err := b.Import(ctx, bundlePath, []string{pubA}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range imported {
		if r.Status != StatusLoaded {
			t.Errorf("import %s: %q %v %s", r.Name, r.Status, r.Err, r.Note)
		}
	}
	for _, q := range []string{
		`SELECT count(*) FROM advisory_ranges WHERE distro='rocky'`,
		`SELECT count(*) FROM advisory_ranges WHERE distro='almalinux'`,
		`SELECT count(*) FROM advisory_ranges WHERE issued IS NOT NULL`,
	} {
		if x, y := count(t, poolA, q), count(t, poolB, q); x != y || x == 0 {
			t.Errorf("%s: A=%d B=%d", q, x, y)
		}
	}
}

// A Rocky walk that comes back short or empty must leave the loaded data and
// the cache alone, like every other feed.
func TestRockyEmptyWalkKeepsLoadedData(t *testing.T) {
	store, pool := tempDB(t)
	u, cfg, _ := rebuildFeeds(t)
	cfg.Enabled = []string{"rocky-9"}
	ctx := context.Background()
	r := newRunner(t, cfg, store)
	if _, err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	before := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='rocky'`)
	if before == 0 {
		t.Fatal("nothing loaded")
	}
	u.custom["/v2/advisories"] = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"advisories": []any{}, "total": 0})
	}
	results, err := r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s := byName(results)["rocky-9"]; s.Status != StatusFailed {
		t.Fatalf("an empty walk: status %q err %v", s.Status, s.Err)
	}
	if after := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='rocky'`); after != before {
		t.Errorf("rocky ranges %d -> %d after a failed walk", before, after)
	}
	if _, ok, _ := r.Cache.LoadMeta("rocky-9"); !ok {
		t.Error("the cached copy was lost")
	}
}

func TestCatalogHasRebuildFeeds(t *testing.T) {
	c := Config{CacheDir: "x", DataDir: "x", URLOverrides: map[string]string{}}
	found := map[string]Spec{}
	for _, s := range Catalog(c) {
		found[s.Name] = s
	}
	for name, want := range map[string]struct {
		kind                 Kind
		distro, release, url string
	}{
		"rocky-9":     {KindRocky, "rocky", "9", "https://apollo.build.resf.org/v2/advisories"},
		"rocky-8":     {KindRocky, "rocky", "8", "https://apollo.build.resf.org/v2/advisories"},
		"almalinux-9": {KindAlma, "almalinux", "9", "https://errata.almalinux.org/9/errata.full.json"},
		"almalinux-8": {KindAlma, "almalinux", "8", "https://errata.almalinux.org/8/errata.full.json"},
	} {
		s, ok := found[name]
		if !ok || s.Kind != want.kind || s.Distro != want.distro || s.Release != want.release || s.URL != want.url {
			t.Errorf("%s = %+v", name, s)
		}
		if sc := s.Scopes(); len(sc) != 1 || sc[0].Distro != want.distro || sc[0].Release != want.release {
			t.Errorf("%s scopes = %+v", name, sc)
		}
	}
	for _, n := range []string{"rocky-8", "rocky-9", "almalinux-8", "almalinux-9"} {
		in := false
		for _, d := range DefaultEnabled {
			in = in || d == n
		}
		if !in {
			t.Errorf("%s is not enabled by default: a Rocky or Alma host would be reported as not assessed", n)
		}
	}
	// The page walk stays within what the pager builds.
	if q := rocky.Pager("https://apollo.build.resf.org/v2/advisories", "8").URL(0); !strings.Contains(q, "Rocky+Linux+8") {
		t.Errorf("pager url %q", q)
	}
}
