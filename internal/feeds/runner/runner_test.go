package runner

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/feeds/fetch"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// End-to-end tests of the sync pipeline against a real Postgres
// (TEST_DATABASE_URL) and an httptest "upstream" serving committed fixtures.
// Each test gets its own throwaway database, because a feed load replaces a
// whole distro/release scope and must not touch rows other tests own.

func tempDB(t *testing.T) (*storepg.Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	rand.Read(b)
	name := "defendsec_feeds_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") //nolint:errcheck
		admin.Close()
	})
	return storepg.New(pool), pool
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// upstream is a fake feed host. Bodies are replaceable; ETag is the body hash,
// so conditional requests behave like the real hosts'.
type upstream struct {
	*httptest.Server
	mu     sync.Mutex
	bodies map[string][]byte
	status map[string]int
	hits   map[string]int
	notMod map[string]int
	// custom answers a path itself (a paged API), under the same lock.
	custom map[string]http.HandlerFunc
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{bodies: map[string][]byte{}, status: map[string]int{}, hits: map[string]int{}, notMod: map[string]int{},
		custom: map[string]http.HandlerFunc{}}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.hits[r.URL.Path]++
		if st := u.status[r.URL.Path]; st != 0 {
			http.Error(w, "upstream says no", st)
			return
		}
		if h, ok := u.custom[r.URL.Path]; ok {
			h(w, r)
			return
		}
		body, ok := u.bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sum := sha256.Sum256(body)
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		if r.Header.Get("If-None-Match") == etag {
			u.notMod[r.URL.Path]++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(body)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) set(path string, body []byte) {
	u.mu.Lock()
	u.bodies[path] = body
	u.mu.Unlock()
}

func (u *upstream) fail(path string, status int) {
	u.mu.Lock()
	u.status[path] = status
	u.mu.Unlock()
}

func gz(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func osvZip(t *testing.T) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files, _ := filepath.Glob("../osv/testdata/*.json")
	for _, f := range files {
		w, _ := zw.Create(filepath.Base(f))
		w.Write(readFile(t, f))
	}
	zw.Close()
	return buf.Bytes()
}

const kevDoc = `{"count":2,"vulnerabilities":[
 {"cveID":"CVE-2022-1292","vendorProject":"OpenSSL","product":"OpenSSL","vulnerabilityName":"OpenSSL c_rehash Command Injection","dateAdded":"2026-09-01","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2099-0001","vendorProject":"Nobody","product":"Nothing","vulnerabilityName":"KEV entry no distro describes","dateAdded":"2026-09-02","knownRansomwareCampaignUse":"Known"}]}`

const epssDoc = "#model_version:v2026.06.15,score_date:2026-10-23T12:00:28Z\ncve,epss,percentile\nCVE-2022-1292,0.50000,0.97000\nCVE-2022-31160,0.01000,0.50000\nCVE-2012-4450,0.02000,0.60000\n"

// feedSet is one self-contained upstream with every feed kind.
func feedSet(t *testing.T) (*upstream, Config) {
	t.Helper()
	u := newUpstream(t)
	u.set("/kev.json", []byte(kevDoc))
	u.set("/epss.csv.gz", gz(t, []byte(epssDoc)))
	u.set("/jammy.xml.bz2", readFile(t, "testdata/jammy.oval.xml.bz2")) // real bzip2
	u.set("/rhel9.xml", readFile(t, "../rhel/testdata/rhel9.oval.xml")) // a mirror serving decompressed
	u.set("/leap16.xml", readFile(t, "../suse/testdata/leap16.oval.xml"))
	u.set("/debian.json", readFile(t, "../debian/testdata/tracker.json"))
	u.set("/pypi.zip", osvZip(t))
	cfg := Config{
		CacheDir: t.TempDir(), DataDir: t.TempDir(), FetchTimeout: time.Minute,
		Enabled:        []string{"kev", "epss", "ubuntu-jammy", "debian", "rhel-9", "suse-leap-16.0", "osv-pypi"},
		OSVEcosystems:  []string{"PyPI"},
		DebianReleases: []string{"bookworm", "trixie"},
		URLOverrides: map[string]string{
			"kev": u.URL + "/kev.json", "epss": u.URL + "/epss.csv.gz", "ubuntu-jammy": u.URL + "/jammy.xml.bz2",
			"debian": u.URL + "/debian.json", "rhel-9": u.URL + "/rhel9.xml", "suse-leap-16.0": u.URL + "/leap16.xml",
			"osv-pypi": u.URL + "/pypi.zip",
		},
	}
	return u, cfg
}

func newRunner(t *testing.T, cfg Config, store *storepg.Store) *Runner {
	t.Helper()
	specs, err := Select(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, specs, store, slog.New(slog.DiscardHandler))
	return r
}

func byName(results []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range results {
		m[r.Name] = r
	}
	return m
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSyncEndToEnd(t *testing.T) {
	store, pool := tempDB(t)
	up, cfg := feedSet(t)
	r := newRunner(t, cfg, store)
	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return t0 }
	r.Fetcher.Now = r.Now
	ctx := context.Background()

	results, err := r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := byName(results)
	for _, name := range []string{"kev", "epss", "ubuntu-jammy", "debian", "rhel-9", "suse-leap-16.0", "osv-pypi"} {
		if got[name].Status != StatusLoaded || got[name].Err != nil {
			t.Errorf("%s: status %q err %v", name, got[name].Status, got[name].Err)
		}
	}
	if got["kev"].Records != 2 {
		t.Errorf("kev records = %d, want 2", got["kev"].Records)
	}
	if got["epss"].Records != 3 {
		t.Errorf("epss records = %d, want 3", got["epss"].Records)
	}
	// Per-scope row counts equal what each feed reported.
	for _, c := range []struct {
		name, distro, release string
	}{
		{"ubuntu-jammy", "ubuntu", "22.04"}, {"rhel-9", "rhel", "9"}, {"suse-leap-16.0", "opensuse-leap", "16.0"},
	} {
		if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro=$1 AND release=$2`, c.distro, c.release); int64(n) != got[c.name].Records || n == 0 {
			t.Errorf("%s: %d rows in db, feed reported %d", c.name, n, got[c.name].Records)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='debian'`); int64(n) != got["debian"].Records || n == 0 {
		t.Errorf("debian: %d rows in db, feed reported %d", n, got["debian"].Records)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE ecosystem='PyPI' AND distro IS NULL`); int64(n) != got["osv-pypi"].Records || n != 3 {
		t.Errorf("osv: %d rows (feed reported %d), want 3 (2 flask + 1 leftpad)", n, got["osv-pypi"].Records)
	}
	// Real bzip2 was decoded, and the ESM range kept its own ecosystem.
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='ubuntu' AND ecosystem='Ubuntu:Pro'`); n != 3 {
		t.Errorf("ubuntu Pro ranges = %d, want 3", n)
	}

	// Enrichment landed on advisories the same run created.
	a, err := store.GetAdvisory(ctx, "CVE-2022-1292")
	if err != nil {
		t.Fatal(err)
	}
	if !a.KEV || a.EPSS == nil || *a.EPSS != 0.5 || a.EPSSDate == nil {
		t.Errorf("CVE-2022-1292 kev=%v epss=%v date=%v", a.KEV, a.EPSS, a.EPSSDate)
	}
	if len(a.Ranges) < 2 {
		t.Errorf("CVE-2022-1292 ranges from other feeds missing: %+v", a.Ranges)
	}
	stub, err := store.GetAdvisory(ctx, "CVE-2099-0001")
	if err != nil || !stub.KEV || stub.Severity != "unknown" || len(stub.Ranges) != 0 {
		t.Errorf("KEV-only stub = %+v err %v", stub, err)
	}
	if x, _ := store.GetAdvisory(ctx, "CVE-2022-31160"); x.EPSS == nil || *x.EPSS != 0.01 {
		t.Errorf("EPSS missing on CVE-2022-31160: %+v", x.EPSS)
	}

	// Snapshot: one, finalized, listing every feed with real counts and digests.
	snap, ok, err := store.LatestFeedSnapshot(ctx)
	if err != nil || !ok {
		t.Fatalf("snapshot: ok=%v err=%v", ok, err)
	}
	if len(snap.Feeds) != 7 {
		t.Fatalf("snapshot feeds = %d, want 7", len(snap.Feeds))
	}
	for _, f := range snap.Feeds {
		res := got[f.Name]
		if f.SHA256 != res.SHA256 || int64(f.RecordCount) != res.Records || !f.FetchedAt.Equal(t0) {
			t.Errorf("snapshot %s = %+v, result %+v", f.Name, f, res)
		}
		if strings.Contains(f.URL, "?") {
			t.Errorf("snapshot URL carries a query: %s", f.URL)
		}
	}
	st, ok, _ := store.GetFeedStatus(ctx, "ubuntu-jammy")
	if !ok || st.SnapshotID == nil || *st.SnapshotID != snap.ID || st.LastSuccess == nil || !st.LastSuccess.Equal(t0) || st.ETag == "" {
		t.Errorf("status = %+v", st)
	}

	// Second run, a day later: everything answers 304; nothing reloads, no new
	// snapshot, but the last-success time moves (the feed was confirmed current).
	t1 := t0.Add(24 * time.Hour)
	r.Now = func() time.Time { return t1 }
	r.Fetcher.Now = r.Now
	results, err = r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range results {
		if res.Status != StatusUnchanged {
			t.Errorf("rerun %s: status %q, want unchanged", res.Name, res.Status)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM feed_snapshots`); n != 1 {
		t.Errorf("snapshots after an unchanged run = %d, want 1", n)
	}
	if up.notMod["/jammy.xml.bz2"] != 1 {
		t.Errorf("conditional GET not used for jammy: %v", up.notMod)
	}
	st, _, _ = store.GetFeedStatus(ctx, "ubuntu-jammy")
	if st.LastSuccess == nil || !st.LastSuccess.Equal(t1) || st.RecordCount != got["ubuntu-jammy"].Records {
		t.Errorf("status after unchanged run = %+v", st)
	}

	// An upstream change reloads just that feed, creates snapshot 2, and
	// re-applies KEV/EPSS so a brand-new advisory is enriched.
	extra := strings.ReplaceAll(string(readFile(t, "../rhel/testdata/rhel9.oval.xml")), "CVE-2022-22576", "CVE-2022-9999")
	up.set("/rhel9.xml", []byte(extra))
	up.set("/epss.csv.gz", gz(t, []byte(epssDoc+"CVE-2022-9999,0.33000,0.80000\n")))
	t2 := t1.Add(time.Hour)
	r.Now = func() time.Time { return t2 }
	r.Fetcher.Now = r.Now
	results, err = r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got = byName(results)
	if got["rhel-9"].Status != StatusLoaded || got["epss"].Status != StatusLoaded || got["ubuntu-jammy"].Status != StatusUnchanged || got["debian"].Status != StatusUnchanged {
		t.Errorf("statuses = rhel9 %s epss %s jammy %s debian %s", got["rhel-9"].Status, got["epss"].Status, got["ubuntu-jammy"].Status, got["debian"].Status)
	}
	if got["kev"].Status != StatusLoaded || !strings.Contains(got["kev"].Note, "re-applied") {
		t.Errorf("kev after a range feed changed: status %q note %q (want re-applied)", got["kev"].Status, got["kev"].Note)
	}
	if n := count(t, pool, `SELECT count(*) FROM feed_snapshots`); n != 2 {
		t.Errorf("snapshots = %d, want 2", n)
	}
	if x, err := store.GetAdvisory(ctx, "CVE-2022-9999"); err != nil || x.EPSS == nil || *x.EPSS != 0.33 {
		t.Errorf("new advisory not enriched: %+v err %v", x.EPSS, err)
	}
	if _, err := store.GetAdvisory(ctx, "CVE-2022-22576"); err == nil {
		// the advisory row remains (rows are never deleted), but its rhel ranges must be gone
		if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE advisory_id='CVE-2022-22576' AND distro='rhel'`); n != 0 {
			t.Errorf("stale rhel ranges for the replaced CVE: %d", n)
		}
	}
}

func TestFailureKeepsGoodDataAndTrueAge(t *testing.T) {
	store, pool := tempDB(t)
	up, cfg := feedSet(t)
	r := newRunner(t, cfg, store)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return t0 }
	r.Fetcher.Now = r.Now
	ctx := context.Background()
	if _, err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	before := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='ubuntu'`)

	// A week later: jammy's host is down and the debian file is junk.
	up.fail("/jammy.xml.bz2", 503)
	up.set("/debian.json", []byte("<html>maintenance</html>"))
	t1 := t0.Add(7 * 24 * time.Hour)
	r.Now = func() time.Time { return t1 }
	r.Fetcher.Now = r.Now
	results, err := r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := byName(results)
	if got["ubuntu-jammy"].Status != StatusFailed || !strings.Contains(got["ubuntu-jammy"].Err.Error(), "503") {
		t.Errorf("jammy = %q %v", got["ubuntu-jammy"].Status, got["ubuntu-jammy"].Err)
	}
	if got["debian"].Status != StatusFailed {
		t.Errorf("debian = %q %v, want failed (junk body)", got["debian"].Status, got["debian"].Err)
	}
	if got["kev"].Status != StatusUnchanged || got["rhel-9"].Status != StatusUnchanged {
		t.Errorf("other feeds disturbed: kev %s rhel %s", got["kev"].Status, got["rhel-9"].Status)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='ubuntu'`); n != before {
		t.Errorf("ubuntu ranges %d -> %d after a failed fetch", before, n)
	}
	st, _, _ := store.GetFeedStatus(ctx, "ubuntu-jammy")
	if st.LastError == "" || st.LastSuccess == nil || !st.LastSuccess.Equal(t0) || st.LastAttempt == nil || !st.LastAttempt.Equal(t1) {
		t.Errorf("jammy status: err %q success %v attempt %v (success must stay at day 0 so the feed shows its true age)", st.LastError, st.LastSuccess, st.LastAttempt)
	}
	// The junk debian download was cached but never parsed into the DB: the
	// loaded digest is still the good one, and the cache was put back to the
	// good copy so `export` can never ship the junk.
	deb, _, _ := store.GetFeedStatus(ctx, "debian")
	if deb.LastError == "" || deb.SHA256 == "" {
		t.Errorf("debian status: %+v", deb)
	}
	if sum, _, err := fetch.FileSHA256(r.Cache.Path("debian")); err != nil || sum != deb.SHA256 {
		t.Errorf("cached debian = %s (%v), loaded digest %s: the junk file stayed in the cache", sum, err, deb.SHA256)
	}
	if _, err := os.Stat(r.Cache.Path("debian") + ".prev"); err == nil {
		t.Error("stash left behind")
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='debian'`); n == 0 {
		t.Error("debian ranges wiped by a junk file")
	}

	// Upstream recovers: both reload.
	up.mu.Lock()
	delete(up.status, "/jammy.xml.bz2")
	up.mu.Unlock()
	up.set("/debian.json", readFile(t, "../debian/testdata/tracker.json"))
	results, err = r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got = byName(results)
	if got["ubuntu-jammy"].Status != StatusUnchanged || got["debian"].Status != StatusUnchanged {
		// jammy's bytes never changed (still the good copy, now confirmed); debian is back to the digest that is loaded
		t.Errorf("after recovery: jammy %s debian %s", got["ubuntu-jammy"].Status, got["debian"].Status)
	}
	st, _, _ = store.GetFeedStatus(ctx, "ubuntu-jammy")
	if st.LastError != "" || !st.LastSuccess.Equal(t1) {
		t.Errorf("jammy after recovery: %+v", st)
	}
}

func TestEmptyAndShrunkFeedsAreRefused(t *testing.T) {
	store, pool := tempDB(t)
	up := newUpstream(t)
	cfg := Config{
		CacheDir: t.TempDir(), DataDir: t.TempDir(), FetchTimeout: time.Minute,
		Enabled: []string{"debian"}, DebianReleases: []string{"bookworm"},
		URLOverrides: map[string]string{"debian": up.URL + "/debian.json"},
	}
	// A big synthetic tracker: 1500 CVEs of one package.
	big := func(n int) []byte {
		var b strings.Builder
		b.WriteString(`{"pkg":{`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"CVE-2020-%04d":{"description":"d","releases":{"bookworm":{"status":"resolved","fixed_version":"1.%d","urgency":"low"}}}`, i+1, i)
		}
		b.WriteString("}}")
		return []byte(b.String())
	}
	ctx := context.Background()
	r := newRunner(t, cfg, store)
	up.set("/debian.json", big(1500))
	if res, err := r.Sync(ctx); err != nil || res[0].Status != StatusLoaded || res[0].Records != 1500 {
		t.Fatalf("initial load: %+v err %v", res, err)
	}

	// A valid but tiny file: refused, data intact, error recorded.
	up.set("/debian.json", big(100))
	res, err := r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != StatusFailed || !strings.Contains(res[0].Err.Error(), "shrank from 1500 to 100") {
		t.Fatalf("shrunk feed: %q %v", res[0].Status, res[0].Err)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='debian'`); n != 1500 {
		t.Errorf("rows after refused load = %d, want 1500", n)
	}
	if st, _, _ := store.GetFeedStatus(ctx, "debian"); !strings.Contains(st.LastError, "shrank") || st.RecordCount != 1500 {
		t.Errorf("status = %+v", st)
	}

	// --force accepts it.
	r.Force = true
	if res, err = r.Sync(ctx); err != nil || res[0].Status != StatusLoaded || res[0].Records != 100 {
		t.Fatalf("forced load: %+v err %v", res, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='debian'`); n != 100 {
		t.Errorf("rows after forced load = %d, want 100", n)
	}

	// A valid-JSON document with no packages / only unwanted releases is an
	// empty parse and is never treated as "everything was fixed".
	r.Force = true
	up.set("/debian.json", []byte(`{"pkg":{"CVE-2020-0001":{"releases":{"sid":{"status":"open","urgency":"low"}}}}}`))
	res, _ = r.Sync(ctx)
	if res[0].Status != StatusFailed || !strings.Contains(res[0].Err.Error(), "no ranges") {
		t.Errorf("empty parse: %q %v", res[0].Status, res[0].Err)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_ranges WHERE distro='debian'`); n != 100 {
		t.Errorf("rows after empty parse = %d, want 100 (untouched)", n)
	}
}

func TestDryRunWritesNothingAndMatchesRealCounts(t *testing.T) {
	store, pool := tempDB(t)
	_, cfg := feedSet(t)
	ctx := context.Background()

	dry := newRunner(t, cfg, nil)
	dryRes, err := dry.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisories`); n != 0 {
		t.Fatalf("dry run touched the database: %d advisories", n)
	}
	for _, r := range dryRes {
		if r.Status != StatusParsed {
			t.Errorf("dry %s: %q %v", r.Name, r.Status, r.Err)
		}
	}

	real := newRunner(t, cfg, store)
	realRes, err := real.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d, rr := byName(dryRes), byName(realRes)
	for name := range rr {
		if d[name].Records != rr[name].Records || d[name].Advisories != rr[name].Advisories {
			t.Errorf("%s: dry run counted %d/%d, real load %d/%d", name, d[name].Records, d[name].Advisories, rr[name].Records, rr[name].Advisories)
		}
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	storeA, poolA := tempDB(t)
	storeB, poolB := tempDB(t)
	upA, cfgA := feedSet(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)

	// Box A (online): sync, then export signed with its control key.
	keyA, err := sign.LoadOrCreate(filepath.Join(cfgA.DataDir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	a := newRunner(t, cfgA, storeA)
	a.Now = func() time.Time { return t0 }
	a.Fetcher.Now = a.Now
	if _, err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "feeds.tar")
	names, err := a.Export(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 7 {
		t.Fatalf("exported %v", names)
	}

	// Box B (air-gapped): its own control key, its own database, no network.
	cfgB := cfgA
	cfgB.CacheDir, cfgB.DataDir = t.TempDir(), t.TempDir()
	cfgB.URLOverrides = map[string]string{} // would fail if it tried to fetch
	if _, err := sign.LoadOrCreate(filepath.Join(cfgB.DataDir, "pki")); err != nil {
		t.Fatal(err)
	}
	b := newRunner(t, cfgB, storeB)
	b.Now = func() time.Time { return t0.Add(48 * time.Hour) }

	// B does not trust A yet.
	if _, err := b.Import(ctx, bundlePath, nil, false); err == nil || !strings.Contains(err.Error(), "does not verify against any trusted key") {
		t.Fatalf("untrusted import: %v", err)
	}
	if n := count(t, poolB, `SELECT count(*) FROM advisories`); n != 0 {
		t.Fatalf("rejected bundle wrote %d advisories", n)
	}
	pubA := filepath.Join(t.TempDir(), "a.pub")
	os.WriteFile(pubA, keyA.PublicPEM(), 0o644)

	results, err := b.Import(ctx, bundlePath, []string{pubA}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Status != StatusLoaded {
			t.Errorf("import %s: %q %v %s", r.Name, r.Status, r.Err, r.Note)
		}
	}

	// B's database is row-for-row what A's is.
	for _, q := range []string{
		`SELECT count(*) FROM advisory_ranges`,
		`SELECT count(*) FROM advisories`,
		`SELECT count(*) FROM advisories WHERE kev`,
		`SELECT count(*) FROM advisories WHERE epss IS NOT NULL`,
	} {
		if x, y := count(t, poolA, q), count(t, poolB, q); x != y || x == 0 {
			t.Errorf("%s: A=%d B=%d", q, x, y)
		}
	}
	var ha, hb string
	const agg = `SELECT md5(string_agg(advisory_id||'|'||ecosystem||'|'||coalesce(distro,'')||'|'||coalesce(release,'')||'|'||package||'|'||coalesce(introduced,'')||'|'||coalesce(fixed,'')||'|'||fix_state, ',' ORDER BY advisory_id, ecosystem, coalesce(distro,''), coalesce(release,''), package, coalesce(introduced,''), coalesce(fixed,''))) FROM advisory_ranges`
	poolA.QueryRow(ctx, agg).Scan(&ha)
	poolB.QueryRow(ctx, agg).Scan(&hb)
	if ha == "" || ha != hb {
		t.Errorf("range digests differ: A=%s B=%s", ha, hb)
	}
	// Age shown on B is the age of the data (A's fetch time), not the import time.
	st, ok, _ := storeB.GetFeedStatus(ctx, "kev")
	if !ok || st.LastSuccess == nil || !st.LastSuccess.Equal(t0) {
		t.Errorf("imported feed last success = %v, want the bundle's fetch time %v", st.LastSuccess, t0)
	}
	// Cached bytes on B are byte-identical to A's.
	for _, n := range names {
		sa, _, _ := fileSum(a.Cache.Path(n))
		sb, _, _ := fileSum(b.Cache.Path(n))
		if sa == "" || sa != sb {
			t.Errorf("cached %s differs: %s vs %s", n, sa, sb)
		}
	}

	// Replaying the same bundle changes nothing; an older bundle is refused as a rollback.
	if results, err = b.Import(ctx, bundlePath, []string{pubA}, false); err != nil {
		t.Fatal(err)
	} else {
		for _, r := range results {
			if r.Status != StatusUnchanged {
				t.Errorf("replay %s: %q", r.Name, r.Status)
			}
		}
	}
	// A fetches a newer KEV catalog a day later and exports again; B takes it.
	upA.set("/kev.json", []byte(strings.Replace(kevDoc, `"count":2`, `"count":3`, 1)[:len(kevDoc)-len(`]}`)]+
		`,{"cveID":"CVE-2099-0002","vulnerabilityName":"Added later","dateAdded":"2026-10-21"}]}`))
	t1 := t0.Add(24 * time.Hour)
	a.Now = func() time.Time { return t1 }
	a.Fetcher.Now = a.Now
	if _, err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(t.TempDir(), "newer.tar")
	if _, err := a.Export(newer); err != nil {
		t.Fatal(err)
	}
	if results, err = b.Import(ctx, newer, []string{pubA}, false); err != nil {
		t.Fatal(err)
	}
	if k := byName(results)["kev"]; k.Status != StatusLoaded || k.Records != 3 {
		t.Fatalf("newer kev: %+v", k)
	}

	// The OLD bundle must not roll KEV back unless forced.
	results, err = b.Import(ctx, bundlePath, []string{pubA}, false)
	if err != nil {
		t.Fatal(err)
	}
	if k := byName(results)["kev"]; k.Status != StatusSkipped || !strings.Contains(k.Note, "older than the cached copy") {
		t.Errorf("rollback not refused: %+v", k)
	}
	if n := count(t, poolB, `SELECT count(*) FROM advisories WHERE kev`); n != 3 {
		t.Errorf("KEV flags after refused rollback = %d, want 3", n)
	}
	results, err = b.Import(ctx, bundlePath, []string{pubA}, true)
	if err != nil {
		t.Fatal(err)
	}
	if k := byName(results)["kev"]; k.Status != StatusLoaded || k.Records != 2 {
		t.Errorf("forced rollback: %+v", k)
	}

	// A bundle for a feed B has not enabled is skipped, not loaded.
	cfgC := cfgB
	cfgC.Enabled = []string{"kev"}
	cfgC.CacheDir = t.TempDir()
	c := newRunner(t, cfgC, storeB)
	results, err = c.Import(ctx, newer, []string{pubA}, true)
	if err != nil {
		t.Fatal(err)
	}
	m := byName(results)
	if m["ubuntu-jammy"].Status != StatusSkipped || !strings.Contains(m["ubuntu-jammy"].Note, "not an enabled feed") {
		t.Errorf("disabled feed: %+v", m["ubuntu-jammy"])
	}
}

func fileSum(path string) (string, int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), int64(len(b)), nil
}
