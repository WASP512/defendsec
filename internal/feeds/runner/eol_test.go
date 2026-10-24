package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"defendsec/internal/sign"
)

// The endoflife.date calendar goes through the same pipeline as every other
// feed: conditional fetch, snapshot with SHA-256, signed offline bundle, the
// age the console banner shows, and a refusal to replace good data with a bad
// download.

func eolConfig(t *testing.T, u *upstream) Config {
	t.Helper()
	return Config{
		CacheDir: t.TempDir(), DataDir: t.TempDir(), FetchTimeout: time.Minute,
		Enabled:      []string{"endoflife"},
		URLOverrides: map[string]string{"endoflife": u.URL + "/eol.json"},
	}
}

func TestEndOfLifeFeedSyncsSnapshotsAndRefusesBadData(t *testing.T) {
	store, pool := tempDB(t)
	u := newUpstream(t)
	fixture := readFile(t, "../endoflife/testdata/products-trimmed.json")
	u.set("/eol.json", fixture)
	cfg := eolConfig(t, u)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 24, 6, 0, 0, 0, time.UTC)
	r := newRunner(t, cfg, store)
	r.Now = func() time.Time { return t0 }
	r.Fetcher.Now = r.Now

	results, err := r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res := byName(results)["endoflife"]
	// 7 kept products are in the trimmed file (android is not kept): php 5, windows 4, windows-server 3,
	// nodejs 5, python 3, postgresql 4, dotnet 4 releases.
	if res.Status != StatusLoaded || res.Records != 28 || res.Advisories != 7 || res.SnapshotID == 0 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Note, "schema=1.2.1") {
		t.Errorf("note = %q", res.Note)
	}
	if n := count(t, pool, `SELECT count(*) FROM eol_releases`); n != 28 {
		t.Errorf("eol_releases = %d, want 28", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM eol_releases WHERE product = 'php' AND cycle = '8.0' AND eol_from = DATE '2023-11-26' AND snapshot_id = $1`, res.SnapshotID); n != 1 {
		t.Errorf("php 8.0 row missing or wrong (the motivating release)")
	}
	if n := count(t, pool, `SELECT count(*) FROM eol_releases WHERE product = 'android'`); n != 0 {
		t.Errorf("an unmapped product was stored")
	}
	// the banner's inputs: status row with the fetch time, snapshot naming the feed with its digest
	st, ok, _ := store.GetFeedStatus(ctx, "endoflife")
	if !ok || st.LastSuccess == nil || !st.LastSuccess.Equal(t0) || st.SHA256 == "" || st.Kind != "endoflife" {
		t.Fatalf("status = %+v", st)
	}
	snap, ok, _ := store.LatestFeedSnapshot(ctx)
	if !ok || len(snap.Feeds) != 1 || snap.Feeds[0].Name != "endoflife" || snap.Feeds[0].SHA256 != st.SHA256 {
		t.Fatalf("snapshot = %+v", snap)
	}

	// unchanged upstream: conditional GET, nothing reloaded
	results, err = r.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res := byName(results)["endoflife"]; res.Status != StatusUnchanged {
		t.Errorf("second sync = %+v", res)
	}
	if u.notMod["/eol.json"] != 1 {
		t.Errorf("conditional requests answered 304 = %d, want 1", u.notMod["/eol.json"])
	}

	// A build that keeps more products than the stored calendar has (an upgrade
	// added the Windows ones) reloads an unchanged document instead of leaving
	// them out for ever.
	if _, err := pool.Exec(ctx, `DELETE FROM eol_releases WHERE product LIKE 'windows%'`); err != nil {
		t.Fatal(err)
	}
	if results, err = r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if res := byName(results)["endoflife"]; res.Status != StatusLoaded {
		t.Errorf("sync with an incomplete calendar = %+v, want loaded", res)
	}
	if n := count(t, pool, `SELECT count(*) FROM eol_releases WHERE product IN ('windows', 'windows-server')`); n != 7 {
		t.Errorf("windows rows after the reload = %d, want 7", n)
	}

	// A truncated download (total disagrees with the products it has) and a
	// schema this build cannot read both fail, and the loaded calendar stays.
	for name, body := range map[string]string{
		"truncated":  `{"schema_version":"1.2.1","total":485,"result":[{"name":"php","label":"PHP","releases":[{"name":"8.0","eolFrom":"2023-11-26"}]}]}`,
		"v2":         `{"schema_version":"2.0.0","total":1,"result":[{"name":"php","label":"PHP","releases":[{"name":"8.0"}]}]}`,
		"no mapped":  `{"schema_version":"1.2.1","total":1,"result":[{"name":"android","label":"Android","releases":[{"name":"4.3"}]}]}`,
		"error page": `<html>502 Bad Gateway</html>`,
	} {
		u.set("/eol.json", []byte(body))
		results, err = r.Sync(ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res := byName(results)["endoflife"]; res.Status != StatusFailed || res.Err == nil {
			t.Errorf("%s: %+v, want a failure", name, res)
		}
		if n := count(t, pool, `SELECT count(*) FROM eol_releases`); n != 28 {
			t.Fatalf("%s replaced the calendar: %d rows", name, n)
		}
		// the age is the time of the last good load, not of the failed attempt
		if st, _, _ := store.GetFeedStatus(ctx, "endoflife"); st.LastSuccess == nil || !st.LastSuccess.Equal(t0) || st.LastError == "" {
			t.Errorf("%s: status = %+v", name, st)
		}
	}
}

func TestEndOfLifeFeedTravelsInASignedBundle(t *testing.T) {
	storeA, _ := tempDB(t)
	storeB, poolB := tempDB(t)
	u := newUpstream(t)
	u.set("/eol.json", readFile(t, "../endoflife/testdata/products-trimmed.json"))
	cfgA := eolConfig(t, u)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 24, 6, 0, 0, 0, time.UTC)

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
	bundle := filepath.Join(t.TempDir(), "feeds.tar")
	if names, err := a.Export(bundle); err != nil || len(names) != 1 || names[0] != "endoflife" {
		t.Fatalf("export = %v, %v", names, err)
	}

	// An air-gapped install: its own database, no network, A's public key trusted.
	cfgB := cfgA
	cfgB.CacheDir, cfgB.DataDir = t.TempDir(), t.TempDir()
	cfgB.URLOverrides = map[string]string{}
	pub := filepath.Join(t.TempDir(), "a.pub")
	if err := os.WriteFile(pub, keyA.PublicPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	b := newRunner(t, cfgB, storeB)
	b.Now = func() time.Time { return t0.Add(72 * time.Hour) }
	results, err := b.Import(ctx, bundle, []string{pub}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res := byName(results)["endoflife"]; res.Status != StatusLoaded || res.Records != 28 {
		t.Fatalf("import = %+v", res)
	}
	if n := count(t, poolB, `SELECT count(*) FROM eol_releases WHERE product = 'php' AND cycle = '8.0' AND eol_from = DATE '2023-11-26'`); n != 1 {
		t.Errorf("php 8.0 missing after import")
	}
	// the banner shows the age of the data, not of the import
	if st, _, _ := storeB.GetFeedStatus(ctx, "endoflife"); st.LastSuccess == nil || !st.LastSuccess.Equal(t0) {
		t.Errorf("last success = %v, want %v", st.LastSuccess, t0)
	}
}
