package storepg

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Feed loading against a real Postgres (TEST_DATABASE_URL). Tests use a private
// distro name and CVE-ID prefix so they neither depend on nor disturb rows other
// tests created, and remove what they wrote.

func feedFixture(t *testing.T, s *Store) (distro, prefix string) {
	t.Helper()
	id := randID(t)
	distro, prefix = "testdistro-"+id, "CVE-2099-"+id[:6]+"-"
	t.Cleanup(func() {
		ctx := context.Background()
		s.pool.Exec(ctx, `DELETE FROM advisories WHERE id LIKE $1`, prefix+"%")   //nolint:errcheck
		s.pool.Exec(ctx, `DELETE FROM advisory_ranges WHERE distro = $1`, distro) //nolint:errcheck
	})
	return distro, prefix
}

func rng(distro, rel, pkg, fixed string, st FixState) AdvisoryRange {
	return AdvisoryRange{Ecosystem: "Test", Distro: distro, Release: rel, Package: pkg, SourcePackage: pkg, Fixed: fixed, FixState: st}
}

func mustLoad(t *testing.T, s *Store, source string, scopes []RangeScope, snap int64, advs ...Advisory) FeedLoadResult {
	t.Helper()
	ctx := context.Background()
	l, err := s.BeginFeedLoad(ctx, source, scopes, snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range advs {
		if err := l.Add(ctx, a); err != nil {
			l.Rollback(ctx)
			t.Fatal(err)
		}
	}
	res, err := l.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestFeedLoadReplacesOnlyItsScope(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro, p := feedFixture(t, s)
	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{{Name: "t", URL: "https://example.invalid/t", FetchedAt: time.Now(), SHA256: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}

	res := mustLoad(t, s, "test-feed", []RangeScope{{Distro: distro, Release: "1"}, {Distro: distro, Release: "2"}}, snap.ID,
		Advisory{ID: p + "1", CVE: p + "1", Severity: "high", Summary: "first", Ranges: []AdvisoryRange{
			rng(distro, "1", "openssl", "1.0-2", FixStateFixed), rng(distro, "2", "openssl", "2.0-1", FixStateFixed)}},
		// same advisory again (another USN naming the same CVE) with an extra range and a duplicate
		Advisory{ID: p + "1", CVE: p + "1", Severity: "low", Summary: "second", Ranges: []AdvisoryRange{
			rng(distro, "1", "openssl", "1.0-2", FixStateFixed), rng(distro, "1", "libssl", "1.0-2", FixStateFixed)}},
		Advisory{ID: p + "2", CVE: p + "2", Severity: "low", Ranges: []AdvisoryRange{rng(distro, "1", "curl", "", FixStateWillNotFix)}},
	)
	if res.Advisories != 2 || res.Ranges != 4 {
		t.Fatalf("result = %+v, want 2 advisories, 4 distinct ranges", res)
	}

	a, err := s.GetAdvisory(ctx, p+"1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Summary != "first" || a.Source != "test-feed" || a.CVE != p+"1" {
		t.Errorf("advisory = %+v (first record's text wins)", a)
	}
	if a.SnapshotID == nil || *a.SnapshotID != snap.ID {
		t.Errorf("advisory snapshot = %v, want %d", a.SnapshotID, snap.ID)
	}
	if len(a.Ranges) != 3 {
		t.Fatalf("ranges = %+v", a.Ranges)
	}
	for _, r := range a.Ranges {
		if r.SnapshotID == nil || *r.SnapshotID != snap.ID || r.Distro != distro {
			t.Errorf("range = %+v", r)
		}
	}
	// A legacy single-floor row must not appear: the new rows have package ''.
	legacy, err := s.ListAdvisories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range legacy {
		if strings.HasPrefix(row["id"], p) {
			t.Errorf("new-shape advisory %s leaked into the legacy matcher list", row["id"])
		}
	}

	// Reload release 1 only (scope narrowed): release 2's range must survive,
	// release 1's old ranges must be replaced.
	mustLoad(t, s, "test-feed", []RangeScope{{Distro: distro, Release: "1"}}, 0,
		Advisory{ID: p + "1", CVE: p + "1", Severity: "high", Ranges: []AdvisoryRange{rng(distro, "1", "openssl", "1.0-9", FixStateFixed)}})
	got, err := s.ListAdvisoryRanges(ctx, RangeQuery{Distro: distro, Release: "1", Package: "openssl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Fixed != "1.0-9" {
		t.Errorf("release 1 openssl = %+v, want only 1.0-9", got)
	}
	if got, _ := s.ListAdvisoryRanges(ctx, RangeQuery{Distro: distro, Release: "1", Package: "libssl"}); len(got) != 0 {
		t.Errorf("stale libssl range survived: %+v", got)
	}
	if got, _ := s.ListAdvisoryRanges(ctx, RangeQuery{Distro: distro, Release: "2", Package: "openssl"}); len(got) != 1 || got[0].Fixed != "2.0-1" {
		t.Errorf("release 2 range disturbed: %+v", got)
	}
}

func TestFeedLoadMergeRules(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro, p := feedFixture(t, s)
	scope := []RangeScope{{Distro: distro, Release: "1"}}

	mustLoad(t, s, "feed-a", scope, 0,
		Advisory{ID: p + "m", CVE: p + "m", Severity: "medium", Summary: "from a", CVSSScore: f64(5.0), CVSSVector: "V-A", CWE: []string{"CWE-1"},
			Ranges: []AdvisoryRange{rng(distro, "1", "pkg", "1", FixStateFixed)}})
	// A second feed with a higher severity and score; same distro scope.
	mustLoad(t, s, "feed-b", scope, 0,
		Advisory{ID: p + "m", CVE: p + "m", Severity: "critical", Summary: "from b", CVSSScore: f64(9.1), CVSSVector: "V-B", CWE: []string{"CWE-2"},
			Ranges: []AdvisoryRange{rng(distro, "1", "pkg", "2", FixStateFixed)}})
	a, err := s.GetAdvisory(ctx, p+"m")
	if err != nil {
		t.Fatal(err)
	}
	if a.Severity != "critical" || a.CVSSScore == nil || *a.CVSSScore != 9.1 || a.CVSSVector != "V-B" {
		t.Errorf("severity/cvss = %q %v %q, want the highest any feed asserts, vector with its score", a.Severity, a.CVSSScore, a.CVSSVector)
	}
	if a.Summary != "from a" || a.Source != "feed-a" || len(a.CWE) != 1 || a.CWE[0] != "CWE-1" {
		t.Errorf("text fields = %q %q %v, want first feed's kept", a.Summary, a.Source, a.CWE)
	}

	// A later, lower assertion must not lower what is stored.
	mustLoad(t, s, "feed-c", scope, 0,
		Advisory{ID: p + "m", CVE: p + "m", Severity: "low", CVSSScore: f64(2.0), CVSSVector: "V-C",
			Ranges: []AdvisoryRange{rng(distro, "1", "pkg", "3", FixStateFixed)}})
	a, _ = s.GetAdvisory(ctx, p+"m")
	if a.Severity != "critical" || *a.CVSSScore != 9.1 || a.CVSSVector != "V-B" {
		t.Errorf("lowered by a later feed: %q %v %q", a.Severity, a.CVSSScore, a.CVSSVector)
	}

	// An existing legacy floor row with the same id is left alone (the matcher
	// still reads it) while ranges are added alongside.
	if err := s.UpsertAdvisory(ctx, p+"legacy", p+"legacy", "oldpkg", "9.9", "high", "legacy row", "osv"); err != nil {
		t.Fatal(err)
	}
	mustLoad(t, s, "feed-a", scope, 0,
		Advisory{ID: p + "legacy", CVE: p + "legacy", Severity: "low", Ranges: []AdvisoryRange{rng(distro, "1", "newpkg", "1", FixStateFixed)}})
	rows, _ := s.ListAdvisories(ctx)
	found := false
	for _, r := range rows {
		if r["id"] == p+"legacy" {
			found = true
			if r["package"] != "oldpkg" || r["below"] != "9.9" || r["severity"] != "high" {
				t.Errorf("legacy row altered: %v", r)
			}
		}
	}
	if !found {
		t.Error("legacy row vanished from ListAdvisories")
	}
}

func TestFeedLoadValidationAndAtomicity(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro, p := feedFixture(t, s)
	scope := []RangeScope{{Distro: distro, Release: "1"}}

	mustLoad(t, s, "feed", scope, 0,
		Advisory{ID: p + "keep", CVE: p + "keep", Severity: "high", Ranges: []AdvisoryRange{rng(distro, "1", "keepme", "1", FixStateFixed)}})

	// Bad scopes.
	for name, sc := range map[string][]RangeScope{
		"none":         nil,
		"empty scope":  {{}},
		"release only": {{Release: "1"}},
		"legacy":       {{Ecosystem: "legacy"}},
	} {
		if _, err := s.BeginFeedLoad(ctx, "x", sc, 0); err == nil {
			t.Errorf("scope %s accepted", name)
		}
	}
	if _, err := s.BeginFeedLoad(ctx, " ", scope, 0); err == nil {
		t.Error("blank source accepted")
	}

	// A range outside the declared scope is rejected at Add, before anything is written.
	l, err := s.BeginFeedLoad(ctx, "feed", scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = l.Add(ctx, Advisory{ID: p + "bad", Severity: "high", Ranges: []AdvisoryRange{rng(distro, "7", "x", "1", FixStateFixed)}})
	if err == nil || !strings.Contains(err.Error(), "outside the declared scopes") {
		t.Errorf("out-of-scope range error = %v", err)
	}
	if err := l.Add(ctx, Advisory{ID: p + "bad", Severity: "high", Ranges: []AdvisoryRange{{Package: "x", FixState: "nonsense"}}}); err == nil {
		t.Error("invalid range accepted")
	}

	// Abandon mid-load after staging good rows: the old scope contents survive.
	if err := l.Add(ctx, Advisory{ID: p + "new", CVE: p + "new", Severity: "high", Ranges: []AdvisoryRange{rng(distro, "1", "newpkg", "1", FixStateFixed)}}); err != nil {
		t.Fatal(err)
	}
	l.Rollback(ctx)
	if _, err := l.Commit(ctx); err == nil {
		t.Error("Commit after Rollback succeeded")
	}
	if got, _ := s.ListAdvisoryRanges(ctx, RangeQuery{Distro: distro, Release: "1", Package: "keepme"}); len(got) != 1 {
		t.Errorf("rollback lost the previous data: %+v", got)
	}
	if _, err := s.GetAdvisory(ctx, p+"new"); err == nil {
		t.Error("rolled-back advisory is visible")
	}
}

func TestFeedLoadFlushesLargeBatches(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro, p := feedFixture(t, s)
	scope := []RangeScope{{Distro: distro, Release: "1"}}
	l, err := s.BeginFeedLoad(ctx, "bulk", scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := feedFlushRows*2 + 17 // crosses two flush boundaries and leaves a partial batch
	for i := 0; i < n; i++ {
		id := p + "b" + itoa(i)
		if err := l.Add(ctx, Advisory{ID: id, CVE: id, Severity: "low", Ranges: []AdvisoryRange{rng(distro, "1", "pkg"+itoa(i%50), itoa(i), FixStateFixed)}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := l.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Advisories != n || res.Ranges != n {
		t.Fatalf("result = %+v, want %d each", res, n)
	}
	var got int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM advisory_ranges WHERE distro = $1`, distro).Scan(&got); err != nil || got != n {
		t.Fatalf("rows in db = %d (%v), want %d", got, err, n)
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}

func TestApplyKEV(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro, p := feedFixture(t, s)
	added := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	// One CVE already described by a feed, one only a legacy id with a cve column.
	mustLoad(t, s, "feed", []RangeScope{{Distro: distro, Release: "1"}}, 0,
		Advisory{ID: p + "have", CVE: p + "have", Severity: "high", Summary: "real text", Ranges: []AdvisoryRange{rng(distro, "1", "x", "1", FixStateFixed)}})
	if err := s.UpsertAdvisory(ctx, "GHSA-"+p+"v", p+"viacve", "pkg", "1", "high", "legacy", "osv"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ApplyKEV(ctx, nil, 0); err == nil {
		t.Fatal("empty KEV catalog accepted")
	}
	res, err := s.ApplyKEV(ctx, []KEVRow{
		{CVE: p + "have", Added: added, Name: "ignored: row already has text"},
		{CVE: p + "viacve", Added: added.AddDate(0, 0, 1), Name: "x"},
		{CVE: p + "stub", Added: added.AddDate(0, 0, 2), Name: "Stub Vuln Name"},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 1 {
		t.Errorf("created = %d, want 1 stub", res.Created)
	}

	have, _ := s.GetAdvisory(ctx, p+"have")
	if !have.KEV || have.KEVAdded == nil || !have.KEVAdded.Equal(added) || have.Summary != "real text" || have.Severity != "high" {
		t.Errorf("have = %+v", have)
	}
	via, _ := s.GetAdvisory(ctx, "GHSA-"+p+"v")
	if !via.KEV || via.KEVAdded == nil || !via.KEVAdded.Equal(added.AddDate(0, 0, 1)) {
		t.Errorf("flag by cve column failed: %+v", via)
	}
	stub, err := s.GetAdvisory(ctx, p+"stub")
	if err != nil {
		t.Fatal(err)
	}
	if !stub.KEV || stub.Severity != "unknown" || stub.Source != "cisa-kev" || stub.Summary != "Stub Vuln Name" || len(stub.Ranges) != 0 {
		t.Errorf("stub = %+v", stub)
	}

	// A real feed record replaces the stub's text and severity; the flag stays.
	mustLoad(t, s, "feed", []RangeScope{{Distro: distro, Release: "1"}}, 0,
		Advisory{ID: p + "stub", CVE: p + "stub", Severity: "critical", Summary: "distro text", Ranges: []AdvisoryRange{rng(distro, "1", "y", "1", FixStateFixed)}})
	stub, _ = s.GetAdvisory(ctx, p+"stub")
	if !stub.KEV || stub.Severity != "critical" || stub.Summary != "distro text" || stub.Source != "feed" {
		t.Errorf("stub after real record = %+v", stub)
	}

	// CISA drops one: its flag clears, the others stay; an unchanged catalog is a no-op.
	res, err = s.ApplyKEV(ctx, []KEVRow{
		{CVE: p + "have", Added: added, Name: "n"},
		{CVE: p + "stub", Added: added.AddDate(0, 0, 2), Name: "n"},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 || res.Cleared < 1 {
		t.Errorf("result = %+v, want 1+ cleared (ours; other tests' rows may add more) and 0 created", res)
	}
	via, _ = s.GetAdvisory(ctx, "GHSA-"+p+"v")
	if via.KEV || via.KEVAdded != nil {
		t.Errorf("dropped CVE still flagged: %+v", via)
	}
	if have, _ = s.GetAdvisory(ctx, p+"have"); !have.KEV {
		t.Error("kept CVE lost its flag")
	}
}

func TestApplyEPSS(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro, p := feedFixture(t, s)
	mustLoad(t, s, "feed", []RangeScope{{Distro: distro, Release: "1"}}, 0,
		Advisory{ID: p + "a", CVE: p + "a", Severity: "high", Ranges: []AdvisoryRange{rng(distro, "1", "x", "1", FixStateFixed)}})
	d1 := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

	if _, err := s.ApplyEPSS(ctx, d1, nil); err == nil {
		t.Error("empty EPSS accepted")
	}
	if _, err := s.ApplyEPSS(ctx, time.Time{}, []EPSSRow{{CVE: p + "a", Score: 0.5}}); err == nil {
		t.Error("zero date accepted")
	}
	n, err := s.ApplyEPSS(ctx, d1, []EPSSRow{{CVE: p + "a", Score: 0.25}, {CVE: p + "nobody", Score: 0.9}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("updated = %d, want 1 (CVE without an advisory is ignored)", n)
	}
	a, _ := s.GetAdvisory(ctx, p+"a")
	if a.EPSS == nil || *a.EPSS != 0.25 || a.EPSSDate == nil || !a.EPSSDate.Equal(d1) {
		t.Errorf("epss = %v %v", a.EPSS, a.EPSSDate)
	}
	// Same data again: nothing to change. New day: updated.
	if n, _ := s.ApplyEPSS(ctx, d1, []EPSSRow{{CVE: p + "a", Score: 0.25}}); n != 0 {
		t.Errorf("re-apply changed %d rows", n)
	}
	d2 := d1.AddDate(0, 0, 1)
	if n, _ := s.ApplyEPSS(ctx, d2, []EPSSRow{{CVE: p + "a", Score: 0.75}}); n != 1 {
		t.Errorf("next day changed %d rows", n)
	}
	a, _ = s.GetAdvisory(ctx, p+"a")
	if *a.EPSS != 0.75 || !a.EPSSDate.Equal(d2) {
		t.Errorf("epss after update = %v %v", *a.EPSS, a.EPSSDate)
	}
	// Score outside 0..1 is rejected by the column CHECK, not stored.
	if _, err := s.ApplyEPSS(ctx, d2, []EPSSRow{{CVE: p + "a", Score: 1.5}}); err == nil {
		t.Error("score 1.5 stored")
	}
}

func TestFeedStatusRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	name := "test-feed-" + randID(t)
	t.Cleanup(func() { s.pool.Exec(ctx, `DELETE FROM feed_status WHERE name = $1`, name) }) //nolint:errcheck

	if _, ok, err := s.GetFeedStatus(ctx, name); err != nil || ok {
		t.Fatalf("unknown feed: ok=%v err=%v", ok, err)
	}
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{{Name: name, URL: "https://example.invalid/f", FetchedAt: t0, SHA256: strings.Repeat("b", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFeedSuccess(ctx, FeedStatus{Name: name, Kind: "kev", URL: "https://example.invalid/f", LastSuccess: &t0,
		RecordCount: 42, SHA256: strings.Repeat("b", 64), ETag: `"abc"`, LastModified: "Tue, 20 Oct 2026 12:00:00 GMT", SnapshotID: &snap.ID}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetFeedStatus(ctx, name)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.RecordCount != 42 || got.ETag != `"abc"` || got.SnapshotID == nil || *got.SnapshotID != snap.ID || got.LastSuccess == nil || !got.LastSuccess.Equal(t0) || got.LastError != "" {
		t.Errorf("status = %+v", got)
	}

	// A failure records the error and attempt time, and leaves success untouched.
	t1 := t0.Add(24 * time.Hour)
	if err := s.RecordFeedFailure(ctx, name, "kev", "https://example.invalid/f", t1, strings.Repeat("x", 800)); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetFeedStatus(ctx, name)
	if got.LastError == "" || len(got.LastError) != 500 || got.LastAttempt == nil || !got.LastAttempt.Equal(t1) {
		t.Errorf("failure not recorded: err len %d attempt %v", len(got.LastError), got.LastAttempt)
	}
	if got.LastSuccess == nil || !got.LastSuccess.Equal(t0) || got.RecordCount != 42 || got.SHA256 == "" {
		t.Errorf("failure disturbed the success fields: %+v", got)
	}
	// A later success clears the error.
	t2 := t0.Add(48 * time.Hour)
	if err := s.RecordFeedSuccess(ctx, FeedStatus{Name: name, Kind: "kev", URL: "https://example.invalid/f", LastSuccess: &t2, RecordCount: 43, SHA256: strings.Repeat("c", 64)}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetFeedStatus(ctx, name)
	if got.LastError != "" || got.RecordCount != 43 || !got.LastSuccess.Equal(t2) {
		t.Errorf("after success: %+v", got)
	}
	// A failure for a feed never seen creates its row with no success time.
	other := name + "-never"
	t.Cleanup(func() { s.pool.Exec(ctx, `DELETE FROM feed_status WHERE name = $1`, other) }) //nolint:errcheck
	if err := s.RecordFeedFailure(ctx, other, "epss", "u", t1, "dns"); err != nil {
		t.Fatal(err)
	}
	if g, ok, _ := s.GetFeedStatus(ctx, other); !ok || g.LastSuccess != nil {
		t.Errorf("never-succeeded feed: %+v", g)
	}
	list, err := s.ListFeedStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, f := range list {
		if f.Name == name || f.Name == other {
			seen++
		}
	}
	if seen != 2 {
		t.Errorf("list contained %d of our 2 feeds", seen)
	}
	if err := s.RecordFeedSuccess(ctx, FeedStatus{Name: name}); err == nil {
		t.Error("success without a time accepted")
	}
}

func TestFinalizeFeedSnapshot(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 23, 1, 2, 3, 0, time.UTC)
	f := FeedRef{Name: "kev", URL: "https://example.invalid/k", FetchedAt: t0, SHA256: strings.Repeat("a", 64)}
	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{f})
	if err != nil {
		t.Fatal(err)
	}
	f.RecordCount = 1756
	g := FeedRef{Name: "epss", URL: "https://example.invalid/e", FetchedAt: t0, SHA256: strings.Repeat("d", 64), RecordCount: 300000}
	if err := s.FinalizeFeedSnapshot(ctx, snap.ID, []FeedRef{f, g}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetFeedSnapshot(ctx, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feeds) != 2 || got.Feeds[0].RecordCount != 1756 || got.Feeds[1].Name != "epss" {
		t.Errorf("finalized = %+v", got.Feeds)
	}
	if err := s.FinalizeFeedSnapshot(ctx, 1<<40, []FeedRef{f}); err == nil {
		t.Error("finalizing a missing snapshot succeeded")
	}
	if err := s.FinalizeFeedSnapshot(ctx, snap.ID, nil); err == nil {
		t.Error("empty feed list accepted")
	}
	if err := s.FinalizeFeedSnapshot(ctx, snap.ID, []FeedRef{{Name: "x"}}); err == nil {
		t.Error("invalid feed ref accepted")
	}
	latest, ok, err := s.LatestFeedSnapshot(ctx)
	if err != nil || !ok || latest.ID < snap.ID {
		t.Errorf("latest = %+v ok=%v err=%v", latest, ok, err)
	}
}
