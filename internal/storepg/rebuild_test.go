package storepg

import (
	"context"
	"strings"
	"testing"
	"time"

	"defendsec/db/migrations"
	"defendsec/internal/vuln"
)

// The rebuild flow against real tables: Red Hat's range and Rocky's range
// written the way the feed loader writes them, a Rocky host matched through the
// Store, awaiting_vendor persisted, listed after the fixable ones, counted in
// the summary, and flipped to fixable when Rocky's erratum arrives.
//
// Distro names "rhel" and "rocky" are fixed (the matcher maps one onto the
// other), so the rows are keyed on random advisory and package names and are
// removed afterwards.
func TestRebuildHostAwaitingVendorEndToEnd(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	pkg := "kernel-" + randID(t)[:6]
	other := "tool-" + randID(t)[:6]
	awaitingAdv, kevAdv, fixableAdv := "TEST-"+randID(t), "TEST-"+randID(t), "TEST-"+randID(t)
	t.Cleanup(func() {
		for _, id := range []string{awaitingAdv, kevAdv, fixableAdv} {
			s.pool.Exec(context.Background(), `DELETE FROM advisories WHERE id = $1`, id) //nolint:errcheck
		}
	})

	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{
		{Name: "rhel-9", URL: "https://example.invalid/rhel", FetchedAt: time.Now(), SHA256: strings.Repeat("ab", 32), RecordCount: 3},
		{Name: "rocky-9", URL: "https://example.invalid/rocky", FetchedAt: time.Now(), SHA256: strings.Repeat("cd", 32), RecordCount: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	rhel := func(adv, p, fixed string) AdvisoryRange {
		return AdvisoryRange{Ecosystem: "Red Hat", Distro: "rhel", Release: "9", Package: p, Fixed: fixed,
			FixState: FixStateFixed, Issued: "2026-10-20"}
	}
	for _, a := range []Advisory{
		{ID: awaitingAdv, CVE: "CVE-2026-90001", Severity: "high", SnapshotID: &snap.ID,
			Ranges: []AdvisoryRange{rhel(awaitingAdv, pkg, "0:5.14.0-687.60.1.el9_8")}},
		{ID: kevAdv, CVE: "CVE-2026-90002", Severity: "medium", KEV: true, SnapshotID: &snap.ID,
			Ranges: []AdvisoryRange{rhel(kevAdv, pkg, "0:5.14.0-687.60.1.el9_8")}},
		{ID: fixableAdv, CVE: "CVE-2026-90003", Severity: "critical", SnapshotID: &snap.ID,
			Ranges: []AdvisoryRange{
				rhel(fixableAdv, other, "0:2.0-1.el9"),
				{Ecosystem: "Rocky Linux", Distro: "rocky", Release: "9", Package: other, Fixed: "0:2.0-1.el9",
					FixState: FixStateFixed, Issued: "2026-10-22"}}},
	} {
		if err := s.UpsertAdvisoryWithRanges(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	// The issue date survives the round trip.
	adv, err := s.GetAdvisory(ctx, awaitingAdv)
	if err != nil || len(adv.Ranges) != 1 || adv.Ranges[0].Issued != "2026-10-20" {
		t.Fatalf("range issued = %+v, %v", adv.Ranges, err)
	}

	dev := "dev-" + randID(t)
	seedDevice(t, s, dev)
	host := vuln.Host{Distro: "rocky", Release: "9.8", PackageManager: "rpm", Packages: []vuln.Package{
		{Name: pkg, Version: "0:5.14.0-687.59.1.el9_8"},
		{Name: other, Version: "0:1.0-1.el9"},
	}}
	run := func() vuln.Result {
		t.Helper()
		res, err := vuln.Match(ctx, s, host)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RecordFindings(ctx, dev, res, &snap.ID); err != nil {
			t.Fatalf("recording an awaiting_vendor finding: %v", err)
		}
		return res
	}
	res := run()
	if res.Coverage != vuln.CoverageFull || res.Stats.AwaitingVendor != 2 || len(res.Open()) != 1 {
		t.Fatalf("coverage %s, stats %+v, findings %+v", res.Coverage, res.Stats, res.Findings)
	}

	list, err := s.ListFindings(ctx, FindingFilter{DeviceID: dev})
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	// Fixable first, then awaiting_vendor with the KEV one ahead of the other:
	// the database must not sort kinds alphabetically ("awaiting_vendor" < "finding").
	order := []string{list[0].Kind, list[1].Kind, list[2].Kind}
	if order[0] != "finding" || order[1] != "awaiting_vendor" || order[2] != "awaiting_vendor" || !list[1].KEV || list[2].KEV {
		t.Errorf("order = %v kev %v %v", order, list[1].KEV, list[2].KEV)
	}
	aw := list[2]
	if aw.Fixed != "0:5.14.0-687.60.1.el9_8" || aw.Installed != "0:5.14.0-687.59.1.el9_8" ||
		!strings.Contains(aw.Reason, "fixed upstream by Red Hat") || !strings.Contains(aw.Reason, "2026-10-20") ||
		!strings.Contains(aw.Reason, "not yet released by Rocky Linux") {
		t.Errorf("awaiting finding = %+v", aw)
	}
	if only, _ := s.ListFindings(ctx, FindingFilter{DeviceID: dev, Kind: "awaiting_vendor"}); len(only) != 2 {
		t.Errorf("kind filter returned %d, want 2", len(only))
	}
	if fix, _ := s.ListFindings(ctx, FindingFilter{DeviceID: dev, Kind: "finding"}); len(fix) != 1 || fix[0].AdvisoryID != fixableAdv {
		t.Errorf("fixable list = %+v", fix)
	}

	sum, err := s.FindingsSummary(ctx, dev)
	if err != nil || len(sum) != 1 {
		t.Fatalf("summary = %+v, %v", sum, err)
	}
	if got := sum[0]; got.Open != 1 || got.AwaitingVendor != 2 || got.KEVAwaitingVendor != 1 || got.KEV != 0 {
		t.Errorf("summary = %+v", got)
	}
	var kevKey bool
	for _, k := range sum[0].SeriousKeys {
		if strings.Contains(k, kevAdv) {
			kevKey = true
		}
		if strings.Contains(k, awaitingAdv) {
			t.Errorf("a non-KEV awaiting_vendor finding is in the serious keys: %v", sum[0].SeriousKeys)
		}
	}
	if !kevKey {
		t.Errorf("the KEV awaiting_vendor finding must be a serious key: %v", sum[0].SeriousKeys)
	}

	// Rocky ships the kernel: the awaiting finding becomes fixable, in place.
	err = s.UpsertAdvisoryWithRanges(ctx, Advisory{ID: awaitingAdv, CVE: "CVE-2026-90001", Severity: "high", SnapshotID: &snap.ID,
		Ranges: []AdvisoryRange{
			rhel(awaitingAdv, pkg, "0:5.14.0-687.60.1.el9_8"),
			{Ecosystem: "Rocky Linux", Distro: "rocky", Release: "9", Package: pkg, Fixed: "0:5.14.0-687.60.1.el9_8",
				FixState: FixStateFixed, Issued: "2026-10-24"}}})
	if err != nil {
		t.Fatal(err)
	}
	res = run()
	if len(res.Open()) != 2 || res.Stats.AwaitingVendor != 1 {
		t.Fatalf("after Rocky shipped: %+v", res.Findings)
	}
	if again, _ := s.ListFindings(ctx, FindingFilter{DeviceID: dev, Kind: "finding"}); len(again) != 2 {
		t.Errorf("fixable after Rocky shipped = %+v", again)
	}
}

// Migration 022 is re-applied on every start; the constraint swap must allow
// the new kind and survive being run again.
func TestMigrationAllowsAwaitingVendorKind(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var def string
	if err := s.pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'vuln_findings'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%kind%'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"finding", "unfixed", "informational", "awaiting_vendor"} {
		if !strings.Contains(def, k) {
			t.Errorf("kind constraint %q does not allow %s", def, k)
		}
	}
	dev := "dev-" + randID(t)
	seedDevice(t, s, dev)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vuln_findings (device_id, advisory_id, family, kind, basis, package, installed, fix_state)
		VALUES ($1, 'TEST-x', 'f', 'nonsense', 'distro', 'p', '1', 'fixed')`, dev)
	if err == nil {
		t.Error("an unknown kind was accepted")
	}
}

// Red Hat ranges loaded before migration 022 have no issue date, and an
// unchanged upstream file is not re-read. The migration therefore forgets the
// RHEL feeds' loaded digest, once, so the next sync fills the dates in. It runs
// on every start, so a second run must leave the digest alone.
func TestMigrationForcesOneReloadOfRHELFeeds(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	name := "zz-rhel-" + randID(t)[:6]
	t.Cleanup(func() {
		s.pool.Exec(context.Background(), `DELETE FROM feed_status WHERE name = $1`, name) //nolint:errcheck
	})
	// Put the database in its pre-022 state, as an upgraded install would be.
	if _, err := s.pool.Exec(ctx, `DELETE FROM meta WHERE key = 'rhel_issued_reload'`); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO feed_status (name, kind, sha256) VALUES ($1, $2, 'abc123')
	           ON CONFLICT (name) DO UPDATE SET sha256 = 'abc123'`
	if _, err := s.pool.Exec(ctx, insert, name, "rhel"); err != nil {
		t.Fatal(err)
	}
	digest := func() string {
		var d string
		if err := s.pool.QueryRow(ctx, `SELECT sha256 FROM feed_status WHERE name = $1`, name).Scan(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if err := migrations.Apply(ctx, s.pool); err != nil {
		t.Fatal(err)
	}
	if d := digest(); d != "" {
		t.Errorf("digest after the migration = %q, want it forgotten so the feed is re-read", d)
	}
	// Second start: nothing more is forgotten.
	if _, err := s.pool.Exec(ctx, `UPDATE feed_status SET sha256 = 'def456' WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, s.pool); err != nil {
		t.Fatal(err)
	}
	if d := digest(); d != "def456" {
		t.Errorf("digest after a second migration run = %q, want it left alone", d)
	}
	// Other feeds are never touched.
	other := "zz-other-" + randID(t)[:6]
	t.Cleanup(func() { s.pool.Exec(context.Background(), `DELETE FROM feed_status WHERE name = $1`, other) }) //nolint:errcheck
	s.pool.Exec(ctx, `DELETE FROM meta WHERE key = 'rhel_issued_reload'`)                                     //nolint:errcheck
	s.pool.Exec(ctx, insert, other, "ubuntu")                                                                 //nolint:errcheck
	if err := migrations.Apply(ctx, s.pool); err != nil {
		t.Fatal(err)
	}
	var d string
	s.pool.QueryRow(ctx, `SELECT sha256 FROM feed_status WHERE name = $1`, other).Scan(&d) //nolint:errcheck
	if d != "abc123" {
		t.Errorf("a non-RHEL feed's digest became %q", d)
	}
}
