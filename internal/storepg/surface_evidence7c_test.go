package storepg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/evidence"
	"defendsec/internal/surface"
)

// Slice 7c, against a real database: the findings list of an exported bundle is
// checked against what the chain attests, in both directions.

func surfaceChecksOK(t *testing.T, rep evidence.Report) {
	t.Helper()
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.Name, "surface") && !c.OK {
			t.Fatalf("%s: %s", c.Name, c.Detail)
		}
	}
}

// A certificate finding's title and severity change from scan to scan (days
// left), so the bundle's finding must be compared with the scan that saw it
// last, not with the scan that opened it. Every column of a finding that the
// bundle shows is then edited in the database, one at a time: each must fail.
func TestSurfaceEvidenceFindingsAreCheckedAgainstTheLatestSightingAndEditsFail(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	a := surfaceAsset(t, s, "domain", "tamper.example.com", true)
	cert := func(days int, sev surface.Severity) surface.Finding {
		f := finding("tls", "tls.expiring", "tamper.example.com:443", sev)
		f.Title = fmt.Sprintf("Certificate expires in %d days", days)
		f.Evidence = map[string]any{"days": days}
		return f
	}
	dmarc := func() surface.Finding { return finding("dmarc", "dmarc.p_none", "tamper.example.com", surface.SevLow) }
	rec := func(when time.Time, rs ...surface.CheckResult) {
		t.Helper()
		if _, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, when, rs...)); err != nil {
			t.Fatal(err)
		}
	}
	rec(now.AddDate(0, 0, -3), result("tls", true, "", cert(20, surface.SevMedium)), result("dmarc", true, "", dmarc()))
	rec(now.AddDate(0, 0, -2), result("tls", true, "", cert(19, surface.SevMedium)), result("dmarc", true, ""))
	rec(now.AddDate(0, 0, -1), result("tls", true, "", cert(5, surface.SevHigh)), result("dmarc", true, "", dmarc()))
	rec(now, result("tls", true, "", cert(4, surface.SevHigh)), result("dmarc", true, "", dmarc()))

	pemKey := testPubPEM(t)
	export := func() *evidence.Bundle {
		t.Helper()
		b, err := s.ExportEvidence(ctx, pemKey, "test", "surface", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := export()
	rep := evidence.Verify(b)
	surfaceChecksOK(t, rep)
	if rep.Surface.FindingsVerified != 2 || rep.Surface.FindingsDatesOnly != 0 || rep.Surface.ScansAttested != 4 {
		t.Fatalf("a fresh export verifies, findings and all: %+v", rep.Surface)
	}
	for _, sn := range b.Surface.Scans {
		if sn.Seen == nil {
			t.Fatalf("scan %d carries no seen list", sn.ScanID)
		}
	}
	if len(b.Surface.Scans[1].Seen) != 1 || len(b.Surface.Scans[3].Seen) != 2 {
		t.Fatalf("a scan lists the findings it saw, opened or not: scan 2 saw %d, scan 4 saw %d", len(b.Surface.Scans[1].Seen), len(b.Surface.Scans[3].Seen))
	}

	if _, err := pool.Exec(ctx, `CREATE TABLE sf_backup AS SELECT * FROM surface_findings`); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM surface_findings`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO surface_findings OVERRIDING SYSTEM VALUE SELECT * FROM sf_backup`); err != nil {
			t.Fatal(err)
		}
	}
	edits := map[string]string{
		"severity":    `UPDATE surface_findings SET severity = 'low' WHERE finding_id = 'tls.expiring'`,
		"title":       `UPDATE surface_findings SET title = 'Certificate expires in 400 days' WHERE finding_id = 'tls.expiring'`,
		"detail":      `UPDATE surface_findings SET detail = 'all good' WHERE finding_id = 'tls.expiring'`,
		"fix":         `UPDATE surface_findings SET fix = '' WHERE finding_id = 'dmarc.p_none'`,
		"evidence":    `UPDATE surface_findings SET evidence = '{"days": 400}'::jsonb WHERE finding_id = 'tls.expiring'`,
		"controls":    `UPDATE surface_findings SET controls = ARRAY[]::text[] WHERE finding_id = 'dmarc.p_none'`,
		"check group": `UPDATE surface_findings SET check_group = 'spf' WHERE finding_id = 'dmarc.p_none'`,
		"last scan":   `UPDATE surface_findings SET last_scan_id = first_scan_id WHERE finding_id = 'tls.expiring'`,
		"first scan":  `UPDATE surface_findings SET first_scan_id = last_scan_id WHERE finding_id = 'tls.expiring'`,
		"one hidden":  `DELETE FROM surface_findings WHERE finding_id = 'tls.expiring'`,
		"all hidden":  `DELETE FROM surface_findings`,
		"one invented": `INSERT INTO surface_findings (asset_id, check_group, finding_id, subject, severity, title, first_seen, last_seen)
			SELECT asset_id, 'spf', 'spf.plus_all', 'tamper.example.com', 'critical', 'SPF allows everyone', first_seen, last_seen
			FROM surface_findings LIMIT 1`,
	}
	for name, stmt := range edits {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rep := evidence.Verify(export())
		if rep.OK() || rep.Surface.FindingsFailed == 0 {
			t.Errorf("a database edit of the finding's %s verified: %+v", name, rep.Surface)
		}
		restore()
		if rep := evidence.Verify(export()); !rep.OK() || rep.Surface.FindingsVerified != 2 {
			t.Fatalf("restored after %s, the bundle must verify again: %+v", name, rep.Surface)
		}
	}
}

// A database upgraded in place: a scan chained under the v1 digest (no seen
// list) verifies for its dates and names its findings as dates-only; the first
// scan after the upgrade that sees a finding makes its title and severity
// attested.
func TestSurfaceEvidenceUpgradesInPlaceFromV1Scans(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	a := surfaceAsset(t, s, "domain", "legacy.example.com", true)
	t0 := time.Now().UTC().Add(-72 * time.Hour).Round(time.Microsecond)

	// A scan as slice 7b stored it: no seen column, v1 digest, no version in the entry.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var scanID int64
	if err := tx.QueryRow(ctx, `INSERT INTO surface_scans (asset_id, triggered_by, started_at, finished_at) VALUES ($1,'schedule',$2,$3) RETURNING id`,
		a.ID, t0.Add(-4*time.Second), t0).Scan(&scanID); err != nil {
		t.Fatal(err)
	}
	obs := json.RawMessage(`{"record":"v=DMARC1; p=none"}`)
	if _, err := tx.Exec(ctx, `INSERT INTO surface_observations (scan_id, asset_id, check_group, assessed, reason, observed, observed_at) VALUES ($1,$2,'dmarc',true,'',$3::jsonb,$4)`,
		scanID, a.ID, string(obs), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO surface_findings (asset_id, check_group, finding_id, subject, severity, title, first_seen, last_seen, first_scan_id, last_scan_id)
		VALUES ($1,'dmarc','dmarc.p_none','legacy.example.com','medium','DMARC is p=none',$2,$2,$3,$3)`, a.ID, t0, scanID); err != nil {
		t.Fatal(err)
	}
	legacy := evidence.SurfaceScan{
		ScanID: scanID, AssetID: a.ID, AssetKind: "domain", AssetValue: "legacy.example.com", TriggeredBy: "schedule",
		StartedAt: t0.Add(-4 * time.Second), FinishedAt: t0,
		Observations: []evidence.SurfaceObservation{{Check: "dmarc", Assessed: true, Observed: obs, ObservedAt: t0}},
		Changes:      []evidence.SurfaceChange{{FindingID: "dmarc.p_none", Subject: "legacy.example.com", Severity: "medium", Change: evidence.SurfaceOpened}},
	}
	ch, _ := json.Marshal(legacy.Changes)
	if _, err := tx.Exec(ctx, `UPDATE surface_scans SET changes = $2::jsonb WHERE id = $1`, scanID, string(ch)); err != nil {
		t.Fatal(err)
	}
	if err := auditInTx(ctx, tx, "system:surface-scanner", evidence.SurfaceScanAction, "", evidence.SurfaceScanEntry{
		ScanID: scanID, AssetID: a.ID, Digest: evidence.ScanDigestVersion(evidence.DigestV1, legacy), FinishedAt: t0.Format(time.RFC3339Nano), Opened: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	pemKey := testPubPEM(t)
	export := func() evidence.Report {
		t.Helper()
		b, err := s.ExportEvidence(ctx, pemKey, "test", "surface", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		return evidence.Verify(b)
	}
	rep := export()
	surfaceChecksOK(t, rep)
	if rep.Surface.ScansAttested != 1 || rep.Surface.FindingsDatesOnly != 1 || rep.Surface.FindingsVerified != 0 {
		t.Fatalf("a v1 scan: dates proven, title not: %+v", rep.Surface)
	}

	// The next scan, recorded by this version, sees the finding again.
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, time.Now().UTC(),
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "legacy.example.com", surface.SevMedium)))); err != nil {
		t.Fatal(err)
	}
	rep = export()
	surfaceChecksOK(t, rep)
	if rep.Surface.ScansAttested != 2 || rep.Surface.FindingsVerified != 1 || rep.Surface.FindingsDatesOnly != 0 {
		t.Fatalf("after one v2 scan that saw it: %+v", rep.Surface)
	}
	if _, err := pool.Exec(ctx, `UPDATE surface_findings SET title = 'edited' WHERE finding_id = 'dmarc.p_none'`); err != nil {
		t.Fatal(err)
	}
	if rep = export(); rep.OK() || rep.Surface.FindingsFailed != 1 {
		t.Fatalf("the title is attested now, so an edit fails: %+v", rep.Surface)
	}
}

// Recording scans while exports run: each export reads one snapshot, so it is
// whole. Without one (several reads on separate connections) a scan landing
// between the reads leaves a finding that is ahead of the scans beside it, and
// the bundle fails its own verification.
func TestSurfaceEvidenceExportReadsOneSnapshot(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	a := surfaceAsset(t, s, "domain", "snapshot.example.com", true)
	base := time.Now().UTC().Add(-48 * time.Hour)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f := finding("dmarc", "dmarc.p_none", "snapshot.example.com", surface.SevMedium)
			f.Title = fmt.Sprintf("title %d", i)
			rs := []surface.CheckResult{result("dmarc", true, "", f)}
			if i%3 == 2 {
				rs = []surface.CheckResult{result("dmarc", true, "")} // resolved, then reopened
			}
			if _, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, base.Add(time.Duration(i)*time.Second), rs...)); err != nil {
				t.Errorf("record: %v", err)
				return
			}
		}
	}()
	pemKey := testPubPEM(t)
	for i := 0; i < 40; i++ {
		b, err := s.ExportEvidence(ctx, pemKey, "test", "surface", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		rep := evidence.Verify(b)
		if rep.Surface.ScansFailed != 0 || rep.Surface.FindingsFailed != 0 {
			close(stop)
			wg.Wait()
			t.Fatalf("export %d is not a snapshot: %+v\n%+v", i, rep.Surface, rep.Checks)
		}
	}
	close(stop)
	wg.Wait()
}

// assetsAffected counts assets with a ranked finding. An asset whose only open
// findings are info (an observation, not work) is not affected.
func TestSurfaceAssetsAffectedIgnoresInfoOnlyAssets(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedMixed(t, s, now) // two assets with ranked findings (and some info), one unconfirmed

	info := surfaceAsset(t, s, "domain", "info-only.example.org", true)
	if _, err := s.RecordSurfaceScan(ctx, info.ID, "manual", report(info, now.Add(-time.Hour),
		result("dnssec", true, "", finding("dnssec", "dnssec.unsigned", "info-only.example.org", surface.SevInfo)),
		result("caa", true, "", finding("caa", "caa.absent", "info-only.example.org", surface.SevInfo)))); err != nil {
		t.Fatal(err)
	}
	sum, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	sf := sum.Surface
	if sf.AssetsAffected != 2 {
		t.Fatalf("an asset with only info findings is not affected: assetsAffected = %d, want 2 (%+v)", sf.AssetsAffected, sf)
	}
	if sf.Assets != 3 || sf.Info != 4 || sf.Findings != 5 {
		t.Fatalf("the info-only asset is scanned and its observations counted as info, not as findings: %+v", sf)
	}

	// Give it a low finding: now it is affected.
	if _, err := s.RecordSurfaceScan(ctx, info.ID, "manual", report(info, now,
		result("caa", true, "", finding("caa", "caa.missing", "info-only.example.org", surface.SevLow)))); err != nil {
		t.Fatal(err)
	}
	sum, _ = s.ExposureSummary(ctx, now)
	if sum.Surface.AssetsAffected != 3 {
		t.Fatalf("a ranked finding makes the asset affected: %+v", sum.Surface)
	}
}
