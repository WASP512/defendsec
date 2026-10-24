package storepg

import (
	"context"
	"errors"
	"testing"
	"time"

	"defendsec/internal/surface"
)

// Surface findings against a real Postgres: assets and their authorisation,
// first-seen / resolved / reopened bookkeeping, the rule that a check which
// could not run resolves nothing, and the raw observations kept per scan.

func surfaceAsset(t *testing.T, s *Store, kind, value string, authorised bool) SurfaceAsset {
	t.Helper()
	a, err := s.CreateSurfaceAsset(context.Background(), SurfaceAssetInput{
		Kind: kind, Value: value, Authorised: authorised, AuthorisedBy: "tester", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func finding(check, id, subject string, sev surface.Severity) surface.Finding {
	return surface.Finding{
		Check: check, ID: id, Subject: subject, Severity: sev, Title: id, Detail: "detail of " + id, Fix: "fix " + id,
		Evidence: map[string]any{"record": "v=DMARC1; p=none", "n": 1}, Controls: []string{"cis-v8:9.5", "nist-800-53:SI-8"},
	}
}

func report(a SurfaceAsset, at time.Time, results ...surface.CheckResult) *surface.Report {
	return &surface.Report{Asset: a.ScanAsset(), StartedAt: at.Add(-5 * time.Second), FinishedAt: at, Results: results}
}

func result(check string, assessed bool, reason string, fs ...surface.Finding) surface.CheckResult {
	return surface.CheckResult{Check: check, Assessed: assessed, Reason: reason, Observed: map[string]any{"check": check, "raw": "text of " + check}, Findings: fs}
}

func TestSurfaceAssetLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	val := "a" + randID(t)[:10] + ".example.com"

	a, err := s.CreateSurfaceAsset(ctx, SurfaceAssetInput{Kind: "domain", Value: val, DKIMSelectors: []string{"s1"}, MailHost: true, CreatedBy: "mason"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Authorised || a.AuthorisedAt != nil || len(a.DKIMSelectors) != 1 || !a.MailHost {
		t.Fatalf("a new asset is not authorised until somebody says so: %+v", a)
	}
	if _, err := s.CreateSurfaceAsset(ctx, SurfaceAssetInput{Kind: "domain", Value: val}); !errors.Is(err, ErrSurfaceAssetExists) {
		t.Fatalf("declaring twice: %v", err)
	}

	due, err := s.SurfaceAssetsDue(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range due {
		if d.ID == a.ID {
			t.Fatal("an unauthorised asset is never due for a scan")
		}
	}

	if err := s.SetSurfaceAssetAuthorised(ctx, a.ID, true, "mason"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSurfaceAsset(ctx, a.ID)
	if !got.Authorised || got.AuthorisedBy != "mason" || got.AuthorisedAt == nil {
		t.Fatalf("%+v", got)
	}
	due, _ = s.SurfaceAssetsDue(ctx, 24*time.Hour)
	isDue := false
	for _, d := range due {
		isDue = isDue || d.ID == a.ID
	}
	if !isDue {
		t.Fatal("an authorised asset never scanned is due")
	}

	// Scanned just now: not due within a day, due within a second of a later time.
	at := time.Now().UTC()
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "manual", report(got, at, result("spf", true, ""))); err != nil {
		t.Fatal(err)
	}
	due, _ = s.SurfaceAssetsDue(ctx, 24*time.Hour)
	for _, d := range due {
		if d.ID == a.ID {
			t.Fatal("asset scanned a moment ago is not due")
		}
	}

	// Withdrawing authorisation stops scans being recorded.
	if err := s.SetSurfaceAssetAuthorised(ctx, a.ID, false, "mason"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "manual", report(got, at, result("spf", true, ""))); !errors.Is(err, ErrSurfaceAssetNotAuthorised) {
		t.Fatalf("recording a scan of an unauthorised asset: %v", err)
	}

	// Removing hides it; declaring it again reactivates and does not inherit authorisation.
	if err := s.SetSurfaceAssetAuthorised(ctx, a.ID, true, "mason"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveSurfaceAsset(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSurfaceAsset(ctx, a.ID); !errors.Is(err, ErrNoSurfaceAsset) {
		t.Fatalf("removed asset still readable: %v", err)
	}
	if err := s.SetSurfaceAssetAuthorised(ctx, a.ID, true, "x"); !errors.Is(err, ErrNoSurfaceAsset) {
		t.Fatalf("authorising a removed asset: %v", err)
	}
	again, err := s.CreateSurfaceAsset(ctx, SurfaceAssetInput{Kind: "domain", Value: val, CreatedBy: "mason"})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != a.ID || again.Authorised {
		t.Fatalf("redeclared asset: %+v", again)
	}
}

func TestSurfaceFindingBookkeeping(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := surfaceAsset(t, s, "domain", "b"+randID(t)[:10]+".example.com", true)
	t0 := time.Date(2026, 10, 24, 6, 0, 0, 0, time.UTC)

	// Scan 1: a DMARC finding and an SPF finding, plus a DKIM check that could not run.
	sum, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, t0,
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "d", surface.SevMedium)),
		result("spf", true, "", finding("spf", "spf.softfail", "d", surface.SevLow)),
		result("dkim", false, "no selector found"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if sum.New != 2 || sum.Open != 2 || sum.ChecksAssessed != 2 || sum.ChecksNotAssessed != 1 {
		t.Fatalf("%+v", sum)
	}
	list, err := s.ListSurfaceFindings(ctx, SurfaceFindingFilter{AssetID: a.ID})
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %+v", err, list)
	}
	if list[0].FindingID != "dmarc.p_none" || list[0].Severity != "medium" {
		t.Fatalf("most severe first: %+v", list)
	}
	f := list[0]
	if !f.FirstSeen.Equal(t0) || !f.LastSeen.Equal(t0) || f.ResolvedAt != nil {
		t.Fatalf("%+v", f)
	}
	if f.Evidence["record"] != "v=DMARC1; p=none" || len(f.Controls) != 2 || f.Fix == "" || f.Detail == "" {
		t.Fatalf("evidence, controls, fix and detail must round-trip: %+v", f)
	}

	// Scan 2 a day later: DMARC still there, SPF fixed, and the DKIM check fails again.
	t1 := t0.Add(24 * time.Hour)
	sum, err = s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, t1,
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "d", surface.SevMedium)),
		result("spf", true, ""),
		result("dkim", false, "lookup failed"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if sum.StillOpen != 1 || sum.Resolved != 1 || sum.Open != 1 || sum.New != 0 {
		t.Fatalf("%+v", sum)
	}
	all, _ := s.ListSurfaceFindings(ctx, SurfaceFindingFilter{AssetID: a.ID, IncludeResolved: true})
	byID := map[string]SurfaceFinding{}
	for _, f := range all {
		byID[f.FindingID] = f
	}
	if d := byID["dmarc.p_none"]; !d.FirstSeen.Equal(t0) || !d.LastSeen.Equal(t1) || d.ResolvedAt != nil {
		t.Fatalf("a still-open finding keeps first_seen and moves last_seen: %+v", d)
	}
	if sp := byID["spf.softfail"]; sp.ResolvedAt == nil || !sp.ResolvedAt.Equal(t1) || !sp.FirstSeen.Equal(t0) {
		t.Fatalf("open on date A, closed on date B: %+v", sp)
	}
	open, _ := s.ListSurfaceFindings(ctx, SurfaceFindingFilter{AssetID: a.ID})
	if len(open) != 1 {
		t.Fatalf("resolved findings are not listed by default: %+v", open)
	}

	// Scan 3: the DMARC check could not run. Nothing may be resolved on that.
	t2 := t1.Add(24 * time.Hour)
	sum, err = s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, t2, result("dmarc", false, "SERVFAIL")))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Resolved != 0 || sum.Open != 1 {
		t.Fatalf("a check that could not run resolved something: %+v", sum)
	}
	open, _ = s.ListSurfaceFindings(ctx, SurfaceFindingFilter{AssetID: a.ID})
	if len(open) != 1 || !open[0].LastSeen.Equal(t1) {
		t.Fatalf("last_seen must stay at the last real confirmation: %+v", open)
	}

	// Scan 4: SPF comes back. The row is reopened, first_seen is kept.
	t3 := t2.Add(24 * time.Hour)
	sum, err = s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, t3,
		result("spf", true, "", finding("spf", "spf.softfail", "d", surface.SevLow))))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Reopened != 1 || sum.Open != 2 {
		t.Fatalf("%+v", sum)
	}
	all, _ = s.ListSurfaceFindings(ctx, SurfaceFindingFilter{AssetID: a.ID, IncludeResolved: true})
	for _, f := range all {
		if f.FindingID == "spf.softfail" && (f.ResolvedAt != nil || !f.FirstSeen.Equal(t0) || !f.LastSeen.Equal(t3)) {
			t.Fatalf("reopened finding: %+v", f)
		}
	}
	if len(all) != 2 {
		t.Fatalf("no duplicate rows: %d", len(all))
	}

	// The same condition on two subjects are two findings; resolving one leaves the other.
	t4 := t3.Add(time.Hour)
	_, err = s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, t4, result("ports", true, "",
		finding("ports", "ports.open", "445/tcp", surface.SevCritical), finding("ports", "ports.open", "22/tcp", surface.SevInfo))))
	if err != nil {
		t.Fatal(err)
	}
	t5 := t4.Add(time.Hour)
	sum, err = s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, t5, result("ports", true, "",
		finding("ports", "ports.open", "22/tcp", surface.SevInfo))))
	if err != nil || sum.Resolved != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	open, _ = s.ListSurfaceFindings(ctx, SurfaceFindingFilter{AssetID: a.ID})
	for _, f := range open {
		if f.FindingID == "ports.open" && f.Subject == "445/tcp" {
			t.Fatalf("445 was resolved but is listed open: %+v", f)
		}
	}
}

func TestSurfaceObservationsAreKeptPerScan(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a := surfaceAsset(t, s, "hostname", "c"+randID(t)[:10]+".example.com", true)
	t0 := time.Date(2026, 10, 24, 6, 0, 0, 0, time.UTC)
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, t0, result("tls-cert", true, ""), result("tls-legacy", false, "FIPS"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, t0.Add(time.Hour), result("tls-cert", false, "timed out"))); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM surface_observations WHERE asset_id = $1`, a.ID).Scan(&n); err != nil || n != 3 {
		t.Fatalf("every check of every scan is stored: %d %v", n, err)
	}
	states, err := s.SurfaceChecks(ctx, a.ID)
	if err != nil || len(states) != 2 {
		t.Fatalf("%v %+v", err, states)
	}
	by := map[string]SurfaceCheckState{}
	for _, st := range states {
		by[st.Check] = st
	}
	if c := by["tls-cert"]; c.Assessed || c.Reason != "timed out" || !c.ObservedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("latest observation wins: %+v", c)
	}
	if c := by["tls-legacy"]; c.Assessed || c.Observed["raw"] != "text of tls-legacy" {
		t.Fatalf("%+v", c)
	}
}

func TestSurfaceRecordRefusesUnknownAsset(t *testing.T) {
	s := testStore(t)
	a := SurfaceAsset{ID: 999999999, Kind: "domain", Value: "nope.example.com", Authorised: true}
	if _, err := s.RecordSurfaceScan(context.Background(), a.ID, "manual", report(a, time.Now())); !errors.Is(err, ErrNoSurfaceAsset) {
		t.Fatalf("%v", err)
	}
}
