package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"defendsec/internal/presence"
	"defendsec/internal/storepg"
	"defendsec/internal/vuln"
)

func getJSON(t *testing.T, s *Server, path string, out any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer viewer-token")
	rec := httptest.NewRecorder()
	s.HandleFindings(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v\n%s", path, err, rec.Body.String())
		}
	}
	return rec
}

func TestHandleFindingsAuthAndMethod(t *testing.T) {
	s := testServer()
	for _, tc := range []struct {
		method, token string
		want          int
	}{
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodGet, "nope", http.StatusUnauthorized},
		{http.MethodPost, "admin-token", http.StatusMethodNotAllowed},
		{http.MethodGet, "admin-token", http.StatusServiceUnavailable}, // no Postgres
	} {
		req := httptest.NewRequest(tc.method, "/v1/findings", strings.NewReader(""))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		s.HandleFindings(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s token=%q: %d, want %d", tc.method, tc.token, rec.Code, tc.want)
		}
	}
}

// The slice's pipeline through apid: a host reports packages, the matcher runs
// against advisory ranges, and the findings API returns each finding with its
// advisory, range, snapshot and feed. A KEV finding raises an alert; patching
// the host closes the finding and the alert.
func TestVulnPipelineThroughApid(t *testing.T) {
	s, pg := pgServer(t)
	s.store = presence.New(filepath.Join(t.TempDir(), "state.json"))
	ctx := context.Background()
	distro := "zz" + strings.ToLower(time.Now().Format("150405.000000"))[7:]
	distro = strings.ReplaceAll(distro, ".", "")

	fetched := time.Date(2026, 10, 21, 4, 0, 0, 0, time.UTC)
	snap, err := pg.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "feed-" + distro, URL: "https://example.invalid/oval",
		FetchedAt: fetched, SHA256: strings.Repeat("cd", 32), RecordCount: 2}})
	if err != nil {
		t.Fatal(err)
	}
	kev, plain := "TEST-KEV-"+distro, "TEST-PLAIN-"+distro
	for _, a := range []storepg.Advisory{
		{ID: kev, CVE: "CVE-2024-6387", Severity: "high", Summary: "regreSSHion", Source: "feed-" + distro, KEV: true,
			SnapshotID: &snap.ID, Ranges: []storepg.AdvisoryRange{{Ecosystem: "Test", Distro: distro, Release: "22.04",
				Package: "openssh-server", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", FixState: storepg.FixStateFixed}}},
		{ID: plain, CVE: "CVE-2024-0001", Severity: "medium", Summary: "minor", Source: "feed-" + distro,
			SnapshotID: &snap.ID, Ranges: []storepg.AdvisoryRange{{Ecosystem: "Test", Distro: distro, Release: "22.04",
				Package: "curl", SourcePackage: "curl", Fixed: "7.81.0-1ubuntu1.18", FixState: storepg.FixStateFixed}}},
	} {
		if err := pg.UpsertAdvisoryWithRanges(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	dev := presence.Device{
		ID: "vulnpipe-" + distro, Hostname: "vulnpipe", Platform: "linux",
		Distro: distro, DistroRelease: "22.04", PackageManager: "dpkg",
		Software: []presence.Software{
			{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.9", SourcePackage: "openssh"},
			{Name: "curl", Version: "7.81.0-1ubuntu1.16", SourcePackage: "curl"},
		},
	}
	if err := pg.UpsertDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	s.processVulnAlerts(dev)

	var list findingsResponse
	if rec := getJSON(t, s, "/v1/findings?deviceId="+dev.ID, &list); rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if list.Total != 2 || list.Truncated || list.State == nil || list.State.Coverage != "covered" || list.State.Packages != 2 ||
		list.LatestSnapshotID == nil {
		t.Fatalf("list = %+v state=%+v", list, list.State)
	}
	// KEV first.
	first := list.Findings[0]
	if first.AdvisoryID != kev || !first.KEV || first.Fixed != "1:8.9p1-3ubuntu0.10" || first.Feed != "feed-"+distro ||
		first.SnapshotID == nil || *first.SnapshotID != snap.ID || first.RangeID == nil || first.FeedDate == nil || !first.FeedDate.Equal(fetched) {
		t.Fatalf("first finding = %+v", first)
	}

	// The fleet summary the console's policy view reads.
	var sum findingsSummaryResponse
	if rec := getJSON(t, s, "/v1/findings/summary", &sum); rec.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	var mine *storepg.DeviceFindingsSummary
	for i := range sum.Devices {
		if sum.Devices[i].DeviceID == dev.ID {
			mine = &sum.Devices[i]
		}
	}
	if mine == nil || mine.Coverage != "covered" || mine.Open != 2 || mine.KEV != 1 ||
		len(mine.SeriousKeys) != 1 || mine.SeriousKeys[0] != dev.ID+":"+kev+":openssh" {
		t.Fatalf("summary row = %+v", mine)
	}

	// The JSON a console reads: camelCase, with the evidence fields present.
	var raw struct{ Findings []map[string]any }
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID+"&kind=finding", &raw)
	for _, k := range []string{"advisoryId", "rangeId", "snapshotId", "feed", "feedDate", "key", "kev", "epss", "installed", "fixed"} {
		if _, ok := raw.Findings[0][k]; !ok {
			t.Errorf("finding JSON has no %q: %v", k, raw.Findings[0])
		}
	}

	var detail findingDetailResponse
	if rec := getJSON(t, s, "/v1/findings/"+itoa(first.ID), &detail); rec.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}
	if detail.Advisory == nil || detail.Advisory.ID != kev || !detail.Advisory.KEV || detail.Range == nil ||
		detail.Range.ID != *first.RangeID || detail.Range.Feed != "feed-"+distro || detail.Range.Fixed != "1:8.9p1-3ubuntu0.10" ||
		detail.Snapshot == nil || detail.Snapshot.ID != snap.ID || len(detail.Snapshot.Feeds) != 1 ||
		detail.Snapshot.Feeds[0].SHA256 != strings.Repeat("cd", 32) {
		t.Fatalf("detail = %+v", detail)
	}
	if rec := getJSON(t, s, "/v1/findings/999999999", nil); rec.Code != http.StatusNotFound {
		t.Errorf("missing finding: %d", rec.Code)
	}
	if rec := getJSON(t, s, "/v1/findings/abc", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id: %d", rec.Code)
	}
	if rec := getJSON(t, s, "/v1/findings?kind=bogus", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad kind: %d", rec.Code)
	}

	// Only the KEV finding raised an alert; the medium one did not.
	alerts, err := pg.ListAlerts(ctx, storepg.AlertFilters{DeviceID: dev.ID, Kind: "vuln", Status: "open"})
	if err != nil || len(alerts) != 1 || alerts[0].SourceID != kev {
		t.Fatalf("open vuln alerts = %+v, %v; want exactly the KEV one", alerts, err)
	}

	// An unchanged report is not re-matched (nothing to write, same answer).
	if res, err := s.matchDevice(ctx, dev); err != nil || res != nil {
		t.Errorf("unchanged inventory re-matched: %v %v", res, err)
	}

	// Patch everything: findings close, the alert resolves.
	dev.Software = []presence.Software{
		{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.11", SourcePackage: "openssh"},
		{Name: "curl", Version: "7.81.0-1ubuntu1.18", SourcePackage: "curl"},
	}
	s.processVulnAlerts(dev)
	var after findingsResponse
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID, &after)
	if after.Total != 0 || after.State == nil || after.State.Coverage != "covered" {
		t.Fatalf("patched host: %+v state=%+v", after, after.State)
	}
	var history findingsResponse
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID+"&resolved=1", &history)
	if history.Total != 2 || history.Findings[0].ResolvedAt == nil {
		t.Errorf("closed findings must stay on record: %+v", history)
	}
	// Patching the host is why they closed, and the record says so: the
	// resolution and the version that fixed it come from the same inventory
	// report that closed them.
	patched := map[string]string{"openssh-server": "1:8.9p1-3ubuntu0.11", "curl": "7.81.0-1ubuntu1.18"}
	for _, f := range history.Findings {
		if f.Resolution != storepg.ResolutionFixed || f.ResolvedInstalled != patched[f.Package] {
			t.Errorf("%s closed as %q at %q, want fixed at %q", f.Package, f.Resolution, f.ResolvedInstalled, patched[f.Package])
		}
	}
	if alerts, _ := pg.ListAlerts(ctx, storepg.AlertFilters{DeviceID: dev.ID, Kind: "vuln", Status: "open"}); len(alerts) != 0 {
		t.Errorf("alert still open after patching: %+v", alerts)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A new feed snapshot makes every host be matched again, even though its
// packages did not change; an unchanged host and snapshot is left alone.
func TestRefreshFindingsRematchesOnNewSnapshot(t *testing.T) {
	s, pg := pgServer(t)
	s.store = presence.New(filepath.Join(t.TempDir(), "state.json"))
	ctx := context.Background()
	distro := "zr" + strings.ReplaceAll(strings.ToLower(time.Now().Format("150405.000000")), ".", "")

	feed := func(sha string) storepg.FeedSnapshot {
		snap, err := pg.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "feed-" + distro, URL: "https://example.invalid/f",
			FetchedAt: time.Now(), SHA256: strings.Repeat(sha, 32), RecordCount: 1}})
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	first := feed("ab")
	adv := storepg.Advisory{ID: "TEST-RF-" + distro, CVE: "CVE-2024-0100", Severity: "high", Source: "feed-" + distro,
		SnapshotID: &first.ID, Ranges: []storepg.AdvisoryRange{{Ecosystem: "Test", Distro: distro, Release: "12",
			Package: "libfoo", SourcePackage: "foo", Fixed: "2.0-1", FixState: storepg.FixStateFixed}}}
	if err := pg.UpsertAdvisoryWithRanges(ctx, adv); err != nil {
		t.Fatal(err)
	}
	dev := presence.Device{ID: "refresh-" + distro, Hostname: "refresh", Platform: "linux",
		Distro: distro, DistroRelease: "12", PackageManager: "dpkg",
		Software: []presence.Software{{Name: "libfoo", Version: "1.0-1", SourcePackage: "foo"}}}
	if err := pg.UpsertDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Seed([]presence.Device{dev}); err != nil {
		t.Fatal(err)
	}

	// Other tests' devices may be in the shared database but not in this store.
	if matched, failed := s.refreshFindings(ctx); matched != 1 || failed != 0 {
		t.Fatalf("first refresh: matched %d failed %d, want 1 and 0", matched, failed)
	}
	if matched, _ := s.refreshFindings(ctx); matched != 0 {
		t.Fatalf("second refresh with nothing new re-matched %d hosts", matched)
	}

	// The feed gains a fix; a new snapshot is recorded. The host's packages are
	// unchanged, and the host is matched again against the new data.
	second := feed("cd")
	adv.SnapshotID = &second.ID
	adv.Ranges[0].Fixed = "1.5-1"
	if err := pg.UpsertAdvisoryWithRanges(ctx, adv); err != nil {
		t.Fatal(err)
	}
	if matched, failed := s.refreshFindings(ctx); matched != 1 || failed != 0 {
		t.Fatalf("refresh after a new snapshot: matched %d failed %d, want 1 and 0", matched, failed)
	}
	rows, err := pg.ListFindings(ctx, storepg.FindingFilter{DeviceID: dev.ID})
	if err != nil || len(rows) != 1 || rows[0].Fixed != "1.5-1" || rows[0].SnapshotID == nil || *rows[0].SnapshotID != second.ID {
		t.Fatalf("findings after refresh = %+v, %v", rows, err)
	}
}

// A Rocky host through apid: Red Hat fixed the kernel, Rocky has not released
// it. Nothing to install, so the host has no fixable finding; both CVEs are
// awaiting_vendor, the KEV one still raises an alert (it is exploited now), the
// merely high one does not. When Rocky ships, the finding becomes fixable.
func TestRebuildHostAwaitingVendorThroughApid(t *testing.T) {
	s, pg := pgServer(t)
	s.store = presence.New(filepath.Join(t.TempDir(), "state.json"))
	ctx := context.Background()
	suffix := strings.ReplaceAll(strings.ToLower(time.Now().Format("150405.000000")), ".", "")
	pkg := "kernel-" + suffix
	kevAdv, plainAdv, shippedAdv := "TEST-RKEV-"+suffix, "TEST-RPLAIN-"+suffix, "TEST-RSHIPPED-"+suffix
	snap, err := pg.RecordFeedSnapshot(ctx, []storepg.FeedRef{
		{Name: "rhel-9", URL: "https://example.invalid/rhel", FetchedAt: time.Now(), SHA256: strings.Repeat("ab", 32), RecordCount: 2},
		{Name: "rocky-9", URL: "https://example.invalid/rocky", FetchedAt: time.Now(), SHA256: strings.Repeat("cd", 32), RecordCount: 1}})
	if err != nil {
		t.Fatal(err)
	}
	rhel := func() storepg.AdvisoryRange {
		return storepg.AdvisoryRange{Ecosystem: "Red Hat", Distro: "rhel", Release: "9", Package: pkg,
			Fixed: "0:5.14.0-687.60.1.el9_8", FixState: storepg.FixStateFixed, Issued: "2026-10-20"}
	}
	for _, a := range []storepg.Advisory{
		{ID: kevAdv, CVE: "CVE-2026-91001", Severity: "medium", KEV: true, SnapshotID: &snap.ID, Ranges: []storepg.AdvisoryRange{rhel()}},
		{ID: plainAdv, CVE: "CVE-2026-91002", Severity: "high", SnapshotID: &snap.ID, Ranges: []storepg.AdvisoryRange{rhel()}},
		// Rocky has an erratum of its own, so its feed is loaded for release 9.
		{ID: shippedAdv, CVE: "CVE-2026-91003", Severity: "low", SnapshotID: &snap.ID, Ranges: []storepg.AdvisoryRange{
			{Ecosystem: "Rocky Linux", Distro: "rocky", Release: "9", Package: pkg, Fixed: "0:5.14.0-687.59.1.el9_8", FixState: storepg.FixStateFixed}}},
	} {
		if err := pg.UpsertAdvisoryWithRanges(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	dev := presence.Device{
		ID: "rebuild-" + suffix, Hostname: "rebuild", Platform: "linux",
		Distro: "rocky", DistroRelease: "9.8", PackageManager: "rpm",
		Software: []presence.Software{{Name: pkg, Version: "0:5.14.0-687.59.1.el9_8", SourcePackage: pkg}},
	}
	if err := pg.UpsertDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	s.processVulnAlerts(dev)

	var fixable, awaiting findingsResponse
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID+"&kind=finding", &fixable)
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID+"&kind=awaiting_vendor", &awaiting)
	if fixable.Total != 0 {
		t.Fatalf("a Rocky host with every released fix has fixable findings: %+v", fixable.Findings)
	}
	if awaiting.Total != 2 || awaiting.Findings[0].AdvisoryID != kevAdv || !awaiting.Findings[0].KEV ||
		!strings.Contains(awaiting.Findings[0].Reason, "not yet released by Rocky Linux") {
		t.Fatalf("awaiting_vendor = %+v", awaiting.Findings)
	}
	var sum findingsSummaryResponse
	getJSON(t, s, "/v1/findings/summary?deviceId="+dev.ID, &sum)
	if len(sum.Devices) != 1 || sum.Devices[0].Open != 0 || sum.Devices[0].AwaitingVendor != 2 || sum.Devices[0].KEVAwaitingVendor != 1 {
		t.Fatalf("summary = %+v", sum.Devices)
	}
	var raw struct{ Devices []map[string]any }
	getJSON(t, s, "/v1/findings/summary?deviceId="+dev.ID, &raw)
	for _, k := range []string{"awaitingVendor", "kevAwaitingVendor"} {
		if _, ok := raw.Devices[0][k]; !ok {
			t.Errorf("summary JSON has no %q: %v", k, raw.Devices[0])
		}
	}
	alerts, err := pg.ListAlerts(ctx, storepg.AlertFilters{DeviceID: dev.ID, Kind: "vuln", Status: "open"})
	if err != nil || len(alerts) != 1 || alerts[0].SourceID != kevAdv || alerts[0].Severity != "high" ||
		!strings.Contains(alerts[0].Summary, "not yet released by Rocky Linux") {
		t.Fatalf("open vuln alerts = %+v, %v; want exactly the KEV one, saying why there is nothing to install", alerts, err)
	}

	// Rocky ships the kernel for both CVEs: both become fixable, in place.
	for _, id := range []string{kevAdv, plainAdv} {
		a, err := pg.GetAdvisory(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		a.SnapshotID = &snap.ID
		a.Ranges = append(a.Ranges, storepg.AdvisoryRange{Ecosystem: "Rocky Linux", Distro: "rocky", Release: "9", Package: pkg,
			Fixed: "0:5.14.0-687.60.1.el9_8", FixState: storepg.FixStateFixed, Issued: "2026-10-24"})
		if err := pg.UpsertAdvisoryWithRanges(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	// A new snapshot is what makes apid re-match a host whose packages did not change.
	if _, err := pg.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "rocky-9", URL: "https://example.invalid/rocky",
		FetchedAt: time.Now(), SHA256: strings.Repeat("ef", 32), RecordCount: 3}}); err != nil {
		t.Fatal(err)
	}
	s.processVulnAlerts(dev)
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID+"&kind=finding", &fixable)
	getJSON(t, s, "/v1/findings?deviceId="+dev.ID+"&kind=awaiting_vendor", &awaiting)
	if fixable.Total != 2 || awaiting.Total != 0 {
		t.Fatalf("after Rocky shipped: fixable %d awaiting %d", fixable.Total, awaiting.Total)
	}
}

func TestUrgentCoversKEVAwaitingVendorOnly(t *testing.T) {
	for _, tc := range []struct {
		kind vuln.Kind
		kev  bool
		sev  string
		want bool
	}{
		{vuln.KindFinding, true, "low", true},
		{vuln.KindFinding, false, "critical", true},
		{vuln.KindFinding, false, "high", false},
		{vuln.KindAwaitingVendor, true, "low", true},
		{vuln.KindAwaitingVendor, false, "critical", false}, // nothing to do yet, and not exploited
		{vuln.KindUnfixed, true, "low", true},
		{vuln.KindInformational, true, "critical", false},
	} {
		if got := urgent(vuln.Finding{Kind: tc.kind, KEV: tc.kev, Severity: tc.sev}); got != tc.want {
			t.Errorf("urgent(%s kev=%v %s) = %v, want %v", tc.kind, tc.kev, tc.sev, got, tc.want)
		}
	}
}
