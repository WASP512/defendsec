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
	if alerts, _ := pg.ListAlerts(ctx, storepg.AlertFilters{DeviceID: dev.ID, Kind: "vuln", Status: "open"}); len(alerts) != 0 {
		t.Errorf("alert still open after patching: %+v", alerts)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
