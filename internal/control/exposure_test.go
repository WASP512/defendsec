package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"defendsec/internal/auditlayer"
	"defendsec/internal/presence"
	"defendsec/internal/storepg"
	"defendsec/internal/vuln"
)

func getExposure(t *testing.T, s *Server, path string, out any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer viewer-token")
	rec := httptest.NewRecorder()
	s.HandleExposure(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v\n%s", path, err, rec.Body.String())
		}
	}
	return rec
}

func TestHandleExposureAuthAndMethod(t *testing.T) {
	s := testServer()
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{http.MethodGet, "/v1/exposure/summary", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/exposure/findings", "nope", http.StatusUnauthorized},
		{http.MethodPost, "/v1/exposure/summary", "admin-token", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/exposure/summary", "admin-token", http.StatusServiceUnavailable}, // no Postgres
		{http.MethodGet, "/v1/exposure/findings", "viewer-token", http.StatusServiceUnavailable},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		s.HandleExposure(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %s token=%q: %d, want %d", tc.method, tc.path, tc.token, rec.Code, tc.want)
		}
	}
}

// The exposure API through apid's handler: ranked rows with keyset paging, the
// provenance of one advisory, the summary and the trend, and its refusals.
func TestExposureAPIThroughApid(t *testing.T) {
	s, pg := pgServer(t)
	ctx := context.Background()
	id := strings.ToLower(time.Now().Format("150405.000000"))[7:]
	id = strings.ReplaceAll(id, ".", "")

	snap, err := pg.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "feed-" + id, URL: "https://example.invalid/oval",
		FetchedAt: time.Now().UTC().Add(-time.Hour), SHA256: strings.Repeat("ef", 32), RecordCount: 2}})
	if err != nil {
		t.Fatal(err)
	}
	kevAdded := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	epss := 0.71
	hi, lo := 9.8, 4.0
	advKEV, advPlain := "EXPO-KEV-"+id, "EXPO-PLAIN-"+id
	for _, a := range []storepg.Advisory{
		{ID: advKEV, CVE: "CVE-2099-" + id, Severity: "high", Summary: "kev one", Source: "test", KEV: true, KEVAdded: &kevAdded,
			EPSS: &epss, CVSSScore: &hi, SnapshotID: &snap.ID},
		{ID: advPlain, CVE: "CVE-2098-" + id, Severity: "medium", Summary: "plain one", Source: "test", CVSSScore: &lo, SnapshotID: &snap.ID},
	} {
		if err := pg.UpsertAdvisoryWithRanges(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	dev := "expo-" + id
	if err := pg.UpsertDevice(ctx, presence.Device{ID: dev, Hostname: "expo-host-" + id, Platform: "linux",
		LastSeen: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	mk := func(adv, cve, sev string, kev bool, e, c *float64) vuln.Finding {
		return vuln.Finding{AdvisoryID: adv, CVE: cve, Kind: vuln.KindFinding, Basis: vuln.BasisDistro, Package: "openssl-" + adv,
			Installed: "1.0", Fixed: "1.1", FixState: "fixed", Severity: sev, KEV: kev, EPSS: e, CVSS: c, Feed: "feed-" + id,
			SnapshotID: &snap.ID}
	}
	res := vuln.Result{Coverage: vuln.CoverageFull, Findings: []vuln.Finding{
		mk(advPlain, "CVE-2098-"+id, "medium", false, nil, &lo),
		mk(advKEV, "CVE-2099-"+id, "high", true, &epss, &hi),
	}}
	if err := pg.RecordFindingsFor(ctx, dev, res, &snap.ID, nil); err != nil {
		t.Fatal(err)
	}

	// Ranked list: ours are in the list, KEV above the plain one.
	var page struct {
		storepg.ExposurePage
		Sort, Bucket, Status string
		LatestSnapshotID     *int64
	}
	if rec := getExposure(t, s, "/v1/exposure/findings?sort=rank&status=open&limit=200", &page); rec.Code != http.StatusOK {
		t.Fatalf("findings: %d %s", rec.Code, rec.Body.String())
	}
	if page.Sort != "rank" || page.Bucket != "fix" || page.Status != "open" || page.LatestSnapshotID == nil {
		t.Errorf("envelope = %+v", page)
	}
	posKEV, posPlain := -1, -1
	for i, g := range page.Findings {
		switch g.AdvisoryID {
		case advKEV:
			posKEV = i
			if !g.KEV || g.KEVAdded == nil || *g.KEVAdded != "2026-09-14" || g.HostCount != 1 || len(g.Hosts) != 1 ||
				g.Hosts[0].Hostname != "expo-host-"+id || g.EPSS == nil || *g.EPSS != 0.71 || g.CVSS == nil || len(g.Kinds) != 1 || g.Kinds[0] != "finding" {
				t.Errorf("kev row = %+v", g)
			}
		case advPlain:
			posPlain = i
		}
	}
	if posKEV < 0 || posPlain < 0 || posKEV > posPlain {
		t.Errorf("positions: kev %d, plain %d (want both present, kev first)", posKEV, posPlain)
	}

	// Keyset paging through the handler: one row per page, cursor passed back.
	seen := 0
	cursor := ""
	for pages := 0; pages < 1000; pages++ {
		path := "/v1/exposure/findings?limit=1"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var p storepg.ExposurePage
		if rec := getExposure(t, s, path, &p); rec.Code != http.StatusOK || len(p.Findings) != 1 {
			t.Fatalf("page %d: %d %s", pages, rec.Code, rec.Body.String())
		}
		seen++
		if p.Next == "" {
			break
		}
		cursor = p.Next
	}
	if seen != page.Total {
		t.Errorf("paged through %d rows, total says %d", seen, page.Total)
	}

	// Provenance drawer data.
	var detail exposureAdvisoryResponse
	if rec := getExposure(t, s, "/v1/exposure/advisory?id="+url.QueryEscape(advKEV), &detail); rec.Code != http.StatusOK {
		t.Fatalf("advisory: %d %s", rec.Code, rec.Body.String())
	}
	if detail.Advisory == nil || !detail.Advisory.KEV || len(detail.Hosts) != 1 || len(detail.Snapshots) != 1 ||
		detail.Snapshots[0].ID != snap.ID || len(detail.Snapshots[0].Feeds) != 1 {
		t.Fatalf("advisory detail = %+v", detail)
	}
	h := detail.Hosts[0]
	if h.Installed != "1.0" || h.Fixed != "1.1" || h.Feed != "feed-"+id || h.SnapshotID == nil || *h.SnapshotID != snap.ID ||
		h.FirstSeen.IsZero() || h.ResolvedAt != nil || h.Key != dev+":"+advKEV+":"+strings.ToLower("openssl-"+advKEV) {
		t.Errorf("host row = %+v", h)
	}
	if rec := getExposure(t, s, "/v1/exposure/advisory?id=NOPE-"+id, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown advisory: %d", rec.Code)
	}

	var sum exposureSummaryResponse
	if rec := getExposure(t, s, "/v1/exposure/summary?top=3", &sum); rec.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	if sum.Fixable.Findings < 2 || sum.Fixable.KEV.Findings < 1 || len(sum.FixThisWeek) == 0 || len(sum.FixThisWeek) > 3 ||
		sum.Hosts.Total < 1 || sum.LatestSnapshotID == nil || sum.KEVWatch == nil || sum.Hosts.SilentList == nil {
		t.Errorf("summary = %+v", sum)
	}
	var raw map[string]any
	getExposure(t, s, "/v1/exposure/summary", &raw)
	for _, k := range []string{"hosts", "fixable", "watch", "sca", "fixThisWeek", "kevWatch", "latestSnapshotId", "generatedAt"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("summary JSON has no %q", k)
		}
	}

	// Trend: by window, and by audit period.
	var tr exposureTrendResponse
	rec := getExposure(t, s, "/v1/exposure/trend", &tr)
	if rec.Code != http.StatusOK || len(tr.Points) != 91 || len(tr.Caveats) == 0 || tr.Period != nil {
		t.Fatalf("trend default window: status %d, %d points, %d caveats, period %v", rec.Code, len(tr.Points), len(tr.Caveats), tr.Period)
	}
	pid := "expo-period-" + id
	if _, err := pg.CreateAuditPeriod(ctx, auditlayer.Period{ID: pid, Name: "Q-" + id, Framework: "nist-800-53",
		StartsAt: time.Now().UTC().AddDate(0, 0, -9), EndsAt: time.Now().UTC().AddDate(0, 0, 60)}); err != nil {
		t.Fatalf("create audit period: %v", err)
	}
	tr = exposureTrendResponse{}
	if rec := getExposure(t, s, "/v1/exposure/trend?periodId="+pid, &tr); rec.Code != http.StatusOK || tr.Period == nil || tr.Period.ID != pid ||
		len(tr.Points) != 10 {
		t.Fatalf("trend by period: %d %+v points=%d", rec.Code, tr.Period, len(tr.Points))
	}
	if last := tr.Points[len(tr.Points)-1]; last.Open < 2 || last.KEV < 1 || !last.Known {
		t.Errorf("last trend point = %+v", last)
	}

	for _, path := range []string{
		"/v1/exposure/findings?sort=severity",
		"/v1/exposure/findings?status=acknowledged",
		"/v1/exposure/findings?bucket=all",
		"/v1/exposure/findings?limit=0x",
		"/v1/exposure/findings?limit=9999",
		"/v1/exposure/findings?cursor=garbage",
		"/v1/exposure/summary?top=0",
		"/v1/exposure/summary?top=26",
		"/v1/exposure/advisory",
		"/v1/exposure/trend?periodId=nope-" + id,
		"/v1/exposure/trend?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z",
		"/v1/exposure/trend?from=yesterday",
	} {
		if rec := getExposure(t, s, path, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (%s)", path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	if rec := getExposure(t, s, "/v1/exposure/nothing", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown endpoint = %d", rec.Code)
	}
}
