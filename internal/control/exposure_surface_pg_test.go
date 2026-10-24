package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"defendsec/internal/evidence"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
	"defendsec/internal/surface"
)

// Slice 7b through apid: a scan's findings appear in the ranked list with the
// reason they rank, open the drawer with the raw observation, leave the list
// when the zone is fixed, join the summary and the trend, and ride in a signed
// evidence export whose surface section verifies. Everything runs on a fake
// resolver.

type surfaceRow = storepg.ExposureGroup

func TestSurfaceFindingsInTheExposureViewThroughApid(t *testing.T) {
	name := uniqueName("expo7b", "example.com")
	zoneFor := func(spf, dmarc string) *surface.FakeResolver {
		z := surface.NewFakeResolver()
		z.Add(
			name+". 300 IN MX 10 mail."+name+".",
			"mail."+name+". 300 IN A 192.0.2.25",
			name+`. 300 IN TXT "`+spf+`"`,
			"_dmarc."+name+`. 300 IN TXT "`+dmarc+`"`,
			name+". 300 IN SOA ns."+name+". h."+name+". 1 7200 3600 1209600 300",
		)
		return z
	}
	s := surfaceTestServer(t, zoneFor("v=spf1 ip4:192.0.2.0/24 +all", "v=DMARC1; p=none; rua=mailto:r@"+name))

	rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets", "admin-token", map[string]any{"kind": "domain", "value": name, "label": "7b"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	a := decode[storepg.SurfaceAsset](t, rec)
	if rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets/"+strconv.FormatInt(a.ID, 10)+"/authorise", "admin-token", map[string]any{"authorised": true}); rec.Code != 200 {
		t.Fatalf("authorise: %d", rec.Code)
	}
	scan := func() {
		t.Helper()
		rec := surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID, "wait": true})
		if rec.Code != 200 {
			t.Fatalf("scan: %d %s", rec.Code, rec.Body.String())
		}
		res := decode[struct{ Scans []surfaceScanResult }](t, rec).Scans
		if len(res) != 1 || res[0].Status != "done" || res[0].Summary == nil || res[0].Summary.Digest == "" {
			t.Fatalf("a recorded scan reports its digest: %+v", res)
		}
	}
	scan()

	list := func(extra string) storepg.ExposurePage {
		t.Helper()
		var page storepg.ExposurePage
		if rec := getExposure(t, s, "/v1/exposure/findings?sort=rank&limit=200"+extra, &page); rec.Code != 200 {
			t.Fatalf("findings: %d %s", rec.Code, rec.Body.String())
		}
		return page
	}
	find := func(p storepg.ExposurePage, id string) (int, surfaceRow) {
		for i, g := range p.Findings {
			if g.Surface != nil && g.Surface.AssetValue == name && g.Surface.ID == id {
				return i, g
			}
		}
		return -1, surfaceRow{}
	}
	page := list("")
	iSPF, spf := find(page, "spf.plus_all")
	iDMARC, dmarc := find(page, "dmarc.p_none")
	if iSPF < 0 || iDMARC < 0 {
		t.Fatalf("the scan's findings are in the Fix this week list: %d %d", iSPF, iDMARC)
	}
	if iSPF > iDMARC {
		t.Errorf("a critical finding ranks above a medium one: %d %d", iSPF, iDMARC)
	}
	if spf.Source != storepg.SourceSurface || spf.Severity != "critical" || spf.Surface.Fix == "" || spf.Surface.Unconfirmed || dmarc.Severity != "medium" {
		t.Errorf("rows: %+v %+v", spf, dmarc)
	}
	// None of them is an info finding, a vulnerability or a KEV.
	for _, g := range page.Findings {
		if g.Surface != nil && g.Surface.AssetValue == name && (g.Severity == "info" || g.KEV) {
			t.Errorf("%+v", g)
		}
	}

	// The drawer: the finding with the raw observation behind it.
	var drawer struct {
		AdvisoryID, Source, Status string
		Detail                     storepg.SurfaceDetail
	}
	if rec := getExposure(t, s, "/v1/exposure/advisory?id="+spf.AdvisoryID, &drawer); rec.Code != 200 {
		t.Fatalf("drawer: %d %s", rec.Code, rec.Body.String())
	}
	if drawer.Source != "surface" || drawer.Status != "open" || drawer.Detail.Finding.FindingID != "spf.plus_all" ||
		drawer.Detail.Confirmed == nil || drawer.Detail.Confirmed.Check != "spf" || len(drawer.Detail.Confirmed.Observed) == 0 ||
		len(drawer.Detail.Intervals) != 1 || drawer.Detail.Intervals[0].ClosedAt != nil {
		t.Fatalf("drawer: %+v", drawer)
	}
	for path, want := range map[string]int{
		"/v1/exposure/advisory?id=surface:1":            400,
		"/v1/exposure/advisory?id=surface:999999999999": 404,
		"/v1/exposure/advisory?id=surface:00000000000x": 400,
	} {
		if rec := getExposure(t, s, path, nil); rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}

	// Summary and trend carry the surface.
	var sum struct {
		Surface storepg.SurfaceExposureSummary
		Fixable struct{ Advisories, Surface, Total int }
	}
	if rec := getExposure(t, s, "/v1/exposure/summary?top=25", &sum); rec.Code != 200 {
		t.Fatalf("summary: %d", rec.Code)
	}
	if sum.Surface.Assets < 1 || sum.Surface.Findings < 2 || sum.Surface.LastScanAt == nil || sum.Fixable.Surface != sum.Surface.Findings || sum.Fixable.Total != sum.Fixable.Advisories+sum.Fixable.Surface {
		t.Fatalf("summary: %+v", sum)
	}
	var trend struct {
		Points       []storepg.TrendPoint
		SurfaceSince *string
	}
	if rec := getExposure(t, s, "/v1/exposure/trend", &trend); rec.Code != 200 || trend.SurfaceSince == nil || len(trend.Points) == 0 {
		t.Fatalf("trend: %d %+v", rec.Code, trend)
	}
	if last := trend.Points[len(trend.Points)-1]; !last.SurfaceKnown || last.Surface < 2 {
		t.Fatalf("today's surface point: %+v", last)
	}

	// Fix the zone and scan again: the findings close and leave the fix list.
	s.SetSurfaceScanner(refusingScanner(zoneFor("v=spf1 ip4:192.0.2.0/24 -all", "v=DMARC1; p=reject; rua=mailto:r@"+name)))
	scan()
	page = list("")
	if i, _ := find(page, "spf.plus_all"); i >= 0 {
		t.Fatalf("a fixed finding must leave the list")
	}
	resolved := list("&status=resolved")
	if i, g := find(resolved, "spf.plus_all"); i < 0 || g.ResolvedAt == nil {
		t.Fatalf("a fixed finding is in the Resolved list with its date")
	}

	// The signed export carries the surface section and it verifies.
	key, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.signer = key
	req := httptest.NewRequest(http.MethodGet, "/v1/audit/evidence?scope=surface", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	s.HandleEvidenceExport(w, req)
	if w.Code != 200 {
		t.Fatalf("export: %d %s", w.Code, w.Body.String())
	}
	if out := os.Getenv("DEFENDSEC_TEST_BUNDLE_OUT"); out != "" {
		// For a manual look with defendsec-verify; never set in CI.
		if err := os.WriteFile(out, w.Body.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := evidence.Read(strings.NewReader(w.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	if b.Surface == nil {
		t.Fatal("the export has no surface section")
	}
	mine, attested := 0, 0
	for _, sc := range b.Surface.Scans {
		if sc.AssetValue == name {
			mine++
		}
	}
	rep := evidence.Verify(b)
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.Name, "surface") && !c.OK {
			t.Fatalf("the surface section must verify: %+v", c)
		}
	}
	attested = rep.Surface.ScansAttested
	if mine != 2 || attested < 2 || rep.Surface.FindingsVerified < 3 {
		t.Fatalf("this asset's two scans are attested and its findings verified: mine=%d %+v", mine, rep.Surface)
	}
	var seenFinding bool
	for _, f := range b.Surface.Findings {
		if f.AssetValue == name && f.FindingID == "spf.plus_all" {
			seenFinding = true
			if len(f.Intervals) != 1 || f.Intervals[0].ClosedAt == nil || len(f.Evidence) == 0 {
				t.Fatalf("open on date A, closed on date B, with its evidence: %+v", f)
			}
		}
	}
	if !seenFinding {
		t.Fatal("the finding is in the export")
	}
}
