package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"defendsec/internal/storepg"
	"defendsec/internal/surface"
)

// The surface scanner through apid: declare an asset, confirm it, scan it, read
// the findings, fix the zone, scan again and watch the finding close. Every
// scan runs on a fake resolver; nothing leaves the machine.

func refusingScanner(zone *surface.FakeResolver) *surface.Scanner {
	return &surface.Scanner{
		Resolver: zone, Validating: zone,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
		FIPS: func() bool { return false },
	}
}

func surfaceTestServer(t *testing.T, zone *surface.FakeResolver) *Server {
	t.Helper()
	s, _ := pgServer(t)
	s.SetSurfaceScanner(refusingScanner(zone))
	s.surf.cooldown = time.Millisecond
	return s
}

func surfReq(t *testing.T, h http.HandlerFunc, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func uniqueName(prefix, suffix string) string {
	return fmt.Sprintf("%s%d.%s", prefix, time.Now().UnixNano()%1_000_000_000, suffix)
}

func TestSurfaceAPIAuth(t *testing.T) {
	s := testServer() // no Postgres
	for _, tc := range []struct {
		h            http.HandlerFunc
		method, path string
		token        string
		want         int
	}{
		{s.HandleAssets, "GET", "/v1/assets", "", 401},
		{s.HandleAssets, "GET", "/v1/assets", "nope", 401},
		{s.HandleAssets, "GET", "/v1/assets", "viewer-token", 503},
		{s.HandleAssets, "POST", "/v1/assets", "viewer-token", 403},
		{s.HandleAssets, "DELETE", "/v1/assets/1", "viewer-token", 403},
		{s.HandleAssets, "POST", "/v1/assets/1/authorise", "viewer-token", 403},
		{s.HandleAssets, "PUT", "/v1/assets", "admin-token", 405},
		{s.HandleAssets, "GET", "/v1/assets/abc", "admin-token", 400},
		{s.HandleSurfaceFindings, "GET", "/v1/surface/findings", "", 401},
		{s.HandleSurfaceFindings, "POST", "/v1/surface/findings", "admin-token", 405},
		{s.HandleSurfaceFindings, "GET", "/v1/surface/findings", "viewer-token", 503},
		{s.HandleSurfaceScan, "POST", "/v1/surface/scan", "", 401},
		{s.HandleSurfaceScan, "POST", "/v1/surface/scan", "viewer-token", 403},
		{s.HandleSurfaceScan, "GET", "/v1/surface/scan", "admin-token", 405},
		{s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", 503},
	} {
		rec := surfReq(t, tc.h, tc.method, tc.path, tc.token, nil)
		if rec.Code != tc.want {
			t.Errorf("%s %s token=%q: %d, want %d (%s)", tc.method, tc.path, tc.token, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func TestSurfacePipelineThroughApid(t *testing.T) {
	name := uniqueName("pipe", "example.com")
	zoneFor := func(spf string) *surface.FakeResolver {
		z := surface.NewFakeResolver()
		z.Add(
			name+". 300 IN MX 10 mail."+name+".",
			"mail."+name+". 300 IN A 192.0.2.25",
			name+`. 300 IN TXT "`+spf+`"`,
			"_dmarc."+name+`. 300 IN TXT "v=DMARC1; p=none; rua=mailto:r@`+name+`"`,
			name+". 300 IN SOA ns."+name+". h."+name+". 1 7200 3600 1209600 300",
		)
		return z
	}
	zone := zoneFor("v=spf1 ip4:192.0.2.0/24 +all")
	s := surfaceTestServer(t, zone)

	rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets", "admin-token", map[string]any{
		"kind": "domain", "value": strings.ToUpper(name) + ".", "label": "Pipeline test", "dkimSelectors": []string{"Acme"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	a := decode[storepg.SurfaceAsset](t, rec)
	if a.Value != name || a.Authorised || len(a.DKIMSelectors) != 1 || a.DKIMSelectors[0] != "acme" || a.CreatedBy == "" {
		t.Fatalf("asset not normalised or already authorised: %+v", a)
	}
	id := strconv.FormatInt(a.ID, 10)

	// Duplicate and bad input.
	if rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets", "admin-token", map[string]any{"kind": "domain", "value": name}); rec.Code != 409 {
		t.Fatalf("duplicate: %d", rec.Code)
	}
	for label, body := range map[string]any{
		"loopback":        map[string]any{"kind": "ip", "value": "127.0.0.1"},
		"url":             map[string]any{"kind": "domain", "value": "https://example.com"},
		"unknown kind":    map[string]any{"kind": "cidr", "value": "192.0.2.0/24"},
		"typo field":      map[string]any{"kind": "domain", "value": "example.net", "authorized": true},
		"selectors on ip": map[string]any{"kind": "ip", "value": "192.0.2.1", "dkimSelectors": []string{"x"}},
		"shared on name":  map[string]any{"kind": "hostname", "value": "www.example.net", "sharedHosting": true},
	} {
		if rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets", "admin-token", body); rec.Code != 400 {
			t.Errorf("%s: %d %s", label, rec.Code, rec.Body.String())
		}
	}

	// Not confirmed: the scan is refused, for one asset and by name.
	rec = surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID, "wait": true})
	if rec.Code != http.StatusConflict {
		t.Fatalf("scan of an unconfirmed asset: %d %s", rec.Code, rec.Body.String())
	}
	if len(zone.Log) != 0 {
		t.Fatalf("an unconfirmed asset caused DNS queries: %v", zone.Log)
	}
	// Scan-all skips it and says so.
	rec = surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"wait": true})
	if rec.Code != 200 {
		t.Fatalf("scan all: %d", rec.Code)
	}
	for _, q := range zone.Log {
		if strings.Contains(q, name) {
			t.Fatalf("scan-all queried an unconfirmed asset: %v", zone.Log)
		}
	}
	skipped := false
	for _, r := range decode[struct{ Scans []surfaceScanResult }](t, rec).Scans {
		if r.Value == name {
			skipped = r.Status == "skipped"
		}
	}
	if !skipped {
		t.Fatalf("the unconfirmed asset should be reported as skipped: %s", rec.Body.String())
	}

	// Confirm.
	rec = surfReq(t, s.HandleAssets, "POST", "/v1/assets/"+id+"/authorise", "admin-token", map[string]any{"authorised": true})
	if rec.Code != 200 || !decode[storepg.SurfaceAsset](t, rec).Authorised {
		t.Fatalf("authorise: %d %s", rec.Code, rec.Body.String())
	}
	if rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets/"+id+"/authorise", "admin-token", map[string]any{}); rec.Code != 400 {
		t.Fatalf("authorise without a value: %d", rec.Code)
	}

	// Scan and wait.
	rec = surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID, "wait": true})
	if rec.Code != 200 {
		t.Fatalf("scan: %d %s", rec.Code, rec.Body.String())
	}
	scan := decode[struct{ Scans []surfaceScanResult }](t, rec).Scans
	if len(scan) != 1 || scan[0].Status != "done" || scan[0].Summary == nil || scan[0].Summary.New == 0 {
		t.Fatalf("%+v", scan)
	}

	get := func(extra string) surfaceFindingsResponse {
		rec := surfReq(t, s.HandleSurfaceFindings, "GET", "/v1/surface/findings?assetId="+id+extra, "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("findings: %d %s", rec.Code, rec.Body.String())
		}
		return decode[surfaceFindingsResponse](t, rec)
	}
	resp := get("")
	have := map[string]storepg.SurfaceFinding{}
	for _, f := range resp.Findings {
		have[f.FindingID] = f
	}
	for _, want := range []string{"spf.plus_all", "dmarc.p_none"} {
		if _, ok := have[want]; !ok {
			t.Fatalf("missing %s in %v", want, have)
		}
	}
	f := have["spf.plus_all"]
	if f.Severity != "critical" || f.Evidence["records"] == nil || f.Fix == "" || len(f.Controls) == 0 || f.AssetValue != name {
		t.Fatalf("%+v", f)
	}
	if resp.Findings[0].Severity != "critical" {
		t.Fatalf("most severe first: %s", resp.Findings[0].Severity)
	}
	if len(resp.Assets) != 1 || resp.Assets[0].Open["critical"] != 1 || resp.Assets[0].LastScanAt == nil {
		t.Fatalf("asset state: %+v", resp.Assets)
	}
	// The declared DKIM selector is not published and TLS had nothing to
	// connect to: the first is a finding, the second is missing evidence, and
	// missing evidence must be listed, not hidden.
	if _, ok := have["dkim.declared_missing"]; !ok {
		t.Fatalf("a declared selector with no key is a finding: %v", have)
	}
	na := map[string]bool{}
	for _, c := range resp.Assets[0].NotAssessed {
		na[c.Check] = true
		if c.Reason == "" {
			t.Errorf("%s not assessed without a reason", c.Check)
		}
	}
	if !na["tls-cert"] || !na["tls-legacy"] {
		t.Fatalf("not assessed = %v", na)
	}
	for _, c := range resp.Assets[0].Checks {
		if c.Check == "spf" && c.Observed["records"] == nil {
			t.Fatalf("spf observation is empty: %+v", c)
		}
	}

	// Fix SPF in the zone and scan again: that finding closes, the other stays.
	s.SetSurfaceScanner(refusingScanner(zoneFor("v=spf1 ip4:192.0.2.0/24 -all")))
	time.Sleep(5 * time.Millisecond)
	if rec := surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID, "wait": true}); rec.Code != 200 {
		t.Fatalf("rescan: %d %s", rec.Code, rec.Body.String())
	}
	for _, f := range get("").Findings {
		if f.FindingID == "spf.plus_all" {
			t.Fatalf("fixed finding is still open: %+v", f)
		}
	}
	closed := false
	for _, f := range get("&resolved=1").Findings {
		if f.FindingID == "spf.plus_all" && f.ResolvedAt != nil && !f.FirstSeen.After(*f.ResolvedAt) {
			closed = true
		}
	}
	if !closed {
		t.Fatal("the closed finding should be listed with resolved=1, with first-seen before resolved")
	}

	// Withdraw the confirmation: the asset can no longer be scanned.
	if rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets/"+id+"/authorise", "admin-token", map[string]any{"authorised": false}); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if rec := surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID, "wait": true}); rec.Code != http.StatusConflict {
		t.Fatalf("scan after withdrawing confirmation: %d", rec.Code)
	}

	// Remove it: gone from the lists.
	if rec := surfReq(t, s.HandleAssets, "DELETE", "/v1/assets/"+id, "admin-token", nil); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if rec := surfReq(t, s.HandleAssets, "DELETE", "/v1/assets/"+id, "admin-token", nil); rec.Code != 404 {
		t.Fatalf("removing twice: %d", rec.Code)
	}
	if got := get(""); len(got.Findings) != 0 || len(got.Assets) != 0 {
		t.Fatalf("a removed asset is still listed: %+v", got)
	}
}

func TestSurfaceAsyncScanAndViewerReadOnly(t *testing.T) {
	name := uniqueName("async", "example.com")
	zone := surface.NewFakeResolver().Add(name+". 300 IN MX 0 .", name+". 300 IN SOA ns."+name+". h."+name+". 1 7200 3600 1209600 300")
	s := surfaceTestServer(t, zone)
	rec := surfReq(t, s.HandleAssets, "POST", "/v1/assets", "admin-token", map[string]any{"kind": "domain", "value": name, "authorised": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	a := decode[storepg.SurfaceAsset](t, rec)
	if !a.Authorised || a.AuthorisedBy == "" || a.AuthorisedAt == nil {
		t.Fatalf("authorised at declaration should record who and when: %+v", a)
	}
	// A viewer reads the list but cannot change anything.
	if rec := surfReq(t, s.HandleAssets, "GET", "/v1/assets", "viewer-token", nil); rec.Code != 200 {
		t.Fatalf("viewer list: %d", rec.Code)
	}
	if rec := surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "viewer-token", map[string]any{"assetId": a.ID}); rec.Code != 403 {
		t.Fatalf("viewer scan: %d", rec.Code)
	}
	// Without wait the request returns at once and the scan finishes in the background.
	rec = surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if sc := decode[struct{ Scans []surfaceScanResult }](t, rec).Scans; len(sc) != 1 || sc[0].Status != "started" {
		t.Fatalf("%+v", sc)
	}
	s.surf.wg.Wait()
	got, err := s.pg.GetSurfaceAsset(context.Background(), a.ID)
	if err != nil || got.LastScanAt == nil {
		t.Fatalf("background scan did not record: %+v %v", got, err)
	}
	_ = s.pg.RemoveSurfaceAsset(context.Background(), a.ID)
}

func TestSurfaceScheduleScansOnlyDueConfirmedAssets(t *testing.T) {
	confirmedName, unconfirmedName := uniqueName("sched", "example.net"), uniqueName("unconf", "example.org")
	zone := surface.NewFakeResolver().Add(confirmedName+". 300 IN MX 0 .", unconfirmedName+". 300 IN MX 0 .")
	s := surfaceTestServer(t, zone)
	ctx := context.Background()

	// Only this test's assets may be in play: the schedule scans everything due.
	if as, err := s.pg.ListSurfaceAssets(ctx); err == nil {
		for _, a := range as {
			_ = s.pg.RemoveSurfaceAsset(ctx, a.ID)
		}
	}
	mk := func(value string, authorised bool) storepg.SurfaceAsset {
		a, err := s.pg.CreateSurfaceAsset(ctx, storepg.SurfaceAssetInput{Kind: "domain", Value: value, Authorised: authorised, AuthorisedBy: "t", CreatedBy: "t"})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	confirmed, unconfirmed := mk(confirmedName, true), mk(unconfirmedName, false)
	t.Cleanup(func() {
		_ = s.pg.RemoveSurfaceAsset(ctx, confirmed.ID)
		_ = s.pg.RemoveSurfaceAsset(ctx, unconfirmed.ID)
	})

	if n := s.scanDueSurfaceAssets(ctx); n != 1 {
		t.Fatalf("scanned %d assets, want only the confirmed one", n)
	}
	for _, q := range zone.Log {
		if strings.Contains(q, unconfirmedName) {
			t.Fatalf("the scheduler queried an asset nobody confirmed: %v", zone.Log)
		}
	}
	got, _ := s.pg.GetSurfaceAsset(ctx, confirmed.ID)
	if got.LastScanAt == nil {
		t.Fatal("scheduled scan did not record")
	}
	if u, _ := s.pg.GetSurfaceAsset(ctx, unconfirmed.ID); u.LastScanAt != nil {
		t.Fatal("unconfirmed asset was scanned")
	}
	// Scanned within a day: not due again.
	if n := s.scanDueSurfaceAssets(ctx); n != 0 {
		t.Fatalf("second pass scanned %d", n)
	}
}

func TestSurfaceScanCooldownAndConcurrency(t *testing.T) {
	s := testServer()
	s.surf.cooldown = time.Hour
	if why, ok := s.claimSurfaceScan(4242, true); !ok {
		t.Fatal(why)
	}
	if why, ok := s.claimSurfaceScan(4242, true); ok || why != "already_running" {
		t.Fatalf("%q %v", why, ok)
	}
	s.releaseSurfaceScan(4242)
	if why, ok := s.claimSurfaceScan(4242, true); ok || why != "too_soon" {
		t.Fatalf("a manual scan right after another should be told to wait: %q %v", why, ok)
	}
	if _, ok := s.claimSurfaceScan(4242, false); !ok {
		t.Fatal("the schedule is not subject to the manual cooldown")
	}
}

// A scan that fails (here: authorisation withdrawn while it ran, so recording is
// refused) is written to the ledger, for the schedule and for a manual scan alike.
func TestFailedSurfaceScansAreWrittenToTheLedger(t *testing.T) {
	s, pg := pgServer(t)
	ctx := context.Background()
	name := uniqueName("failscan", "example.com")
	zone := surface.NewFakeResolver()
	zone.Add(name+". 300 IN A 192.0.2.80", name+`. 300 IN TXT "v=spf1 -all"`, name+". 300 IN SOA ns."+name+". h."+name+". 1 7200 3600 1209600 300")
	a, err := pg.CreateSurfaceAsset(ctx, storepg.SurfaceAssetInput{Kind: "domain", Value: name, Authorised: true, AuthorisedBy: "t", CreatedBy: "t"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.RemoveSurfaceAsset(ctx, a.ID) })
	sc := refusingScanner(zone)
	sc.Dial = func(context.Context, string, string) (net.Conn, error) {
		_ = pg.SetSurfaceAssetAuthorised(ctx, a.ID, false, "revoker") // withdrawn mid-scan
		return nil, errors.New("connection refused")
	}
	s.SetSurfaceScanner(sc)
	s.surf.cooldown = time.Millisecond

	count := func() int {
		rows, err := pg.ListAudit(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rows {
			if r["action"] == "surface_scan_failed" && strings.Contains(fmt.Sprint(r["detail"]), name) {
				n++
			}
		}
		return n
	}
	s.scanDueSurfaceAssets(ctx) // other tests' assets in this database may be scanned too; only ours is looked at
	if got := count(); got != 1 {
		t.Fatalf("the failed scheduled scan is in the ledger %d times, want 1", got)
	}

	if err := pg.SetSurfaceAssetAuthorised(ctx, a.ID, true, "t"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	rec := surfReq(t, s.HandleSurfaceScan, "POST", "/v1/surface/scan", "admin-token", map[string]any{"assetId": a.ID, "wait": true})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"failed"`) {
		t.Fatalf("manual scan: %d %s", rec.Code, rec.Body.String())
	}
	if got := count(); got != 2 {
		t.Fatalf("the failed manual scan is in the ledger too: %d", got)
	}
}
