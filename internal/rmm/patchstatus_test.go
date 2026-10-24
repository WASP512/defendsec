package rmm_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"defendsec/internal/feeds"
	"defendsec/internal/rmm/dattotest"
	"defendsec/internal/storepg"
)

// One Windows 10 device, audited a few hours ago, with the given patchStatus
// (empty = no patchManagement block at all) and, optionally, empty update lists.
func (r *rig) onlyWin10(status string, emptyLists bool) {
	r.t.Helper()
	pm := ""
	if status != "" {
		pm = `,"patchManagement":{"patchStatus":"` + status + `","patchesApprovedPending":0,"patchesNotApproved":0,"patchesInstalled":10}`
	}
	dev := `{"id":1,"uid":"` + dattotest.Win10 + `","siteUid":"` + dattotest.Site1 + `","deviceType":{"category":"Laptop","type":"Laptop"},"hostname":"DEMO-PC-01","operatingSystem":"Microsoft Windows 10 Pro","online":true,"deleted":false,"lastSeen":1792824000000,"lastAuditDate":1792800000000,"deviceClass":"device"` + pm + `}`
	r.srv.Override["/api/v2/site/"+dattotest.Site1+"/devices"] = `{"pageDetails":{"count":1,"totalCount":1,"prevPageUrl":null,"nextPageUrl":null},"devices":[` + dev + `]}`
	if emptyLists {
		empty := `{"pageDetails":{"nextPageUrl":null},"patches":[]}`
		r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=APPROVED_PENDING"] = empty
		r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=NOT_APPROVED"] = empty
	}
}

// A device RMM has no patch evidence for must be not assessed, never covered,
// and the console counts it as not assessed.
func TestPatchStatusWithoutEvidenceIsNotAssessedNeverClean(t *testing.T) {
	cases := []struct {
		name, status string
		emptyLists   bool
		want         string // host_patch_state.coverage
	}{
		{"NoData, empty lists", "NoData", true, "no_data"},
		{"NoData, updates listed anyway", "NoData", false, "no_data"},
		{"NoPolicy, empty lists", "NoPolicy", true, "no_data"},
		{"no patchManagement block, empty lists", "", true, "no_data"},
		{"NoPolicy, updates listed", "NoPolicy", false, "covered"},
		{"no patchManagement block, updates listed", "", false, "covered"},
		{"FullyPatched, empty lists", "FullyPatched", true, "covered"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.onlyWin10(c.status, c.emptyLists)
			got := r.sync()
			if cov := r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, win10ID); cov != c.want {
				t.Fatalf("coverage = %q, want %q (sync %+v)", cov, c.want, got)
			}
			rs, err := r.store.RMMSummary(context.Background(), r.now)
			if err != nil {
				t.Fatal(err)
			}
			if c.want == "no_data" {
				if rs.NoData != 1 || rs.Covered != 0 {
					t.Errorf("summary covered %d noData %d, want 0 and 1", rs.Covered, rs.NoData)
				}
				if reason := r.text(`SELECT reason FROM host_patch_state WHERE device_id = $1`, win10ID); !strings.Contains(reason, "not a clean result") {
					t.Errorf("reason %q does not say it is not a clean result", reason)
				}
				sum, err := r.store.ExposureSummary(context.Background(), r.now)
				if err != nil {
					t.Fatal(err)
				}
				if sum.Hosts.Assessed != 0 {
					t.Errorf("exposure summary counts %d assessed hosts for a device with no patch evidence", sum.Hosts.Assessed)
				}
			} else if rs.Covered != 1 || rs.NoData != 0 {
				t.Errorf("summary covered %d noData %d, want 1 and 0", rs.Covered, rs.NoData)
			}
		})
	}
}

// A device that goes from patch-managed to NoData keeps the findings it had:
// losing evidence neither closes them nor calls the host clean.
func TestNoDataAfterACoveredReadKeepsOpenFindings(t *testing.T) {
	r := newRig(t)
	r.sync()
	open := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID)
	if open == 0 {
		t.Fatal("setup: the covered read produced no findings")
	}
	r.onlyWin10("NoData", true)
	r.sync()
	if cov := r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, win10ID); cov != "no_data" {
		t.Fatalf("coverage = %q, want no_data", cov)
	}
	if now := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID); now != open {
		t.Errorf("open findings %d -> %d after the device lost its patch data", open, now)
	}
}

// One CVE fixed by two KBs the same device is missing is one row naming the
// host once (a screenshot once showed "DEMO-PC-01, DEMO-PC-01").
func TestTwoMissingKBsForOneCVENameTheHostOnce(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	snap, err := r.store.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "msrc", URL: "https://api.msrc.microsoft.com/cvrf/v3.0",
		FetchedAt: time.Date(2026, 10, 24, 2, 0, 0, 0, time.UTC), SHA256: strings.Repeat("b", 64), RecordCount: 1}})
	if err != nil {
		t.Fatal(err)
	}
	load, err := r.store.BeginFeedLoad(ctx, "msrc", []storepg.RangeScope{{Distro: "windows"}}, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	score := 8.8
	rng := func(kb string) feeds.Range {
		return feeds.Range{Ecosystem: "MSRC", Distro: "windows", Package: kb, Fixed: kb, State: feeds.Fixed, Issued: "2026-10-13"}
	}
	a := feeds.Advisory{ID: "CVE-2099-0001", CVE: "CVE-2099-0001", Summary: "Windows Kernel EoP", Severity: "high", CVSSScore: &score,
		Ranges: []feeds.Range{rng("KB5000001"), rng("KB5000002")}}
	if err := load.Add(ctx, storepgAdvisory(a)); err != nil {
		t.Fatal(err)
	}
	if _, err := load.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.ApplyKEV(ctx, []storepg.KEVRow{{CVE: "CVE-2099-0001", Added: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Name: "x"}}, snap.ID); err != nil {
		t.Fatal(err)
	}
	r.sync()
	page, err := r.store.ListExposure(ctx, storepg.ExposureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var row *storepg.ExposureGroup
	for i := range page.Findings {
		if page.Findings[i].AdvisoryID == "CVE-2099-0001" {
			row = &page.Findings[i]
		}
	}
	if row == nil {
		t.Fatal("the CVE fixed by two missing KBs is not in the exposure list")
	}
	if row.HostCount != 1 || len(row.Hosts) != 1 {
		t.Errorf("hostCount %d, hosts %v: want the one host named once", row.HostCount, row.Hosts)
	}
}
