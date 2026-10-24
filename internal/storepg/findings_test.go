package storepg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"defendsec/internal/vuln"
)

// The matcher against real advisory tables: ranges written the way the feed
// loader writes them, a host matched through the Store's RangeSource, findings
// persisted, closed when fixed and reopened when they come back.
//
// The distro name is random so rows left by other tests cannot leak in.
func TestMatcherEndToEndAgainstStore(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	distro := "zz" + randID(t)[:8]
	pkg := "openssh-" + randID(t)[:6] // source package, unique to this test
	bin := pkg + "-server"
	adv := "TEST-" + randID(t)

	fetched := time.Date(2026, 10, 20, 3, 0, 0, 0, time.UTC)
	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{
		{Name: "feed-" + distro, URL: "https://example.invalid/oval.xml.bz2", FetchedAt: fetched, SHA256: strings.Repeat("ab", 32), RecordCount: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.UpsertAdvisoryWithRanges(ctx, Advisory{
		ID: adv, CVE: "CVE-2024-6387", Summary: "regreSSHion", Severity: "high", Source: "feed-" + distro,
		KEV: true, EPSS: f64(0.9), CVSSScore: f64(8.1), SnapshotID: &snap.ID,
		Ranges: []AdvisoryRange{
			{Ecosystem: "Test", Distro: distro, Release: "22.04", Package: bin, SourcePackage: pkg,
				Fixed: "1:8.9p1-3ubuntu0.10", FixState: FixStateFixed},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	dev := "dev-" + randID(t)
	seedDevice(t, s, dev)
	host := func(ver string) vuln.Host {
		return vuln.Host{Distro: distro, Release: "22.04", PackageManager: "dpkg",
			Packages: []vuln.Package{{Name: bin, Version: ver, SourcePackage: pkg}}}
	}
	run := func(ver string) vuln.Result {
		t.Helper()
		res, err := vuln.Match(ctx, s, host(ver))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RecordFindings(ctx, dev, res, &snap.ID); err != nil {
			t.Fatal(err)
		}
		return res
	}

	// Behind the fix: one finding carrying advisory, range, snapshot, feed, feed date.
	res := run("1:8.9p1-3ubuntu0.9")
	if res.Coverage != vuln.CoverageFull || len(res.Open()) != 1 {
		t.Fatalf("behind: coverage %s, findings %+v", res.Coverage, res.Findings)
	}
	list, err := s.ListFindings(ctx, FindingFilter{DeviceID: dev})
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	f := list[0]
	if f.AdvisoryID != adv || f.RangeID == nil || f.SnapshotID == nil || *f.SnapshotID != snap.ID ||
		f.Feed != "feed-"+distro || f.FeedDate == nil || !f.FeedDate.Equal(fetched) {
		t.Errorf("finding lacks its evidence: %+v", f)
	}
	if f.Kind != "finding" || f.Basis != "distro" || f.Fixed != "1:8.9p1-3ubuntu0.10" || f.Installed != "1:8.9p1-3ubuntu0.9" ||
		f.Family != pkg || f.Package != bin || !f.KEV || f.EPSS == nil || *f.EPSS != 0.9 || f.CVSS == nil || f.Severity != "high" {
		t.Errorf("finding = %+v", f)
	}
	if f.Key != dev+":"+adv+":"+pkg {
		t.Errorf("triage key = %q", f.Key)
	}
	st, ok, err := s.GetHostVulnState(ctx, dev)
	if err != nil || !ok || st.Coverage != "covered" || st.Packages != 1 || st.DistroMapped != 1 || st.SnapshotID == nil {
		t.Fatalf("host state = %+v ok=%v err=%v", st, ok, err)
	}
	detail, err := s.GetFindingDetail(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Advisory == nil || detail.Advisory.ID != adv || detail.Range == nil || detail.Range.ID != *f.RangeID ||
		detail.Range.Feed != "feed-"+distro || detail.Snapshot == nil || detail.Snapshot.ID != snap.ID {
		t.Errorf("detail = %+v", detail)
	}
	firstSeen := f.FirstSeen

	// Patched: nothing open, and the finding is closed rather than deleted.
	res = run("1:8.9p1-3ubuntu0.11")
	if len(res.Findings) != 0 {
		t.Fatalf("patched host has findings: %+v", res.Findings)
	}
	if open, _ := s.ListFindings(ctx, FindingFilter{DeviceID: dev}); len(open) != 0 {
		t.Errorf("open after patch: %+v", open)
	}
	all, _ := s.ListFindings(ctx, FindingFilter{DeviceID: dev, IncludeResolved: true})
	if len(all) != 1 || all[0].ResolvedAt == nil || !all[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("closed finding must remain with resolved_at set: %+v", all)
	}

	// Regression (downgrade, or a re-image): reopened as new.
	run("1:8.9p1-3ubuntu0.2")
	again, _ := s.ListFindings(ctx, FindingFilter{DeviceID: dev})
	if len(again) != 1 || again[0].ResolvedAt != nil || again[0].ID != f.ID {
		t.Fatalf("reopen = %+v", again)
	}
	if !again[0].FirstSeen.After(firstSeen) {
		t.Errorf("a reopened finding starts a new open period: first_seen %v, was %v", again[0].FirstSeen, firstSeen)
	}

	// A release with no feed is reported as unassessed, not clean.
	res, err = vuln.Match(ctx, s, vuln.Host{Distro: distro, Release: "24.04", PackageManager: "dpkg",
		Packages: []vuln.Package{{Name: bin, Version: "1:8.9p1-3ubuntu0.2", SourcePackage: pkg}}})
	if err != nil || res.Coverage != vuln.CoverageNoFeed || len(res.Findings) != 0 {
		t.Errorf("no-feed release: %+v %v", res, err)
	}

	if _, err := s.GetFinding(ctx, f.ID+1_000_000_000); !errors.Is(err, ErrNoFinding) {
		t.Errorf("missing finding err = %v", err)
	}
}

// The upstream catalogue is consulted only for the ecosystems in
// upstreamEcosystems; an OSV language ecosystem range with the same package
// name must not match a distro package.
func TestUpstreamRangesAreLimitedToLegacyEcosystem(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	name := "pkg-" + randID(t)[:8]
	a, b := "TEST-"+randID(t), "TEST-"+randID(t)
	for id, eco := range map[string]string{a: "PyPI", b: ""} {
		adv := Advisory{ID: id, Severity: "high", Ranges: []AdvisoryRange{
			{Ecosystem: eco, Package: name, Fixed: "2.0", FixState: FixStateFixed}}}
		if err := s.UpsertAdvisoryWithRanges(ctx, adv); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.UpstreamRanges(ctx, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.Package == name {
			t.Errorf("range from ecosystem %q leaked into the upstream catalogue: %+v", c.Ecosystem, c)
		}
	}
}
