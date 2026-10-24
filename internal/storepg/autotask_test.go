package storepg

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/autotask"
	"defendsec/internal/m365"
	"defendsec/internal/surface"
	"defendsec/internal/vuln"
)

// Slice 14: Autotask storage. Every test runs in a throwaway database
// (scratchStore) because the candidates are the whole database's open findings.

func atkSettings() autotask.Settings {
	s := autotask.DefaultSettings()
	s.APIUser = "api-user@example.com"
	s.CompanyID = 3001
	s.QueueID, s.Status = "101", "1"
	s.PriorityCritical, s.PriorityHigh, s.PriorityMedium = "1", "2", "3"
	s.NoteType, s.NotePublish = "1", "2"
	return s
}

func atkLedger(t *testing.T, s *Store, action string) int { return idnAuditCount(t, s, action) }

func TestAutotaskSettingsLedgerAndTheLiveGate(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()

	got, err := s.GetAutotaskSettings(ctx)
	if err != nil || got.Mode != autotask.ModeDryRun || got.AutoComplete || got.MinUrgency != "high" || got.UpdatedAt != nil || got.CompanyID != 0 {
		t.Fatalf("defaults = %+v, %v", got, err)
	}
	set := atkSettings()
	if err := s.SetAutotaskSettings(ctx, "mason", set); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetAutotaskSettings(ctx)
	if err != nil || got.CompanyID != 3001 || got.QueueID != "101" || got.UpdatedBy != "mason" || got.UpdatedAt == nil || got.PriorityHigh != "2" {
		t.Fatalf("saved = %+v, %v", got, err)
	}
	if n := atkLedger(t, s, "autotask_settings_changed"); n != 1 {
		t.Fatalf("%d ledger entries for one change", n)
	}
	if err := s.SetAutotaskSettings(ctx, "mason", autotask.Settings{Mode: "live", MinUrgency: "high", DueDaysCritical: 1, DueDaysHigh: 1, DueDaysMedium: 1, MaxCreates: 1, QueueID: "x"}); !errors.Is(err, autotask.ErrBadSettings) {
		t.Fatalf("a bad value was saved: %v", err)
	}
	if n := atkLedger(t, s, "autotask_settings_changed"); n != 1 {
		t.Fatal("a refused change was chained")
	}

	// Going live needs a dry run, for these settings, that read Autotask and found no problem.
	live := set
	live.Mode = autotask.ModeLive
	if err := s.SetAutotaskSettings(ctx, "mason", live); !errors.Is(err, autotask.ErrBadSettings) || !strings.Contains(err.Error(), "dry run") {
		t.Fatalf("live with no dry run: %v", err)
	}
	record := func(res autotask.Result) {
		t.Helper()
		if _, err := s.RecordAutotaskRun(ctx, "manual:mason", time.Now().Add(-time.Second), res); err != nil {
			t.Fatal(err)
		}
	}
	record(autotask.Result{Mode: autotask.ModeDryRun, Verified: false, UnverifiedWhy: "offline", Fingerprint: live.Fingerprint()})
	if err := s.SetAutotaskSettings(ctx, "mason", live); err == nil {
		t.Fatal("an unverified dry run opened the gate")
	}
	record(autotask.Result{Mode: autotask.ModeDryRun, Verified: true, Fingerprint: live.Fingerprint(), Problems: []string{"the queue is gone"}})
	if err := s.SetAutotaskSettings(ctx, "mason", live); err == nil {
		t.Fatal("a dry run with a problem opened the gate")
	}
	record(autotask.Result{Mode: autotask.ModeLive, Verified: true, Fingerprint: live.Fingerprint()})
	if err := s.SetAutotaskSettings(ctx, "mason", live); err == nil {
		t.Fatal("a live run counted as the dry run")
	}
	record(autotask.Result{Mode: autotask.ModeDryRun, Verified: true, Fingerprint: live.Fingerprint()})
	if err := s.SetAutotaskSettings(ctx, "mason", live); err != nil {
		t.Fatalf("a good dry run did not open the gate: %v", err)
	}
	fp, _ := s.LatestGoodDryRunFingerprint(ctx)
	if fp != live.Fingerprint() {
		t.Errorf("fingerprint = %q", fp)
	}
	other := live
	other.QueueID = "100"
	if err := s.SetAutotaskSettings(ctx, "mason", other); err == nil {
		t.Fatal("changed settings went live on the old dry run")
	}
	other.Mode = autotask.ModeDryRun
	if err := s.SetAutotaskSettings(ctx, "mason", other); err != nil {
		t.Fatalf("saving dry-run settings needs no gate: %v", err)
	}
	if n := atkLedger(t, s, "autotask_dry_run"); n != 3 {
		t.Errorf("%d dry-run entries, want 3", n)
	}
	if n := atkLedger(t, s, "autotask_run"); n != 1 {
		t.Errorf("%d run entries, want 1", n)
	}

	runs, err := s.ListAutotaskRuns(ctx, 10)
	if err != nil || len(runs) != 4 || len(runs[0].Ops) != 0 {
		t.Fatalf("runs = %d, %v", len(runs), err)
	}
	last, err := s.LatestAutotaskRun(ctx)
	if err != nil || last == nil || last.Mode != autotask.ModeDryRun || last.Status != "ok" {
		t.Fatalf("latest = %+v, %v", last, err)
	}
}

func TestAutotaskCandidatesAreTheFixThisWeekList(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedMixed(t, s, now) // four vulnerabilities on host alpha, a surface of two assets

	// A revoked device and a removed asset leave the list.
	expoHost(t, s, "gone", "gone-host")
	a := expoAdv{"V-gone", "CVE-2099-9001", "high", true, "2026-09-01", f64(0.5), f64(8)}
	seedExposure(t, s, []expoAdv{a})
	expoRecord(t, s, "gone", expoFinding(a, vuln.KindFinding, "openssl", "1.0", "1.1"))
	if _, err := s.pool.Exec(ctx, `UPDATE devices SET revoked = true WHERE id = 'gone'`); err != nil {
		t.Fatal(err)
	}
	removed := surfaceAsset(t, s, "domain", "removed.example.org", true)
	if _, err := s.RecordSurfaceScan(ctx, removed.ID, "schedule", report(removed, now, result("spf", true, "", finding("spf", "spf.missing", "removed.example.org", surface.SevHigh)))); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveSurfaceAsset(ctx, removed.ID); err != nil {
		t.Fatal(err)
	}
	// An unfixed finding is the watch list, not Fix this week.
	expoHost(t, s, "w", "watch-host")
	b := expoAdv{"V-unfixed", "CVE-2099-9002", "high", false, "", nil, f64(8)}
	seedExposure(t, s, []expoAdv{b})
	expoRecord(t, s, "w", expoFinding(b, vuln.KindUnfixed, "libx", "1.0", ""))
	// Identity findings.
	if _, err := s.RecordIdentityRun(ctx, "m365", "tenant.example.com", "manual", idnReport(now,
		idnCheck("mfa", true, "", idnFinding("mfa.not_registered", "u1", "ann@example.com", m365.SevCritical), idnFinding("mfa.not_registered", "u2", "bob@example.com", m365.SevMedium)))); err != nil {
		t.Fatal(err)
	}

	cands, err := s.AutotaskCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bySource := map[string][]autotask.Finding{}
	for _, c := range cands {
		bySource[c.Source] = append(bySource[c.Source], c)
	}
	if len(bySource[autotask.SourceVuln]) != 4 || len(bySource[autotask.SourceSurface]) != 5 || len(bySource[autotask.SourceIdentity]) != 2 || len(bySource[autotask.SourceEOL]) != 0 {
		t.Fatalf("candidates by source: vuln %d surface %d identity %d eol %d", len(bySource[autotask.SourceVuln]), len(bySource[autotask.SourceSurface]),
			len(bySource[autotask.SourceIdentity]), len(bySource[autotask.SourceEOL]))
	}

	// The same population as the exposure list's fix bucket: the same advisories, and one surface and identity row per finding.
	page, err := s.ListExposure(ctx, ExposureQuery{Bucket: BucketFix, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var want, got []string
	counts := map[string]int{}
	for _, g := range page.Findings {
		counts[g.Source]++
		if g.Source == SourceVulnerability {
			want = append(want, g.AdvisoryID)
		}
	}
	for _, c := range bySource[autotask.SourceVuln] {
		got = append(got, c.AdvisoryID)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") || counts["surface"] != len(bySource[autotask.SourceSurface]) || counts["identity"] != len(bySource[autotask.SourceIdentity]) {
		t.Fatalf("the candidates differ from the fix list:\nlist  %v %v\ncands %v", want, counts, got)
	}

	// What the planner needs is there.
	var kev autotask.Finding
	for _, c := range bySource[autotask.SourceVuln] {
		if c.KEV {
			kev = c
		}
	}
	if kev.MemberKey != "h1" || kev.MemberLabel != "alpha" || kev.Family == "" || kev.Fixed != "1.1" || kev.EPSS == nil || *kev.EPSS != 0.10 {
		t.Errorf("a vulnerability row = %+v", kev)
	}
	for _, c := range bySource[autotask.SourceSurface] {
		if c.MemberLabel == "" || c.CheckID == "" || c.Fix == "" || !strings.Contains(c.MemberKey, "|"+c.CheckID+"|") {
			t.Errorf("a surface row = %+v", c)
		}
		if c.Severity == "info" {
			t.Error("an info finding is a candidate")
		}
	}
	for _, c := range bySource[autotask.SourceIdentity] {
		if c.Provider != "m365" || c.MemberLabel == "" || c.MemberKey != "m365|mfa.not_registered|"+c.Subject {
			t.Errorf("an identity row = %+v", c)
		}
	}
	groups := autotask.BuildGroups(cands, autotask.DefaultSettings())
	if len(groups) == 0 {
		t.Fatal("no groups")
	}
}

func TestAutotaskTrackedCommitAndLedger(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Round(time.Microsecond)
	tr := autotask.Tracked{GroupKey: "vuln|openssl", Generation: 1, Tag: autotask.Tag("vuln|openssl", 1), TicketID: 9001, TicketNumber: "T20261024.0001", CompanyID: 3001,
		Title: "Update openssl on 2 hosts [DS-x]", State: autotask.StateOpen, Urgency: "critical", CreatedAt: now, UpdatedAt: now,
		Members: map[string]autotask.MemberState{"h1": {Label: "alpha", Digest: "d1"}, "h2": {Label: "bravo", Digest: "d2"}}}
	if err := s.AutotaskCommit(ctx, "schedule", autotask.Change{Action: "autotask_ticket_created", Tracked: tr, Detail: map[string]any{"ticketId": 9001, "tag": tr.Tag}}); err != nil {
		t.Fatal(err)
	}
	list, err := s.AutotaskTracked(ctx)
	if err != nil || len(list) != 1 || list[0].TicketID != 9001 || len(list[0].Members) != 2 || list[0].Members["h2"].Label != "bravo" || list[0].State != autotask.StateOpen {
		t.Fatalf("tracked = %+v, %v", list, err)
	}
	// An update changes the row, not the count; every commit is one ledger entry.
	tr.Members = map[string]autotask.MemberState{"h1": {Label: "alpha", Digest: "d9"}}
	tr.State = autotask.StateResolved
	rt := now.Add(time.Hour)
	tr.ResolvedAt = &rt
	if err := s.AutotaskCommit(ctx, "schedule", autotask.Change{Action: "autotask_ticket_note_added", Tracked: tr, Detail: map[string]any{"ticketId": 9001}}); err != nil {
		t.Fatal(err)
	}
	list, _ = s.AutotaskTracked(ctx)
	if len(list) != 1 || list[0].State != autotask.StateResolved || list[0].ResolvedAt == nil || len(list[0].Members) != 1 || !list[0].CreatedAt.Equal(now) {
		t.Fatalf("after the update: %+v", list)
	}
	if atkLedger(t, s, "autotask_ticket_created") != 1 || atkLedger(t, s, "autotask_ticket_note_added") != 1 {
		t.Fatal("ledger entries missing")
	}
	var actor string
	if err := s.pool.QueryRow(ctx, `SELECT actor FROM audit_log WHERE action = 'autotask_ticket_created'`).Scan(&actor); err != nil || actor != "schedule" {
		t.Errorf("actor = %q, %v", actor, err)
	}

	// The tag is unique: a second row with the same tag is refused, and its ledger entry is not written.
	dup := tr
	dup.GroupKey = "vuln|other"
	if err := s.AutotaskCommit(ctx, "schedule", autotask.Change{Action: "autotask_ticket_created", Tracked: dup, Detail: map[string]any{}}); err == nil {
		t.Fatal("a duplicate tag was stored")
	}
	if atkLedger(t, s, "autotask_ticket_created") != 1 {
		t.Fatal("a refused commit left a ledger entry")
	}
	// A new generation of an action is another row.
	g2 := tr
	g2.Generation, g2.Tag, g2.State, g2.TicketID, g2.ResolvedAt = 2, autotask.Tag("vuln|openssl", 2), autotask.StateOpen, 9002, nil
	if err := s.AutotaskCommit(ctx, "schedule", autotask.Change{Action: "autotask_ticket_created", Tracked: g2, Detail: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	c, err := s.AutotaskTicketCounts(ctx)
	if err != nil || c.Open != 1 || c.Resolved != 0 {
		t.Fatalf("counts = %+v (only the latest generation counts), %v", c, err)
	}
}

func TestAutotaskEvidenceSaysHowItClosed(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	a := expoAdv{"E-adv", "CVE-2099-3001", "high", false, "", f64(0.3), f64(7)}
	b := expoAdv{"E-adv2", "CVE-2099-3002", "high", false, "", f64(0.3), f64(7)}
	seedExposure(t, s, []expoAdv{a, b})
	for _, h := range []string{"fixed", "removed", "blind"} {
		expoHost(t, s, h, "host-"+h)
		expoRecord(t, s, h, expoFinding(a, vuln.KindFinding, "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15"), expoFinding(b, vuln.KindFinding, "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15"))
	}
	closeWith := func(h string, inv *Inventory) {
		t.Helper()
		if err := s.RecordFindingsFor(ctx, h, vuln.Result{Coverage: vuln.CoverageFull}, nil, inv); err != nil {
			t.Fatal(err)
		}
	}
	dpkg := func(pkg, v string) *Inventory {
		return &Inventory{Scheme: vuln.SchemeDpkg, Versions: map[string]string{pkg: v}}
	}
	closeWith("fixed", dpkg("openssl", "3.0.2-0ubuntu1.15"))
	closeWith("removed", dpkg("curl", "7.81.0"))
	closeWith("blind", nil)
	since := time.Now().Add(-time.Hour)
	var fam string
	if err := s.pool.QueryRow(ctx, `SELECT family FROM vuln_findings LIMIT 1`).Scan(&fam); err != nil {
		t.Fatal(err)
	}
	ref := func(dev string) autotask.MemberRef {
		return autotask.MemberRef{GroupKey: "vuln|" + fam, MemberKey: dev, Since: since}
	}
	ev, err := s.AutotaskEvidence(ctx, []autotask.MemberRef{ref("fixed"), ref("removed"), ref("blind"), ref("never-existed")})
	if err != nil {
		t.Fatal(err)
	}
	if got := ev[ref("fixed")]; !got.Found || !strings.Contains(got.Detail, "openssl 3.0.2-0ubuntu1.15 observed, at or above the fixed version 3.0.2-0ubuntu1.15") || !strings.Contains(got.Detail, "(2 findings closed)") || got.ResolvedAt.IsZero() {
		t.Errorf("fixed: %+v", got)
	}
	if got := ev[ref("removed")]; !got.Found || !strings.Contains(got.Detail, "openssl is no longer installed") {
		t.Errorf("removed: %+v", got)
	}
	if got := ev[ref("blind")]; !got.Found || !strings.Contains(got.Detail, "no longer reported") || strings.Contains(got.Detail, "observed") {
		t.Errorf("blind (no inventory): %+v — must not claim a version was observed", got)
	}
	if got, ok := ev[ref("never-existed")]; ok {
		t.Errorf("a host with no record has evidence: %+v", got)
	}
	// Findings that closed before the ticket opened are not its evidence.
	late := autotask.MemberRef{GroupKey: "vuln|" + fam, MemberKey: "fixed", Since: time.Now().Add(time.Hour)}
	if got, _ := s.AutotaskEvidence(ctx, []autotask.MemberRef{late}); len(got) != 0 {
		t.Errorf("evidence from before the ticket: %+v", got)
	}

	// Surface and identity members.
	now := time.Now().UTC()
	dom := surfaceAsset(t, s, "domain", "client.example.com", true)
	if _, err := s.RecordSurfaceScan(ctx, dom.ID, "schedule", report(dom, now.Add(-time.Hour), result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "", surface.SevMedium)))); err != nil {
		t.Fatal(err)
	}
	cands, _ := s.AutotaskCandidates(ctx)
	var sfKey string
	for _, c := range cands {
		if c.Source == autotask.SourceSurface {
			sfKey = c.MemberKey
		}
	}
	if sfKey == "" {
		t.Fatal("no surface candidate")
	}
	sref := autotask.MemberRef{GroupKey: "surface|dmarc.p_none", MemberKey: sfKey, Since: since}
	if got, _ := s.AutotaskEvidence(ctx, []autotask.MemberRef{sref}); len(got) != 0 {
		t.Errorf("an open finding has evidence: %+v", got)
	}
	if _, err := s.RecordSurfaceScan(ctx, dom.ID, "schedule", report(dom, now, result("dmarc", true, ""))); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.AutotaskEvidence(ctx, []autotask.MemberRef{sref}); !got[sref].Found || !strings.Contains(got[sref].Detail, "the latest scan no longer reports it") {
		t.Errorf("surface: %+v", got)
	}
	if _, err := s.RecordIdentityRun(ctx, "m365", "t.example.com", "manual", idnReport(now.Add(-time.Hour), idnCheck("mfa", true, "", idnFinding("mfa.not_registered", "u1", "ann@example.com", m365.SevMedium)))); err != nil {
		t.Fatal(err)
	}
	iref := autotask.MemberRef{GroupKey: "identity|m365|mfa.not_registered", MemberKey: "m365|mfa.not_registered|u1", Since: since}
	if _, err := s.RecordIdentityRun(ctx, "m365", "t.example.com", "manual", idnReport(now, idnCheck("mfa", true, ""))); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.AutotaskEvidence(ctx, []autotask.MemberRef{iref}); !got[iref].Found || !strings.Contains(got[iref].Detail, "the latest read of the tenant no longer reports it") {
		t.Errorf("identity: %+v", got)
	}
}
