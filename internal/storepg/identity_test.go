package storepg

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/exposure"
	"defendsec/internal/m365"
	"defendsec/internal/vuln"
)

// Slice 12: identity findings. Every test runs in a throwaway database
// (scratchStore) because the list, summary and trend count the whole database.

func idnFinding(id, subject, label string, sev m365.Severity) m365.Finding {
	return m365.Finding{
		ID: id, Subject: subject, SubjectLabel: label, Severity: sev, Title: "title of " + id, Detail: "detail of " + id,
		Fix: "fix of " + id, Evidence: map[string]any{"user": label}, Controls: []string{"nist-800-53:IA-2(2)"},
	}
}

func idnCheck(group string, assessed bool, reason string, fs ...m365.Finding) m365.CheckResult {
	return m365.CheckResult{Check: group, Assessed: assessed, Reason: reason, Observed: map[string]any{"n": len(fs)}, Findings: fs}
}

func idnReport(at time.Time, checks ...m365.CheckResult) *m365.Report {
	return &m365.Report{
		StartedAt: at, FinishedAt: at.Add(2 * time.Second), Checks: checks, Requests: 7,
		NotAssessed: []m365.NotAssessed{{What: "Mailbox-level forwarding", Why: "Exchange only"}},
		Counts:      m365.Counts{Users: 9},
	}
}

func idnAll(t *testing.T, s *Store, resolved bool) map[string]IdentityFinding {
	t.Helper()
	list, err := s.ListIdentityFindings(context.Background(), IdentityFindingFilter{Provider: "m365", Resolved: resolved})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]IdentityFinding{}
	for _, f := range list {
		out[f.FindingID+"/"+f.Subject] = f
	}
	return out
}

func idnAuditCount(t *testing.T, s *Store, action string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIdentityRunBookkeeping(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-96 * time.Hour).Round(time.Microsecond)

	mfaSam := idnFinding("mfa.not_registered", "u-sam", "sam@example.com", m365.SevCritical)
	mfaCasey := idnFinding("mfa.not_registered", "u-casey", "casey@example.com", m365.SevMedium)
	rule := idnFinding("inbox_rule.hides_mail", "u-casey/r1", "casey@example.com · Intuit stuff", m365.SevCritical)
	ruleDana := idnFinding("inbox_rule.forward_external", "u-dana/r9", "dana@example.com · From partner", m365.SevHigh)

	run1, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "manual:test", idnReport(t0,
		idnCheck(m365.GroupMFA, true, "", mfaSam, mfaCasey),
		idnCheck(m365.GroupInboxRules, true, "", rule, ruleDana),
		idnCheck(m365.GroupLegacyAuth, true, ""),
		idnCheck(m365.GroupAdminRoles, true, "")))
	if err != nil {
		t.Fatal(err)
	}
	if run1.Status != "ok" || run1.Open != 4 || run1.Opened != 4 || run1.Resolved != 0 || run1.TriggeredBy != "manual:test" {
		t.Fatalf("run 1 = %+v", run1)
	}
	open := idnAll(t, s, false)
	if len(open) != 4 || open["inbox_rule.hides_mail/u-casey/r1"].Detail != "detail of inbox_rule.hides_mail" {
		t.Fatalf("open after run 1: %d", len(open))
	}
	if !open["mfa.not_registered/u-sam"].FirstSeen.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("first seen = %v", open["mfa.not_registered/u-sam"].FirstSeen)
	}
	if got := open["mfa.not_registered/u-sam"].Controls; len(got) != 1 || got[0] != "nist-800-53:IA-2(2)" {
		t.Errorf("controls = %v", got)
	}

	// Run 2: Sam registered MFA (fixed), Casey's severity rose; the rules check was NOT
	// assessed (permission lost); Dana's mailbox is not covered by the MFA... no, by the
	// rules check, which did not run at all.
	casey2 := mfaCasey
	casey2.Severity = m365.SevHigh
	run2, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", idnReport(t0.Add(24*time.Hour),
		idnCheck(m365.GroupMFA, true, "", casey2),
		idnCheck(m365.GroupInboxRules, false, "Microsoft refused every mailbox read (403)"),
		idnCheck(m365.GroupLegacyAuth, true, ""),
		idnCheck(m365.GroupAdminRoles, true, "")))
	if err != nil {
		t.Fatal(err)
	}
	if run2.Status != "partial" || run2.Resolved != 1 || run2.Opened != 0 || run2.Open != 3 {
		t.Fatalf("run 2 = %+v", run2)
	}
	open = idnAll(t, s, false)
	if _, still := open["mfa.not_registered/u-sam"]; still {
		t.Error("Sam's finding stayed open although the MFA check was assessed and did not confirm it")
	}
	if open["mfa.not_registered/u-casey"].Severity != "high" {
		t.Errorf("severity change not stored: %v", open["mfa.not_registered/u-casey"].Severity)
	}
	// The unassessed rules check resolved nothing, and its findings are shown unconfirmed.
	for _, k := range []string{"inbox_rule.hides_mail/u-casey/r1", "inbox_rule.forward_external/u-dana/r9"} {
		f, ok := open[k]
		if !ok || !f.Unconfirmed {
			t.Errorf("%s: open=%v unconfirmed=%v, want open and unconfirmed", k, ok, f.Unconfirmed)
		}
	}
	if open["mfa.not_registered/u-casey"].Unconfirmed {
		t.Error("an assessed check's finding is unconfirmed")
	}
	closed := idnAll(t, s, true)
	if f, ok := closed["mfa.not_registered/u-sam"]; !ok || f.ResolvedAt == nil || !f.ResolvedAt.Equal(t0.Add(24*time.Hour+2*time.Second)) {
		t.Errorf("Sam's finding is not closed at run 2: %+v", f.ResolvedAt)
	}

	// Run 3: the rules check ran again but could not read Dana's mailbox. Casey's rule is
	// gone (resolved); Dana's finding is neither confirmed nor resolved, and is unconfirmed.
	run3, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", idnReport(t0.Add(48*time.Hour),
		idnCheck(m365.GroupMFA, true, "", casey2),
		func() m365.CheckResult {
			c := idnCheck(m365.GroupInboxRules, true, "")
			c.UnassessedPrefixes = []string{"u-dana/"}
			return c
		}(),
		idnCheck(m365.GroupLegacyAuth, true, ""),
		idnCheck(m365.GroupAdminRoles, true, "")))
	if err != nil {
		t.Fatal(err)
	}
	if run3.Resolved != 1 {
		t.Fatalf("run 3 resolved %d, want 1 (Casey's rule only)", run3.Resolved)
	}
	open = idnAll(t, s, false)
	if _, ok := open["inbox_rule.hides_mail/u-casey/r1"]; ok {
		t.Error("Casey's rule is still open although its mailbox was read and the rule is gone")
	}
	if d, ok := open["inbox_rule.forward_external/u-dana/r9"]; !ok || !d.Unconfirmed {
		t.Errorf("Dana's finding: open=%v unconfirmed=%v, want open and unconfirmed (her mailbox was not read)", ok, d.Unconfirmed)
	}

	// Run 4: the credentials were refused: every check is not assessed. Nothing changes.
	fatal := &m365.Report{StartedAt: t0.Add(60 * time.Hour), FinishedAt: t0.Add(60 * time.Hour), Fatal: "credentials refused",
		Checks: []m365.CheckResult{{Check: m365.GroupMFA, Reason: "x"}, {Check: m365.GroupInboxRules, Reason: "x"}, {Check: m365.GroupLegacyAuth, Reason: "x"}, {Check: m365.GroupAdminRoles, Reason: "x"}}}
	run4, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", fatal)
	if err != nil {
		t.Fatal(err)
	}
	if run4.Status != "not_assessed" || run4.Resolved != 0 || run4.Open != 2 || run4.Reason != "credentials refused" {
		t.Fatalf("run 4 = %+v", run4)
	}
	if n := len(idnAll(t, s, false)); n != 2 {
		t.Errorf("%d findings open after a not-assessed run, want 2 (nothing resolved)", n)
	}

	// Run 5: Sam's finding comes back. The interval that ended is kept and first_seen restarts.
	run5At := t0.Add(72 * time.Hour)
	if _, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", idnReport(run5At,
		idnCheck(m365.GroupMFA, true, "", casey2, mfaSam),
		idnCheck(m365.GroupInboxRules, true, ""),
		idnCheck(m365.GroupLegacyAuth, true, ""),
		idnCheck(m365.GroupAdminRoles, true, ""))); err != nil {
		t.Fatal(err)
	}
	sam := idnAll(t, s, false)["mfa.not_registered/u-sam"]
	if sam.ResolvedAt != nil || !sam.FirstSeen.Equal(run5At.Add(2*time.Second)) {
		t.Errorf("reopened finding: resolved=%v first_seen=%v, want a restarted first_seen", sam.ResolvedAt, sam.FirstSeen)
	}
	d, err := s.GetIdentityDetail(ctx, sam.Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Intervals) != 2 || d.Intervals[0].ClosedAt == nil || d.Intervals[1].ClosedAt != nil {
		t.Fatalf("intervals = %+v, want one closed span then an open one", d.Intervals)
	}
	if !d.Intervals[0].OpenedAt.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("the first span opened at %v", d.Intervals[0].OpenedAt)
	}
	if d.Latest == nil || d.CheckState == nil || d.CheckState.Check != m365.GroupMFA || !d.CheckState.Assessed {
		t.Errorf("detail latest/check state = %+v / %+v", d.Latest, d.CheckState)
	}

	// The ledger: one chained entry per run, and one for the settings.
	if n := idnAuditCount(t, s, "identity_run_recorded"); n != 5 {
		t.Errorf("identity_run_recorded entries = %d, want 5", n)
	}
	// History of runs.
	runs, err := s.ListIdentityRuns(ctx, "m365", 10)
	if err != nil || len(runs) != 5 {
		t.Fatalf("runs = %d, %v", len(runs), err)
	}
	if len(runs[0].NotAssessed) != 1 || len(runs[0].Checks) != 4 {
		t.Errorf("latest run = %+v", runs[0])
	}
}

func TestIdentitySettings(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	got, err := s.GetM365Settings(ctx)
	if err != nil || got.Configured || got.GlobalAdminMax != 4 || got.Cloud != "global" || got.ResolveFolders {
		t.Fatalf("defaults = %+v, %v", got, err)
	}
	good := M365Settings{TenantID: "aaaaaaaa-1111-4222-8333-444444444444", ClientID: "bbbbbbbb-1111-4222-8333-555555555555", Cloud: "global",
		GlobalAdminMax: 3, TrustedDomains: []string{" Partner.Example.org ", "partner.example.org", ""}, FinanceTerms: []string{"Tax Refund"}, ResolveFolders: true}
	if err := s.SetM365Settings(ctx, "tester", good); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetM365Settings(ctx)
	if !got.Configured || got.GlobalAdminMax != 3 || len(got.TrustedDomains) != 1 || got.TrustedDomains[0] != "partner.example.org" || got.FinanceTerms[0] != "tax refund" || !got.ResolveFolders || got.UpdatedBy != "tester" {
		t.Errorf("saved = %+v", got)
	}
	if n := idnAuditCount(t, s, "identity_settings_changed"); n != 1 {
		t.Errorf("settings ledger entries = %d, want 1", n)
	}
	bad := map[string]M365Settings{
		"tenant common":         {TenantID: "common", ClientID: good.ClientID, GlobalAdminMax: 4},
		"client id not guid":    {TenantID: good.TenantID, ClientID: "nope", GlobalAdminMax: 4},
		"tenant without client": {TenantID: good.TenantID, GlobalAdminMax: 4},
		"limit zero":            {TenantID: good.TenantID, ClientID: good.ClientID, GlobalAdminMax: 0},
		"limit huge":            {TenantID: good.TenantID, ClientID: good.ClientID, GlobalAdminMax: 51},
		"bad cloud":             {TenantID: good.TenantID, ClientID: good.ClientID, GlobalAdminMax: 4, Cloud: "mars"},
		"bad domain":            {TenantID: good.TenantID, ClientID: good.ClientID, GlobalAdminMax: 4, TrustedDomains: []string{"not a domain"}},
		"short finance term":    {TenantID: good.TenantID, ClientID: good.ClientID, GlobalAdminMax: 4, FinanceTerms: []string{"ab"}},
	}
	for name, in := range bad {
		if err := s.SetM365Settings(ctx, "tester", in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := idnAuditCount(t, s, "identity_settings_changed"); n != 1 {
		t.Errorf("refused settings wrote ledger entries: %d", n)
	}
}

// idnSeedMixed puts vulnerabilities, a surface finding and identity findings of every
// severity into s and returns the identity finding keys by finding id + subject.
func idnSeedMixed(t *testing.T, s *Store, now time.Time) map[string]string {
	t.Helper()
	ctx := context.Background()
	advs := []expoAdv{
		{"V-kev", "CVE-2099-2001", "high", true, "2026-09-01", f64(0.10), f64(7.0)},
		{"V-epss", "CVE-2099-2002", "medium", false, "", f64(0.60), f64(4.0)},
		{"V-cvss6", "CVE-2099-2003", "medium", false, "", nil, f64(6.0)},
		{"V-cvss4", "CVE-2099-2004", "low", false, "", nil, f64(4.0)},
	}
	seedExposure(t, s, advs)
	expoHost(t, s, "h1", "alpha")
	var fs []vuln.Finding
	for i, a := range advs {
		fs = append(fs, expoFinding(a, vuln.KindFinding, "pkg"+itoa(i), "1.0", "1.1"))
	}
	expoRecord(t, s, "h1", fs...)

	t0 := now.Add(-48 * time.Hour)
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(t0,
		idnCheck(m365.GroupMFA, true, "",
			idnFinding("mfa.not_registered", "u1", "sam.admin@example.com", m365.SevCritical),
			idnFinding("mfa.not_registered", "u2", "pat@example.com", m365.SevHigh),
			idnFinding("mfa.not_registered", "u3", "casey@example.com", m365.SevMedium)),
		idnCheck(m365.GroupLegacyAuth, true, "", idnFinding("legacyauth.partial", "tenant", "Microsoft 365 tenant", m365.SevLow)),
		idnCheck(m365.GroupInboxRules, true, "", idnFinding("inbox_rule.forward_external", "u4/r1", "dana@example.com · From partner", m365.SevCritical)),
		idnCheck(m365.GroupAdminRoles, true, ""))); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListIdentityFindings(ctx, IdentityFindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, f := range list {
		keys[f.FindingID+"/"+f.Subject] = f.Key
	}
	return keys
}

func idnLabel(g ExposureGroup) string {
	if g.Identity != nil {
		return g.Identity.ID + "/" + g.Identity.Key
	}
	return g.AdvisoryID
}

func idnLabels(p ExposurePage) []string {
	var out []string
	for _, g := range p.Findings {
		out = append(out, idnLabel(g))
	}
	return out
}

func TestIdentityFindingsAreRankedWithVulnerabilities(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	idnSeedMixed(t, s, time.Now().UTC())
	p, err := s.ListExposure(ctx, ExposureQuery{})
	if err != nil {
		t.Fatal(err)
	}
	// KEV first; then the critical and high identity findings (older finding id first
	// at equal severity); then vulnerabilities by EPSS; then CVSS-only rows with the
	// medium identity finding among them; the low one among the low.
	want := []string{
		"V-kev",
		"mfa.not_registered/u1",
		"inbox_rule.forward_external/u4/r1",
		"mfa.not_registered/u2",
		"V-epss",
		"V-cvss6",
		"mfa.not_registered/u3", // medium: CVSS-equivalent 5.0, between 6.0 and 4.0
		"V-cvss4",
		"legacyauth.partial/tenant", // low: 2.0
	}
	got := idnLabels(p)
	// u1 and u4 are both critical: the lower finding id (u1, stored first? ids follow the
	// order the checks were stored: mfa, legacy, inbox) comes first.
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("order:\n got  %v\n want %v", got, want)
	}
	if p.Total != 9 {
		t.Errorf("total = %d, want 9", p.Total)
	}
	row := p.Findings[1]
	if row.Source != SourceIdentity || row.Identity == nil || len(row.Hosts) != 0 || row.HostCount != 0 || row.Kinds[0] != "identity" {
		t.Errorf("identity row = %+v", row)
	}
	if row.Summary != "title of mfa.not_registered" || row.Identity.Subject != "sam.admin@example.com" || row.Identity.Provider != "m365" ||
		row.Identity.Fix != "fix of mfa.not_registered" || row.Identity.Check != "mfa" || row.Identity.Unconfirmed || row.Identity.LastSeen.IsZero() {
		t.Errorf("identity row fields = %+v", row.Identity)
	}
	if !strings.HasPrefix(row.AdvisoryID, exposure.IdentityKeyPrefix) || len(row.AdvisoryID) != len(exposure.IdentityKeyPrefix)+12 {
		t.Errorf("row key = %q", row.AdvisoryID)
	}

	// Identity rows are never in the watch bucket, never in the KEV callout, and the
	// resolved list shows only what closed.
	if w, err := s.ListExposure(ctx, ExposureQuery{Bucket: BucketWatch}); err != nil || w.Total != 0 {
		t.Errorf("watch bucket: %v total %d", err, w.Total)
	}
	if k, err := s.ListExposure(ctx, ExposureQuery{KEVOnly: true}); err != nil || k.Total != 1 || idnLabel(k.Findings[0]) != "V-kev" {
		t.Errorf("KEV only: %v %v", err, idnLabels(k))
	}
	if r, err := s.ListExposure(ctx, ExposureQuery{Status: ExposureResolved}); err != nil || r.Total != 0 {
		t.Errorf("resolved list: %v total %d", err, r.Total)
	}
}

func TestIdentityOrderMatchesRankingRuleAndPagesByKeyset(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	idnSeedMixed(t, s, time.Now().UTC())
	full, err := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	items := make([]exposure.Item, 0, len(full.Findings))
	for _, g := range full.Findings {
		it := exposure.Item{AdvisoryID: g.AdvisoryID, Severity: g.Severity, KEV: g.KEV, EPSS: g.EPSS, CVSS: g.CVSS,
			Surface: g.Source == SourceSurface, Identity: g.Source == SourceIdentity}
		if g.KEVAdded != nil {
			it.KEVAdded = day(*g.KEVAdded)
		}
		items = append(items, it)
	}
	sorted := append([]exposure.Item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return exposure.Compare(sorted[i], sorted[j]) < 0 })
	for i := range items {
		if items[i].AdvisoryID != sorted[i].AdvisoryID {
			t.Fatalf("SQL order differs from exposure.Compare at %d: SQL %s, Go %s", i, items[i].AdvisoryID, sorted[i].AdvisoryID)
		}
	}
	for _, size := range []int{1, 2, 4, 200} {
		var got []string
		cursor := ""
		for pages := 0; pages < 20; pages++ {
			p, err := s.ListExposure(ctx, ExposureQuery{Limit: size, Cursor: cursor})
			if err != nil {
				t.Fatalf("limit %d: %v", size, err)
			}
			got = append(got, idnLabels(p)...)
			if p.Next == "" {
				break
			}
			cursor = p.Next
		}
		if strings.Join(got, "|") != strings.Join(idnLabels(full), "|") {
			t.Fatalf("limit %d paged to\n %v\nwant\n %v", size, got, idnLabels(full))
		}
	}
}

// A mutation test in miniature: each severity must land where the rule says, so a typo in
// the SQL score of one of them is caught here, not by a reader of the list.
func TestIdentityEverySeverityRanksWhereTheRuleSays(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	expoHost(t, s, "h1", "alpha")
	advs := []expoAdv{
		{"V-cvss9", "CVE-2099-3001", "critical", false, "", nil, f64(9.0)},
		{"V-cvss8", "CVE-2099-3002", "high", false, "", nil, f64(8.0)},
		{"V-cvss7", "CVE-2099-3003", "high", false, "", nil, f64(7.0)},
		{"V-cvss5", "CVE-2099-3004", "medium", false, "", nil, f64(5.0)},
		{"V-cvss3", "CVE-2099-3005", "low", false, "", nil, f64(3.0)},
		{"V-cvss1", "CVE-2099-3006", "low", false, "", nil, f64(1.0)},
	}
	seedExposure(t, s, advs)
	var fs []vuln.Finding
	for i, a := range advs {
		fs = append(fs, expoFinding(a, vuln.KindFinding, "pkg"+itoa(i), "1.0", "1.1"))
	}
	expoRecord(t, s, "h1", fs...)
	now := time.Now().UTC()
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(now,
		idnCheck(m365.GroupMFA, true, "",
			idnFinding("a.critical", "s", "c", m365.SevCritical),
			idnFinding("a.high", "s", "h", m365.SevHigh),
			idnFinding("a.medium", "s", "m", m365.SevMedium),
			idnFinding("a.low", "s", "l", m365.SevLow)))); err != nil {
		t.Fatal(err)
	}
	p, err := s.ListExposure(ctx, ExposureQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	// critical (9.5) and high (8.0) identity rows are in the urgent band, before every
	// vulnerability; medium (5.0) ties V-cvss5 and the identity row wins the tie on key
	// ("identity:" sorts before "V-" bytewise? 'V' is 0x56, 'i' is 0x69, so V- first).
	want := []string{"a.critical/s", "a.high/s", "V-cvss9", "V-cvss8", "V-cvss7", "V-cvss5", "a.medium/s", "V-cvss3", "a.low/s", "V-cvss1"}
	if got := idnLabels(p); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("order:\n got  %v\n want %v", got, want)
	}
}

func TestIdentitySummaryDetailAndTrend(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sum0, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if sum0.Identity.Configured || sum0.Identity.Findings != 0 || sum0.Identity.LastRunAt != nil || sum0.Identity.LastStatus != "" {
		t.Fatalf("empty summary = %+v", sum0.Identity)
	}
	if err := s.SetM365Settings(ctx, "t", M365Settings{TenantID: "aaaaaaaa-1111-4222-8333-444444444444", ClientID: "bbbbbbbb-1111-4222-8333-555555555555", GlobalAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	keys := idnSeedMixed(t, s, now)
	// A second run: one check not assessed, so the card says so.
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(now.Add(-time.Hour),
		idnCheck(m365.GroupMFA, true, "",
			idnFinding("mfa.not_registered", "u1", "sam.admin@example.com", m365.SevCritical),
			idnFinding("mfa.not_registered", "u2", "pat@example.com", m365.SevHigh),
			idnFinding("mfa.not_registered", "u3", "casey@example.com", m365.SevMedium)),
		idnCheck(m365.GroupLegacyAuth, false, "Policy.Read.All missing"),
		idnCheck(m365.GroupInboxRules, true, "", idnFinding("inbox_rule.forward_external", "u4/r1", "dana@example.com · From partner", m365.SevCritical)),
		idnCheck(m365.GroupAdminRoles, true, ""))); err != nil {
		t.Fatal(err)
	}
	sum, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	id := sum.Identity
	if !id.Configured || id.Findings != 5 || id.BySeverity["critical"] != 2 || id.BySeverity["high"] != 1 || id.BySeverity["medium"] != 1 || id.BySeverity["low"] != 1 {
		t.Errorf("identity summary = %+v", id)
	}
	if id.LastStatus != "partial" || id.ChecksNotAssessed != 1 || id.ChecksTotal != 4 || id.LastRunAt == nil || !strings.Contains(id.LastReason, "Policy.Read.All") {
		t.Errorf("identity run state = %+v", id)
	}
	if sum.Fixable.Identity != 5 || sum.Fixable.Total != sum.Fixable.Advisories+sum.Fixable.Surface+5 {
		t.Errorf("fixable = %+v", sum.Fixable)
	}

	// The legacy finding's check was not assessed in the latest run: its row says unconfirmed.
	p, _ := s.ListExposure(ctx, ExposureQuery{Limit: 50})
	for _, g := range p.Findings {
		if g.Identity != nil && g.Identity.ID == "legacyauth.partial" && !g.Identity.Unconfirmed {
			t.Error("a finding whose check was not assessed in the latest run is not marked unconfirmed")
		}
		if g.Identity != nil && g.Identity.ID == "mfa.not_registered" && g.Identity.Unconfirmed {
			t.Error("an assessed finding is marked unconfirmed")
		}
	}

	// The drawer.
	d, err := s.GetIdentityDetail(ctx, keys["inbox_rule.forward_external/u4/r1"])
	if err != nil {
		t.Fatal(err)
	}
	if d.Finding.SubjectLabel != "dana@example.com · From partner" || d.Finding.Evidence["user"] == nil || len(d.Intervals) != 1 || d.Intervals[0].ClosedAt != nil {
		t.Errorf("detail = %+v", d)
	}
	if _, err := s.GetIdentityDetail(ctx, "identity:000000999999"); err != ErrNoIdentityFinding {
		t.Errorf("a missing finding: %v", err)
	}
	for _, bad := range []string{"surface:000000000001", "identity:1", "identity:abc", "", "identity:-00000000001", "identity:000000000000"} {
		if _, err := s.GetIdentityDetail(ctx, bad); err != ErrBadIdentityKey {
			t.Errorf("%q: %v, want ErrBadIdentityKey", bad, err)
		}
	}
	if _, err := s.GetExposureDetail(ctx, keys["mfa.not_registered/u1"], "", ""); err == nil {
		t.Error("the vulnerability drawer accepted an identity key")
	}

	// The trend: its own series, unknown before the first run.
	tr, err := s.ExposureTrend(ctx, now.Add(-5*24*time.Hour), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.IdentitySince == nil {
		t.Fatal("no identity-since")
	}
	last := tr.Points[len(tr.Points)-1]
	if !last.IdentityKnown || last.Identity != 5 || last.IdentityHigh != 3 {
		t.Errorf("today = %+v, want 5 open (3 critical or high)", last)
	}
	if first := tr.Points[0]; first.IdentityKnown || first.Identity != 0 {
		t.Errorf("first day = %+v, want unknown", first)
	}
}

func TestIdentityDoesNotTouchSurfaceOrVulnerabilityCounts(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	idnSeedMixed(t, s, time.Now().UTC())
	sum, err := s.ExposureSummary(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Surface.Findings != 0 || sum.Fixable.Advisories != 4 || sum.Fixable.KEV.Advisories != 1 {
		t.Errorf("summary = %+v", sum.Fixable)
	}
}
