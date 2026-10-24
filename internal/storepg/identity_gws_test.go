package storepg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"defendsec/internal/gws"
	"defendsec/internal/m365"
)

// Slice 13: Google Workspace settings, and Google runs and findings beside Microsoft
// 365's in the shared identity tables.

func gwsReport(at time.Time, checks ...gws.CheckResult) *gws.Report {
	return &gws.Report{
		StartedAt: at, FinishedAt: at.Add(time.Second), Checks: checks, Requests: 5, Labels: gws.CheckLabels,
		NotAssessed: []gws.NotAssessed{{What: "The domain's email routing", Why: "Admin console only"}},
		Counts:      gws.Counts{Users: 4},
	}
}

func gwsFinding(id, subject, label string, sev gws.Severity) gws.Finding {
	return gws.Finding{ID: id, Subject: subject, SubjectLabel: label, Severity: sev, Title: "title of " + id, Detail: "detail", Fix: "fix", Evidence: map[string]any{"u": label}}
}

func gwsOpen(t *testing.T, s *Store, provider string) map[string]IdentityFinding {
	t.Helper()
	list, err := s.ListIdentityFindings(context.Background(), IdentityFindingFilter{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]IdentityFinding{}
	for _, f := range list {
		k := f.FindingID + "/" + f.Subject
		if provider == "" {
			k = f.Provider + ":" + k // two providers may share an id and a subject
		}
		out[k] = f
	}
	return out
}

func TestGWSSettings(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	d, err := s.GetGWSSettings(ctx)
	if err != nil || d.Configured || d.GmailScope != GWSScopeReadonly || d.SuperAdminMax != gws.DefaultSuperAdminMax || d.UpdatedAt != nil {
		t.Fatalf("defaults = %+v, %v", d, err)
	}
	if d.GmailScopeURL() != "https://www.googleapis.com/auth/gmail.readonly" {
		t.Errorf("scope url = %q", d.GmailScopeURL())
	}

	in := GWSSettings{AdminEmail: "  Alex@Example.COM ", GmailScope: GWSScopeSettingsBasic, SuperAdminMax: 3,
		TrustedDomains: []string{"Partner.Example.org", "partner.example.org", " "}, FinanceTerms: []string{"Tax Refund"}}
	if err := s.SetGWSSettings(ctx, "admin:test", in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGWSSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Configured || got.AdminEmail != "alex@example.com" || got.GmailScope != "settings.basic" || got.SuperAdminMax != 3 ||
		len(got.TrustedDomains) != 1 || got.TrustedDomains[0] != "partner.example.org" || got.FinanceTerms[0] != "tax refund" ||
		got.UpdatedBy != "admin:test" || got.UpdatedAt == nil {
		t.Errorf("saved = %+v", got)
	}
	if got.GmailScopeURL() != "https://www.googleapis.com/auth/gmail.settings.basic" {
		t.Errorf("scope url = %q", got.GmailScopeURL())
	}
	if n := idnAuditCount(t, s, "identity_settings_changed"); n != 1 {
		t.Errorf("ledger entries = %d, want 1", n)
	}

	for name, bad := range map[string]GWSSettings{
		"not an address":     {AdminEmail: "alex", GmailScope: "readonly", SuperAdminMax: 4},
		"unknown scope":      {AdminEmail: "a@example.com", GmailScope: "modify", SuperAdminMax: 4},
		"limit too low":      {AdminEmail: "a@example.com", SuperAdminMax: 0},
		"limit too high":     {AdminEmail: "a@example.com", SuperAdminMax: 51},
		"bad trusted":        {AdminEmail: "a@example.com", SuperAdminMax: 4, TrustedDomains: []string{"no spaces.com"}},
		"short finance word": {AdminEmail: "a@example.com", SuperAdminMax: 4, FinanceTerms: []string{"ab"}},
	} {
		if err := s.SetGWSSettings(ctx, "admin:test", bad); !errors.Is(err, ErrBadIdentitySettings) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if n := idnAuditCount(t, s, "identity_settings_changed"); n != 1 {
		t.Errorf("a refused save wrote to the ledger: %d entries", n)
	}
	// Clearing the administrator disconnects the domain.
	if err := s.SetGWSSettings(ctx, "admin:test", GWSSettings{SuperAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetGWSSettings(ctx); got.Configured || got.GmailScope != GWSScopeReadonly {
		t.Errorf("cleared = %+v", got)
	}
}

func TestIdentityProvidersKeepTheirOwnFindings(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-48 * time.Hour).Round(time.Microsecond)

	// The same finding id and subject in both providers must not be one finding.
	m := idnFinding("mfa.not_registered", "u-1", "sam@example.com", m365.SevCritical)
	g := gwsFinding("mfa.not_registered", "u-1", "sam@example.com", gws.SevCritical)
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(t0, idnCheck(m365.GroupMFA, true, "", m))); err != nil {
		t.Fatal(err)
	}
	gr, err := s.RecordIdentityRun(ctx, "google", "example.com", "schedule", gwsReport(t0,
		gws.CheckResult{Check: gws.GroupTwoStep, Assessed: true, Findings: []gws.Finding{g}},
		gws.CheckResult{Check: gws.GroupMailConfig, Assessed: true}))
	if err != nil {
		t.Fatal(err)
	}
	if gr.Provider != "google" || gr.Tenant != "example.com" || gr.Open != 1 || gr.Opened != 1 || gr.Status != "ok" {
		t.Fatalf("google run = %+v", gr)
	}
	// The run stores the provider's own labels for the groups.
	labels := map[string]string{}
	for _, c := range gr.Checks {
		labels[c.Check] = c.Label
	}
	if labels["mfa"] != "2-Step Verification" || labels["inbox-rules"] != "Gmail forwarding and filters" {
		t.Errorf("labels = %v", labels)
	}
	if len(gwsOpen(t, s, "m365")) != 1 || len(gwsOpen(t, s, "google")) != 1 || len(gwsOpen(t, s, "")) != 2 {
		t.Fatalf("findings: m365 %d google %d all %d", len(gwsOpen(t, s, "m365")), len(gwsOpen(t, s, "google")), len(gwsOpen(t, s, "")))
	}

	// A Microsoft run that finds nothing resolves Microsoft's finding and not Google's.
	r2, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(t0.Add(time.Hour), idnCheck(m365.GroupMFA, true, "")))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Resolved != 1 || r2.Open != 0 {
		t.Errorf("m365 run 2 = %+v", r2)
	}
	if len(gwsOpen(t, s, "google")) != 1 {
		t.Error("a Microsoft read closed a Google finding")
	}

	// A Google run whose 2-Step check could not run resolves nothing, and the finding
	// is shown unconfirmed; the mail check that ran with an unreadable mailbox keeps
	// that mailbox's findings.
	mailF := gwsFinding("gmail.filter_hides_mail", "u-9/f1", "x@example.com · filter", gws.SevHigh)
	if _, err := s.RecordIdentityRun(ctx, "google", "example.com", "schedule", gwsReport(t0.Add(2*time.Hour),
		gws.CheckResult{Check: gws.GroupTwoStep, Assessed: true, Findings: []gws.Finding{g}},
		gws.CheckResult{Check: gws.GroupMailConfig, Assessed: true, Findings: []gws.Finding{mailF}})); err != nil {
		t.Fatal(err)
	}
	r4, err := s.RecordIdentityRun(ctx, "google", "example.com", "schedule", gwsReport(t0.Add(3*time.Hour),
		gws.CheckResult{Check: gws.GroupTwoStep, Assessed: false, Reason: "the user list could not be read"},
		gws.CheckResult{Check: gws.GroupMailConfig, Assessed: true, UnassessedPrefixes: []string{"u-9/"}}))
	if err != nil {
		t.Fatal(err)
	}
	if r4.Status != "partial" || r4.Resolved != 0 || r4.Open != 2 {
		t.Fatalf("run 4 = %+v", r4)
	}
	open := gwsOpen(t, s, "google")
	if f := open["mfa.not_registered/u-1"]; !f.Unconfirmed || f.Provider != "google" {
		t.Errorf("2sv finding = %+v", f)
	}
	if f := open["gmail.filter_hides_mail/u-9/f1"]; !f.Unconfirmed {
		t.Errorf("finding on an unreadable mailbox = %+v", f)
	}
	if !strings.Contains(r4.Reason, "2-Step Verification: the user list could not be read") {
		t.Errorf("reason = %q (the check is named in the provider's words)", r4.Reason)
	}
}

func TestIdentitySummaryCoversBothProviders(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Hour).Round(time.Microsecond)

	sum, err := s.IdentityExposureSummary(ctx)
	if err != nil || sum.Configured || sum.Provider != "m365" || len(sum.Providers) != 0 || sum.LastStatus != "" || sum.Findings != 0 {
		t.Fatalf("empty summary = %+v, %v", sum, err)
	}

	if err := s.SetGWSSettings(ctx, "t", GWSSettings{AdminEmail: "alex@example.com", SuperAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	if sum, _ = s.IdentityExposureSummary(ctx); !sum.Configured || sum.Provider != "google" || len(sum.Providers) != 1 {
		t.Errorf("google only = %+v", sum)
	}
	if err := s.SetM365Settings(ctx, "t", M365Settings{TenantID: "aaaaaaaa-1111-4222-8333-444444444444", ClientID: "bbbbbbbb-1111-4222-8333-555555555555", GlobalAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	if sum, _ = s.IdentityExposureSummary(ctx); sum.Provider != "m365,google" || len(sum.Providers) != 2 {
		t.Errorf("both = %+v", sum)
	}

	// Microsoft read fine with one finding; Google could not assess one of its three groups.
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(now,
		idnCheck(m365.GroupMFA, true, "", idnFinding("mfa.not_registered", "u1", "a@example.com", m365.SevMedium)),
		idnCheck(m365.GroupLegacyAuth, true, ""))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordIdentityRun(ctx, "google", "example.com", "schedule", gwsReport(now.Add(30*time.Minute),
		gws.CheckResult{Check: gws.GroupTwoStep, Assessed: true, Findings: []gws.Finding{
			gwsFinding("2sv.not_enrolled", "u2", "b@example.com", gws.SevCritical), gwsFinding("2sv.not_enrolled", "u3", "c@example.com", gws.SevMedium)}},
		gws.CheckResult{Check: gws.GroupAdmins, Assessed: true},
		gws.CheckResult{Check: gws.GroupMailConfig, Assessed: false, Reason: "delegation missing"})); err != nil {
		t.Fatal(err)
	}
	sum, err = s.IdentityExposureSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Findings != 3 || sum.BySeverity["critical"] != 1 || sum.BySeverity["medium"] != 2 {
		t.Errorf("findings = %d %v", sum.Findings, sum.BySeverity)
	}
	if sum.LastStatus != "partial" || sum.ChecksTotal != 5 || sum.ChecksNotAssessed != 1 {
		t.Errorf("status %q checks %d/%d", sum.LastStatus, sum.ChecksNotAssessed, sum.ChecksTotal)
	}
	if sum.LastRunAt == nil || !sum.LastRunAt.Equal(now.Add(30*time.Minute+time.Second)) {
		t.Errorf("last run at %v", sum.LastRunAt)
	}
	if !strings.Contains(sum.LastReason, "Google Workspace: Gmail forwarding and filters: delegation missing") {
		t.Errorf("reason = %q", sum.LastReason)
	}

	// Each provider's own summary counts only its own.
	m, _ := s.IdentityProviderSummary(ctx, "m365")
	g, _ := s.IdentityProviderSummary(ctx, "google")
	if m.Findings != 1 || m.LastStatus != "ok" || m.ChecksTotal != 2 || m.Provider != "m365" || g.Findings != 2 || g.LastStatus != "partial" || g.ChecksTotal != 3 || g.Provider != "google" {
		t.Errorf("m365 %+v\n google %+v", m, g)
	}
	if m.LastReason != "" || !strings.HasPrefix(g.LastReason, "Gmail forwarding") {
		t.Errorf("reasons: %q / %q", m.LastReason, g.LastReason)
	}

	// A bad read of either provider makes the combined status the worst.
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(now.Add(time.Hour),
		idnCheck(m365.GroupMFA, false, "refused"))); err != nil {
		t.Fatal(err)
	}
	if sum, _ = s.IdentityExposureSummary(ctx); sum.LastStatus != "not_assessed" {
		t.Errorf("combined status = %q, want not_assessed", sum.LastStatus)
	}
}

func TestGoogleFindingsRankWithTheRest(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Hour)
	if _, err := s.RecordIdentityRun(ctx, "google", "example.com", "schedule", gwsReport(now,
		gws.CheckResult{Check: gws.GroupTwoStep, Assessed: true, Findings: []gws.Finding{
			gwsFinding("2sv.not_enrolled", "u2", "b@example.com", gws.SevCritical), gwsFinding("2sv.not_enforced", "tenant", "Google Workspace domain", gws.SevLow)}})); err != nil {
		t.Fatal(err)
	}
	p, err := s.ListExposure(ctx, ExposureQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 2 || p.Findings[0].Identity == nil || p.Findings[0].Identity.Provider != "google" || p.Findings[0].Identity.Check != "mfa" || p.Findings[0].Summary != "title of 2sv.not_enrolled" {
		t.Fatalf("exposure = %+v", p)
	}
	d, err := s.GetIdentityDetail(ctx, p.Findings[0].AdvisoryID)
	if err != nil || d.Finding.Provider != "google" || d.CheckState == nil || d.CheckState.Label != "2-Step Verification" {
		t.Errorf("detail = %+v, %v", d, err)
	}
}
