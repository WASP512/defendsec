package m365_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/m365"
	"defendsec/internal/m365/graph"
	"defendsec/internal/m365/m365test"
)

func collect(t *testing.T, srv *m365test.Server, opt m365.Options) *m365.Report {
	t.Helper()
	cfg := srv.Config()
	cfg.Sleep = func(context.Context, time.Duration) error { return nil }
	c, err := graph.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m365.Collect(context.Background(), m365.NewGraphSource(c), opt)
}

func check(t *testing.T, r *m365.Report, group string) m365.CheckResult {
	t.Helper()
	for _, c := range r.Checks {
		if c.Check == group {
			return c
		}
	}
	t.Fatalf("no check %q in the report", group)
	return m365.CheckResult{}
}

func summary(c m365.CheckResult) []string {
	var out []string
	for _, f := range c.Findings {
		out = append(out, f.ID+"|"+f.SubjectLabel+"|"+string(f.Severity))
	}
	sort.Strings(out)
	return out
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s:\n got  %v\n want %v", what, got, want)
	}
}

// One full read of the fixture tenant, with every check assessed.
func TestCollectFixtureTenant(t *testing.T) {
	srv := m365test.New(t)
	r := collect(t, srv, m365.Options{ResolveFolders: true})
	if r.Status() != "ok" || r.Fatal != "" {
		t.Fatalf("status = %s (%s), fatal %q", r.Status(), r.Reason(), r.Fatal)
	}
	for _, c := range r.Checks {
		if !c.Assessed {
			t.Errorf("%s not assessed: %s", c.Check, c.Reason)
		}
	}

	eq(t, "mfa", summary(check(t, r, m365.GroupMFA)), []string{
		"mfa.not_registered|casey@example.com|medium",
		"mfa.not_registered|pat.helpdesk@example.com|high",
		"mfa.not_registered|sam.admin@example.com|critical",
	})
	eq(t, "legacy", summary(check(t, r, m365.GroupLegacyAuth)), []string{"legacyauth.not_blocked|Microsoft 365 tenant|medium"})
	eq(t, "roles", summary(check(t, r, m365.GroupAdminRoles)), nil) // two Global Admins, limit 4
	eq(t, "inbox rules", summary(check(t, r, m365.GroupInboxRules)), []string{
		"inbox_rule.forward_external|dana@example.com · From partner|critical",
		"inbox_rule.hides_mail|casey@example.com · Intuit stuff|critical",
	})

	// The AMP-like rule, with the folder named.
	var amp m365.Finding
	for _, f := range check(t, r, m365.GroupInboxRules).Findings {
		if f.ID == m365.FindingRuleHides {
			amp = f
		}
	}
	ev, _ := json.Marshal(amp.Evidence)
	for _, want := range []string{"RSS Feeds", "quickbooks", "intuit.com", "Intuit stuff", "financeMatches"} {
		if !strings.Contains(string(ev), want) {
			t.Errorf("AMP rule evidence lacks %q: %s", want, ev)
		}
	}

	// Counts: 9 users, 8 report rows; mailboxes: casey dana erin alex sam pat + the one with none = 7 eligible.
	if r.Counts.Users != 9 || r.Counts.MailboxesEligible != 7 || r.Counts.MailboxesRead != 6 || r.Counts.NoMailbox != 1 || r.Counts.Rules != 5 || r.Counts.GlobalAdmins != 2 {
		t.Errorf("counts = %+v", r.Counts)
	}
	obs := check(t, r, m365.GroupInboxRules).Observed
	if obs["guestsSkipped"] != 1 || obs["disabledAccountsSkipped"] != 1 {
		t.Errorf("inbox observed = %v", obs)
	}
	if mfa := check(t, r, m365.GroupMFA).Observed; mfa["guestsSkipped"] != 1 {
		t.Errorf("mfa observed = %v", mfa)
	}

	// What Graph cannot see is said, every time.
	var what []string
	for _, n := range r.NotAssessed {
		what = append(what, n.What)
	}
	joined := strings.Join(what, "\n")
	for _, want := range []string{"ForwardingSmtpAddress", "Privileged Identity Management", "Whether MFA is enforced", "SMTP AUTH", "client"} {
		if !strings.Contains(joined, want) {
			t.Errorf("not-assessed list lacks %q:\n%s", want, joined)
		}
	}
	for _, f := range allFindings(r) {
		if f.Fix == "" || f.Detail == "" || len(f.Controls) == 0 {
			t.Errorf("finding %s %s lacks detail, fix or controls", f.ID, f.SubjectLabel)
		}
	}
}

func allFindings(r *m365.Report) []m365.Finding {
	var out []m365.Finding
	for _, c := range r.Checks {
		out = append(out, c.Findings...)
	}
	return out
}

// Read-only, and never a message: the paths a read touches are a fixed set.
func TestCollectOnlyReadsDefinitionsAndMetadata(t *testing.T) {
	srv := m365test.New(t)
	r := collect(t, srv, m365.Options{ResolveFolders: true})
	allowed := []string{
		"/users", "/reports/authenticationMethods/userRegistrationDetails", "/roleManagement/directory/roleDefinitions",
		"/roleManagement/directory/roleAssignments", "/policies/identitySecurityDefaultsEnforcementPolicy",
		"/identity/conditionalAccess/policies",
	}
	for _, q := range srv.Requests() {
		if q.Method != http.MethodGet {
			t.Errorf("%s %s: not a GET", q.Method, q.Path)
		}
		ok := false
		for _, a := range allowed {
			ok = ok || q.Path == a
		}
		ok = ok || (strings.HasPrefix(q.Path, "/users/") && strings.HasSuffix(q.Path, "/mailFolders/inbox/messageRules"))
		ok = ok || (strings.HasPrefix(q.Path, "/users/") && strings.Contains(q.Path, "/mailFolders/") && !strings.Contains(q.Path, "/messages"))
		if !ok {
			t.Errorf("unexpected Graph path %s", q.Path)
		}
		if strings.Contains(q.Path, "/messages") || strings.Contains(q.Path, "/$value") || strings.Contains(q.Path, "/attachments") {
			t.Errorf("a message endpoint was touched: %s", q.Path)
		}
		// The only $select on a mail folder is its name.
		if strings.Contains(q.Path, "/mailFolders/") && !strings.HasSuffix(q.Path, "/messageRules") && !strings.Contains(q.Query, "displayName") {
			t.Errorf("folder read without the name-only select: %s?%s", q.Path, q.Query)
		}
	}
	if r.Requests != len(srv.Requests()) {
		t.Errorf("report says %d requests, server saw %d", r.Requests, len(srv.Requests()))
	}
	// Folder lookups happened only because ResolveFolders was on, and once per folder.
	if n := srv.Count("/users/" + m365test.UserCasey + "/mailFolders/AAMk"); n != 2 {
		t.Errorf("casey folder lookups = %d, want 2 (one per distinct folder)", n)
	}
	off := m365test.New(t)
	collect(t, off, m365.Options{})
	for _, q := range off.Requests() {
		if strings.Contains(q.Path, "/mailFolders/") && !strings.HasSuffix(q.Path, "/messageRules") {
			t.Errorf("folder name read although folder names are off: %s", q.Path)
		}
	}
}

// Without the optional permission, an unnamed destination is said, and the AMP
// rule is still caught because it also marks the mail as read.
func TestCollectWithoutFolderNames(t *testing.T) {
	srv := m365test.New(t)
	r := collect(t, srv, m365.Options{})
	var casey *m365.Finding
	for _, f := range check(t, r, m365.GroupInboxRules).Findings {
		if strings.HasPrefix(f.SubjectLabel, "casey@") {
			f := f
			casey = &f
		}
	}
	if casey == nil || casey.Severity != m365.SevCritical {
		t.Fatalf("AMP-like rule without folder names: %+v", casey)
	}
	var found bool
	for _, n := range r.NotAssessed {
		if n.What == "Where a move rule sends mail" {
			found = true
			if !strings.Contains(n.Why, "Mail.ReadBasic.All") {
				t.Errorf("why = %s", n.Why)
			}
		}
	}
	if !found {
		t.Error("the unnamed move destinations are not listed as not assessed")
	}
}

func TestCollectFolderPermissionMissingFallsBack(t *testing.T) {
	srv := m365test.New(t)
	srv.FailBody("/users/"+m365test.UserCasey+"/mailFolders/"+m365test.FolderRSS, 403, -1, nil, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`)
	srv.FailBody("/users/"+m365test.UserCasey+"/mailFolders/"+m365test.FolderNews, 403, -1, nil, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`)
	r := collect(t, srv, m365.Options{ResolveFolders: true})
	inbox := check(t, r, m365.GroupInboxRules)
	if !inbox.Assessed {
		t.Fatalf("inbox rules not assessed: %s", inbox.Reason)
	}
	if note, _ := inbox.Observed["folderNamesNote"].(string); !strings.Contains(note, "Mail.ReadBasic.All") {
		t.Errorf("folder note = %q", note)
	}
	if inbox.Observed["folderNamesResolved"] != false {
		t.Errorf("folderNamesResolved = %v", inbox.Observed["folderNamesResolved"])
	}
}

func TestCollectRegistrationReportForbiddenIsNotAssessedNotClean(t *testing.T) {
	srv := m365test.New(t)
	srv.FailBody("/reports/authenticationMethods/userRegistrationDetails", 403, -1, nil,
		`{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn't have premium license"}}`)
	r := collect(t, srv, m365.Options{})
	mfa := check(t, r, m365.GroupMFA)
	if mfa.Assessed || len(mfa.Findings) != 0 {
		t.Fatalf("mfa assessed=%v findings=%v", mfa.Assessed, summary(mfa))
	}
	for _, want := range []string{"AuditLog.Read.All", "P1 or P2", "Authentication_RequestFromNonPremiumTenantOrB2CTenant"} {
		if !strings.Contains(mfa.Reason, want) {
			t.Errorf("reason lacks %q: %s", want, mfa.Reason)
		}
	}
	if r.Status() != "partial" || !check(t, r, m365.GroupInboxRules).Assessed || !check(t, r, m365.GroupAdminRoles).Assessed {
		t.Errorf("the other checks should still run: status %s", r.Status())
	}
	if !strings.Contains(r.Reason(), "MFA registration") {
		t.Errorf("run reason = %q", r.Reason())
	}
}

func TestCollectCredentialsRefusedReadsNothing(t *testing.T) {
	srv := m365test.New(t)
	srv.RejectToken = true
	r := collect(t, srv, m365.Options{})
	if r.Status() != "not_assessed" || r.Fatal == "" || len(allFindings(r)) != 0 {
		t.Fatalf("status %s fatal %q findings %d", r.Status(), r.Fatal, len(allFindings(r)))
	}
	if len(r.Checks) != 4 {
		t.Errorf("%d checks listed, want 4 (each not assessed)", len(r.Checks))
	}
	for _, c := range r.Checks {
		if c.Assessed || c.Reason == "" {
			t.Errorf("%s: assessed=%v reason=%q", c.Check, c.Assessed, c.Reason)
		}
	}
	if !strings.Contains(r.Fatal, "AADSTS7000215") || strings.Contains(r.Fatal, m365test.ClientSecret) {
		t.Errorf("fatal = %q", r.Fatal)
	}
	if len(srv.Requests()) != 0 {
		t.Errorf("%d Graph requests after the credentials were refused", len(srv.Requests()))
	}
}

func TestCollectTokenRefusedByGraphIsFatal(t *testing.T) {
	srv := m365test.New(t)
	srv.Fail("*", 401, -1, nil)
	r := collect(t, srv, m365.Options{})
	if r.Status() != "not_assessed" || r.Fatal == "" {
		t.Fatalf("status %s fatal %q", r.Status(), r.Fatal)
	}
}

func TestCollectEveryMailboxForbidden(t *testing.T) {
	srv := m365test.New(t)
	srv.FailBody("/users/"+m365test.UserCasey+"/mailFolders/inbox/messageRules", 403, -1, nil, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied. Check credentials and try again."}}`)
	for _, id := range []string{m365test.UserAlexAdmin, m365test.UserSamAdmin, m365test.UserPatHelp, m365test.UserDana, m365test.UserErin, m365test.UserNoMailbox} {
		srv.FailBody("/users/"+id+"/mailFolders/inbox/messageRules", 403, -1, nil, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`)
	}
	r := collect(t, srv, m365.Options{})
	inbox := check(t, r, m365.GroupInboxRules)
	if inbox.Assessed || len(inbox.Findings) != 0 || !strings.Contains(inbox.Reason, "MailboxSettings.Read") {
		t.Fatalf("inbox rules: assessed=%v findings=%v reason=%q", inbox.Assessed, summary(inbox), inbox.Reason)
	}
	if !check(t, r, m365.GroupMFA).Assessed {
		t.Error("the MFA check should not depend on mailboxes")
	}
}

// One mailbox unreadable: the rest is assessed, and findings under the one that
// could not be read are neither confirmed nor resolved by this run.
func TestCollectOneMailboxUnreadable(t *testing.T) {
	srv := m365test.New(t)
	srv.FailBody("/users/"+m365test.UserDana+"/mailFolders/inbox/messageRules", 403, -1, nil, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`)
	r := collect(t, srv, m365.Options{})
	inbox := check(t, r, m365.GroupInboxRules)
	if !inbox.Assessed {
		t.Fatalf("not assessed: %s", inbox.Reason)
	}
	eq(t, "findings", summary(inbox), []string{"inbox_rule.hides_mail|casey@example.com · Intuit stuff|critical"})
	if len(inbox.UnassessedPrefixes) != 1 || inbox.UnassessedPrefixes[0] != m365test.UserDana+"/" {
		t.Errorf("unassessed prefixes = %v", inbox.UnassessedPrefixes)
	}
	if r.Status() != "partial" || r.Counts.Unreadable != 1 {
		t.Errorf("status %s, unreadable %d", r.Status(), r.Counts.Unreadable)
	}
	if !strings.Contains(r.Reason(), "1 mailbox could not be read") {
		t.Errorf("reason = %q", r.Reason())
	}
}

func TestCollectThrottledUserListLeavesOtherChecks(t *testing.T) {
	srv := m365test.New(t)
	srv.Fail("/users", 429, -1, map[string]string{"Retry-After": "1"})
	r := collect(t, srv, m365.Options{})
	inbox := check(t, r, m365.GroupInboxRules)
	if inbox.Assessed || !strings.Contains(inbox.Reason, "throttled") {
		t.Fatalf("inbox rules: assessed=%v reason=%q", inbox.Assessed, inbox.Reason)
	}
	// The MFA check still runs from the registration report alone.
	if mfa := check(t, r, m365.GroupMFA); !mfa.Assessed || len(mfa.Findings) != 3 {
		t.Errorf("mfa assessed=%v findings=%v", mfa.Assessed, summary(mfa))
	}
}

func TestCollectThrottledOnceRecovers(t *testing.T) {
	srv := m365test.New(t)
	srv.Fail("/roleManagement/directory/roleAssignments", 429, 2, map[string]string{"Retry-After": "3"})
	r := collect(t, srv, m365.Options{})
	if r.Status() != "ok" {
		t.Errorf("status %s: %s", r.Status(), r.Reason())
	}
}

func TestCollectRoleAssignmentsForbiddenKeepsMFAHonest(t *testing.T) {
	srv := m365test.New(t)
	srv.FailBody("/roleManagement/directory/roleAssignments", 403, -1, nil, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`)
	r := collect(t, srv, m365.Options{})
	roles := check(t, r, m365.GroupAdminRoles)
	if roles.Assessed || !strings.Contains(roles.Reason, "RoleManagement.Read.Directory") {
		t.Fatalf("roles assessed=%v reason=%q", roles.Assessed, roles.Reason)
	}
	// The registration report still says who is an admin, so Sam is high, not critical, and the check says why.
	mfa := check(t, r, m365.GroupMFA)
	got := summary(mfa)
	want := []string{"mfa.not_registered|casey@example.com|medium", "mfa.not_registered|pat.helpdesk@example.com|high", "mfa.not_registered|sam.admin@example.com|high"}
	eq(t, "mfa", got, want)
	if mfa.Observed["globalAdminsIdentified"] != false {
		t.Errorf("observed = %v", mfa.Observed)
	}
}

func TestCollectGlobalAdminLimitIsConfigurable(t *testing.T) {
	srv := m365test.New(t)
	r := collect(t, srv, m365.Options{GlobalAdminMax: 1})
	eq(t, "roles", summary(check(t, r, m365.GroupAdminRoles)), []string{"roles.global_admin_count|Microsoft 365 tenant|medium"})
}

func TestCollectLegacyAuthVariants(t *testing.T) {
	// Security defaults on: blocked.
	on := m365test.New(t)
	on.SecurityDefaultsOn = true
	eq(t, "defaults on", summary(check(t, collect(t, on, m365.Options{}), m365.GroupLegacyAuth)), nil)

	// A policy that blocks legacy sign-in for everyone (with a break-glass exclusion).
	block := m365test.New(t)
	block.BlockLegacy = true
	res := check(t, collect(t, block, m365.Options{}), m365.GroupLegacyAuth)
	eq(t, "CA block", summary(res), nil)
	if res.Observed["policyHasExclusions"] != true {
		t.Errorf("observed = %v", res.Observed)
	}

	// The default fixture has only a report-only policy: not enforcing.
	rep := m365test.New(t)
	res = check(t, collect(t, rep, m365.Options{}), m365.GroupLegacyAuth)
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Detail, "CA002") {
		t.Errorf("report-only: %v", summary(res))
	}

	// Conditional Access needs a licence the tenant lacks, and defaults are off: not assessed.
	lic := m365test.New(t)
	lic.FailBody("/identity/conditionalAccess/policies", 403, -1, nil, `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"premium license needed"}}`)
	res = check(t, collect(t, lic, m365.Options{}), m365.GroupLegacyAuth)
	if res.Assessed || !strings.Contains(res.Reason, "Policy.Read.All") {
		t.Errorf("CA unlicensed: assessed=%v reason=%q", res.Assessed, res.Reason)
	}
}

func TestCollectExtraFinanceTermsAndTrustedDomains(t *testing.T) {
	srv := m365test.New(t)
	// Dana's rule forwards to example.net; trusting that domain removes the forwarding finding, but the rule still deletes finance mail.
	r := collect(t, srv, m365.Options{TrustedDomains: []string{"EXAMPLE.net"}})
	eq(t, "trusted domain", summary(check(t, r, m365.GroupInboxRules)), []string{"inbox_rule.hides_mail|casey@example.com · Intuit stuff|critical", "inbox_rule.hides_mail|dana@example.com · From partner|critical"})
}

func TestCollectMailboxLimitIsCountedAsSkipped(t *testing.T) {
	srv := m365test.New(t)
	r := collect(t, srv, m365.Options{MaxMailboxes: 3})
	if r.Counts.Skipped != 4 || r.Status() != "partial" {
		t.Errorf("skipped %d, status %s", r.Counts.Skipped, r.Status())
	}
	if !strings.Contains(r.Reason(), "skipped") {
		t.Errorf("reason = %q", r.Reason())
	}
	// The mailboxes past the cap (sorted by UPN) are neither confirmed nor cleared:
	// every one is an unassessed prefix, so RecordIdentityRun keeps their findings.
	// Eligible, by UPN: alex.admin, casey, dana, erin, pat.helpdesk, sam.admin,
	// shared.noMailbox; the first three are read.
	inbox := check(t, r, m365.GroupInboxRules)
	want := []string{
		m365test.UserErin + "/", m365test.UserPatHelp + "/", m365test.UserSamAdmin + "/", m365test.UserNoMailbox + "/",
	}
	sort.Strings(want)
	eq(t, "unassessed prefixes", inbox.UnassessedPrefixes, want)
	if len(inbox.UnassessedPrefixes) != r.Counts.Skipped {
		t.Errorf("%d prefixes for %d skipped mailboxes", len(inbox.UnassessedPrefixes), r.Counts.Skipped)
	}
}

// Only the mailboxes past the cap are listed as unassessed; one that was read never is.
func TestCollectMailboxLimitPrefixesAreOnlyTheSkippedOnes(t *testing.T) {
	srv := m365test.New(t)
	r := collect(t, srv, m365.Options{MaxMailboxes: 3})
	for _, pfx := range check(t, r, m365.GroupInboxRules).UnassessedPrefixes {
		for _, read := range []string{m365test.UserAlexAdmin, m365test.UserCasey, m365test.UserDana} {
			if pfx == read+"/" {
				t.Errorf("%s was read but is listed as unassessed", read)
			}
		}
	}
}

// A disabled account is dropped from the MFA check even when the registration
// report lists it as not registered.
func TestCollectDisabledAccountIsNotInTheMFACheck(t *testing.T) {
	srv := m365test.New(t)
	srv.Override["/reports/authenticationMethods/userRegistrationDetails"] = `{"value":[
{"id":"` + m365test.UserCasey + `","userPrincipalName":"casey@example.com","userDisplayName":"Casey Example","isAdmin":false,"isMfaRegistered":false,"methodsRegistered":[],"userType":"member"},
{"id":"11111111-0000-4000-8000-000000000008","userPrincipalName":"former@example.com","userDisplayName":"Former Employee","isAdmin":false,"isMfaRegistered":false,"methodsRegistered":[],"userType":"member"}]}`
	r := collect(t, srv, m365.Options{})
	mfa := check(t, r, m365.GroupMFA)
	if !mfa.Assessed {
		t.Fatalf("mfa not assessed: %s", mfa.Reason)
	}
	eq(t, "mfa", summary(mfa), []string{"mfa.not_registered|casey@example.com|medium"})
}

func TestCollectStopsWhenCancelled(t *testing.T) {
	srv := m365test.New(t)
	cfg := srv.Config()
	c, err := graph.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := m365.Collect(ctx, m365.NewGraphSource(c), m365.Options{})
	if r.Status() != "not_assessed" || len(allFindings(r)) != 0 {
		t.Errorf("a cancelled read: status %s, %d findings", r.Status(), len(allFindings(r)))
	}
}
