package gws_test

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/gws"
	"defendsec/internal/gws/google"
	"defendsec/internal/gws/gwstest"
)

func newSource(t *testing.T, s *gwstest.Server, mod func(*google.Config)) *gws.GoogleSource {
	t.Helper()
	cfg := s.Config()
	if mod != nil {
		mod(&cfg)
	}
	c, err := google.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gws.NewGoogleSource(c)
}

func collect(t *testing.T, s *gwstest.Server, opt gws.Options, mod func(*google.Config)) *gws.Report {
	t.Helper()
	return gws.Collect(context.Background(), newSource(t, s, mod), opt)
}

func check(rep *gws.Report, name string) *gws.CheckResult {
	for i := range rep.Checks {
		if rep.Checks[i].Check == name {
			return &rep.Checks[i]
		}
	}
	return nil
}

// keys lists "id severity subject" of a check's findings, sorted.
func keys(c *gws.CheckResult) []string {
	var out []string
	for _, f := range c.Findings {
		out = append(out, f.ID+" "+string(f.Severity)+" "+f.Subject)
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCollectFixtureDomain(t *testing.T) {
	s := gwstest.New(t)
	rep := collect(t, s, gws.Options{}, nil)
	if rep.Status() != "ok" || rep.Fatal != "" {
		t.Fatalf("status %s (%s)", rep.Status(), rep.Reason())
	}
	if len(rep.Checks) != 3 {
		t.Fatalf("checks = %d", len(rep.Checks))
	}
	for _, c := range rep.Checks {
		if !c.Assessed {
			t.Errorf("%s not assessed: %s", c.Check, c.Reason)
		}
	}

	two := check(rep, gws.GroupTwoStep)
	wantTwo := []string{
		"2sv.not_enforced high tenant",
		"2sv.not_enrolled critical " + gwstest.UserSam,
		"2sv.not_enrolled high " + gwstest.UserPat,
		"2sv.not_enrolled medium " + gwstest.UserCasey,
	}
	sort.Strings(wantTwo)
	if got := keys(two); !equal(got, wantTwo) {
		t.Errorf("2-Step Verification findings:\n got %v\nwant %v", got, wantTwo)
	}
	for _, f := range two.Findings {
		if f.ID == gws.FindingNotEnforced && !strings.Contains(f.Title, "4 of 9 active users") {
			t.Errorf("enforcement title = %q", f.Title)
		}
	}
	if two.Observed["guestsSkipped"] != 1 || two.Observed["suspendedOrArchivedSkipped"] != 1 {
		t.Errorf("observed = %+v", two.Observed)
	}

	admins := check(rep, gws.GroupAdmins)
	if len(admins.Findings) != 0 || admins.Observed["superAdmins"] != 2 || admins.Observed["delegatedAdmins"] != 1 {
		t.Errorf("admins = %+v %+v", admins.Findings, admins.Observed)
	}

	mail := check(rep, gws.GroupMailConfig)
	wantMail := []string{
		"gmail.autoforward_external critical " + gwstest.UserDana + "/autoforward",
		"gmail.filter_forward_external critical " + gwstest.UserDana + "/ANe1BmDanaFilter1",
		"gmail.filter_hides_mail critical " + gwstest.UserCasey + "/ANe1BmCaseyFilter1",
		"gmail.filter_hides_mail high " + gwstest.UserFran + "/ANe1BmFranFilter1",
		"gmail.filter_hides_mail high " + gwstest.UserGil + "/ANe1BmGilFilter1",
	}
	sort.Strings(wantMail)
	if got := keys(mail); !equal(got, wantMail) {
		t.Errorf("mail findings:\n got %v\nwant %v", got, wantMail)
	}
	// Most urgent first.
	if mail.Findings[0].Severity != gws.SevCritical || mail.Findings[len(mail.Findings)-1].Severity != gws.SevHigh {
		t.Errorf("order: %s ... %s", mail.Findings[0].Severity, mail.Findings[len(mail.Findings)-1].Severity)
	}
	if len(mail.UnassessedPrefixes) != 0 {
		t.Errorf("unassessed prefixes = %v", mail.UnassessedPrefixes)
	}
	c := rep.Counts
	if c.Users != 11 || c.Registrations != 9 || c.MailboxesEligible != 8 || c.MailboxesRead != 8 || c.NoMailbox != 1 || c.Unreadable != 0 || c.Skipped != 0 || c.Rules != 7 || c.GlobalAdmins != 2 {
		t.Errorf("counts = %+v", c)
	}
	if mail.Observed["guestsSkipped"] != 1 || mail.Observed["suspendedOrArchivedSkipped"] != 1 {
		t.Errorf("mail observed = %+v", mail.Observed)
	}
	dom, _ := mail.Observed["internalDomains"].([]string)
	if strings.Join(dom, ",") != "alias.example.net,example.com" {
		t.Errorf("internal domains = %v (a guest's domain must not count)", dom)
	}
	if rep.Labels["mfa"] != "2-Step Verification" || rep.Label("inbox-rules") != "Gmail forwarding and filters" {
		t.Errorf("labels = %v", rep.Labels)
	}
	if len(rep.NotAssessed) != len(gws.StandingNotAssessed) {
		t.Errorf("not assessed = %d, want the %d standing ones", len(rep.NotAssessed), len(gws.StandingNotAssessed))
	}
	if rep.Requests != 18 {
		t.Errorf("requests = %d, want 18 (2 directory pages + 2 reads for each of 8 mailboxes)", rep.Requests)
	}
}

// The privacy rule: settings and filters only, never a message. The fake records
// every request; nothing but the users list and the two settings resources is asked.
func TestCollectOnlyReadsSettingsAndNeverTouchesAMessage(t *testing.T) {
	s := gwstest.New(t)
	rep := collect(t, s, gws.Options{}, nil)
	if rep.Status() != "ok" {
		t.Fatalf("status = %s", rep.Status())
	}
	allowed := map[string]bool{
		"/admin/directory/v1/users":                  true,
		"/gmail/v1/users/me/settings/autoForwarding": true,
		"/gmail/v1/users/me/settings/filters":        true,
	}
	acted := map[string]bool{}
	for _, r := range s.Requests() {
		if r.Method != "GET" {
			t.Errorf("non-GET request %s %s", r.Method, r.Path)
		}
		if !allowed[r.Path] {
			t.Errorf("request to %s", r.Path)
		}
		if strings.Contains(strings.ToLower(r.Path+r.Query), "message") || strings.Contains(strings.ToLower(r.Path), "thread") || strings.Contains(r.Path, "attachment") {
			t.Errorf("a request names a message: %s?%s", r.Path, r.Query)
		}
		if strings.HasPrefix(r.Path, "/gmail/") {
			if r.Query != "" {
				t.Errorf("Gmail read with a query: %s", r.Query)
			}
			acted[r.Sub] = true
		}
	}
	// Only mailboxes that exist and can be signed in were acted as.
	for _, no := range []string{"former@example.com", "nomail@example.com", "partner@other.example.org"} {
		if acted[no] {
			t.Errorf("acted as %s, who is suspended, has no mailbox or is a guest", no)
		}
	}
	if len(acted) != 8 {
		t.Errorf("acted as %d users, want the 8 eligible: %v", len(acted), acted)
	}
	if calls, subs := s.TokenCalls(); calls != 9 || subs[0] != gwstest.AdminEmail {
		t.Errorf("token calls = %d %v", calls, subs)
	}
	scopes := map[string]bool{}
	for _, r := range s.Requests() {
		scopes[r.Scope] = true
	}
	if len(scopes) != 2 || !scopes[google.ScopeDirectoryUsers] || !scopes[google.ScopeGmailSettingsBasic] || scopes[google.ScopeGmailReadonly] {
		t.Errorf("scopes used = %v", scopes)
	}
}

func TestCollectFailsClosed(t *testing.T) {
	notAssessedAll := func(t *testing.T, rep *gws.Report, wantFatal bool, reasonHas string) {
		t.Helper()
		if rep.Status() != "not_assessed" {
			t.Errorf("status = %s, want not_assessed", rep.Status())
		}
		if (rep.Fatal != "") != wantFatal {
			t.Errorf("fatal = %q, want fatal=%v", rep.Fatal, wantFatal)
		}
		if len(rep.Checks) != 3 {
			t.Fatalf("checks = %d", len(rep.Checks))
		}
		for _, c := range rep.Checks {
			if c.Assessed || len(c.Findings) != 0 || !strings.Contains(c.Reason, reasonHas) {
				t.Errorf("%s: assessed=%v findings=%d reason=%q (want it to contain %q)", c.Check, c.Assessed, len(c.Findings), c.Reason, reasonHas)
			}
		}
		if !strings.Contains(rep.Reason(), reasonHas) {
			t.Errorf("reason = %q", rep.Reason())
		}
		if len(rep.NotAssessed) < len(gws.StandingNotAssessed) {
			t.Errorf("not assessed list = %d", len(rep.NotAssessed))
		}
	}

	t.Run("401 on the user list that a new token does not cure", func(t *testing.T) {
		s := gwstest.New(t)
		s.Fail("/admin/directory/v1/users", 401, -1, nil)
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), true, "refused the access token")
	})
	t.Run("the key is refused", func(t *testing.T) {
		s := gwstest.New(t)
		s.RejectKey = true
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), true, "refused the service account's credentials")
	})
	t.Run("the administrator is not a user", func(t *testing.T) {
		s := gwstest.New(t)
		s.RejectSubjects[gwstest.AdminEmail] = true
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), true, "refused the service account's credentials")
	})
	t.Run("403 on the user list", func(t *testing.T) {
		s := gwstest.New(t)
		s.FailBody("/admin/directory/v1/users", 403, -1, nil, `{"error":{"code":403,"message":"Not Authorized to access this resource/api","errors":[{"reason":"forbidden"}]}}`)
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), false, "the user list could not be read: Google refused the read (403)")
	})
	t.Run("the Admin SDK API is not enabled", func(t *testing.T) {
		s := gwstest.New(t)
		s.FailBody("/admin/directory/v1/users", 403, -1, nil, `{"error":{"code":403,"message":"Admin SDK API has not been used","errors":[{"reason":"accessNotConfigured"}]}}`)
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), false, "not enabled in the service account's Google Cloud project")
	})
	t.Run("429 on the user list that does not stop", func(t *testing.T) {
		s := gwstest.New(t)
		s.Fail("/admin/directory/v1/users", 429, -1, nil)
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), false, "throttled")
	})
	t.Run("no delegation for the directory scope", func(t *testing.T) {
		s := gwstest.New(t)
		s.DelegatedScopes[google.ScopeGmailSettingsBasic] = true
		notAssessedAll(t, collect(t, s, gws.Options{}, nil), false, "domain-wide delegation")
	})
	t.Run("the read is cancelled", func(t *testing.T) {
		s := gwstest.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rep := gws.Collect(ctx, newSource(t, s, nil), gws.Options{})
		if rep.Status() != "not_assessed" || rep.Fatal == "" {
			t.Errorf("status %s fatal %q", rep.Status(), rep.Fatal)
		}
	})
}

func TestCollectKeepsWhatItCouldReadWhenGmailIsRefused(t *testing.T) {
	// The Gmail scope is not delegated: 2-Step Verification and super administrators
	// are still read and judged; the mail check says why it could not run, and is
	// the only one that did not.
	s := gwstest.New(t)
	s.DelegatedScopes[google.ScopeDirectoryUsers] = true
	rep := collect(t, s, gws.Options{}, nil)
	if rep.Status() != "partial" {
		t.Fatalf("status = %s (%s)", rep.Status(), rep.Reason())
	}
	if !check(rep, gws.GroupTwoStep).Assessed || !check(rep, gws.GroupAdmins).Assessed {
		t.Error("the directory checks must still be assessed")
	}
	mail := check(rep, gws.GroupMailConfig)
	if mail.Assessed || len(mail.Findings) != 0 || !strings.Contains(mail.Reason, "domain-wide delegation") {
		t.Errorf("mail = %+v", mail)
	}
	if calls, _ := s.TokenCalls(); calls > 1+4+1 {
		t.Errorf("%d token requests: a delegation that is missing must stop the mailbox reads, not be asked for each user", calls)
	}
	if !strings.Contains(rep.Reason(), "Gmail forwarding and filters") {
		t.Errorf("reason = %q", rep.Reason())
	}
	var found bool
	for _, n := range rep.NotAssessed {
		if strings.Contains(n.What, "Gmail forwarding and filters (this read)") {
			found = true
		}
	}
	if !found {
		t.Error("the failed check is missing from the not-assessed list")
	}
}

func TestCollectMailboxFailures(t *testing.T) {
	t.Run("one mailbox cannot be acted as: its findings are neither confirmed nor cleared", func(t *testing.T) {
		s := gwstest.New(t)
		s.RejectSubjects["casey@example.com"] = true
		rep := collect(t, s, gws.Options{}, nil)
		mail := check(rep, gws.GroupMailConfig)
		if !mail.Assessed || rep.Status() != "partial" {
			t.Fatalf("assessed %v status %s", mail.Assessed, rep.Status())
		}
		if len(mail.UnassessedPrefixes) != 1 || mail.UnassessedPrefixes[0] != gwstest.UserCasey+"/" {
			t.Errorf("unassessed prefixes = %v", mail.UnassessedPrefixes)
		}
		for _, f := range mail.Findings {
			if strings.HasPrefix(f.Subject, gwstest.UserCasey) {
				t.Errorf("a finding on the unreadable mailbox: %+v", f)
			}
		}
		if len(mail.Findings) != 4 || rep.Counts.Unreadable != 1 || rep.Counts.MailboxesRead != 7 {
			t.Errorf("findings %d, counts %+v", len(mail.Findings), rep.Counts)
		}
		if !strings.Contains(rep.Reason(), "1 mailbox could not be read") {
			t.Errorf("reason = %q", rep.Reason())
		}
	})
	t.Run("Gmail not enabled for a user is no mailbox, not a failure", func(t *testing.T) {
		s := gwstest.New(t)
		s.FailBody("/gmail/v1/users/me/settings/filters", 400, 1, nil,
			`{"error":{"code":400,"message":"Mail service not enabled","errors":[{"reason":"failedPrecondition"}],"status":"FAILED_PRECONDITION"}}`)
		rep := collect(t, s, gws.Options{}, nil)
		if rep.Status() != "ok" || rep.Counts.NoMailbox != 2 || rep.Counts.Unreadable != 0 || rep.Counts.MailboxesRead != 7 {
			t.Errorf("status %s counts %+v", rep.Status(), rep.Counts)
		}
	})
	t.Run("every mailbox is throttled: the check is not assessed", func(t *testing.T) {
		s := gwstest.New(t)
		s.Fail("/gmail/v1/users/me/settings/autoForwarding", 429, -1, nil)
		rep := collect(t, s, gws.Options{}, nil)
		mail := check(rep, gws.GroupMailConfig)
		if mail.Assessed || len(mail.Findings) != 0 || !strings.Contains(mail.Reason, "throttled") {
			t.Errorf("mail = %+v", mail)
		}
		if rep.Status() != "partial" || !check(rep, gws.GroupTwoStep).Assessed {
			t.Errorf("status %s", rep.Status())
		}
	})
	t.Run("a forbidden mailbox read for everyone says what to check", func(t *testing.T) {
		s := gwstest.New(t)
		s.Fail("/gmail/v1/users/me/settings/filters", 403, -1, nil)
		rep := collect(t, s, gws.Options{}, nil)
		mail := check(rep, gws.GroupMailConfig)
		if mail.Assessed || !strings.Contains(mail.Reason, "refused every mailbox read (403)") {
			t.Errorf("mail = %+v", mail)
		}
	})
	t.Run("the Gmail API is not enabled in the project", func(t *testing.T) {
		s := gwstest.New(t)
		s.FailBody("/gmail/v1/users/me/settings/autoForwarding", 403, -1, nil, `{"error":{"code":403,"message":"Gmail API has not been used in project 1 before or it is disabled.","errors":[{"reason":"accessNotConfigured"}]}}`)
		rep := collect(t, s, gws.Options{}, nil)
		mail := check(rep, gws.GroupMailConfig)
		if mail.Assessed || !strings.Contains(mail.Reason, "not enabled in the service account's Google Cloud project") {
			t.Errorf("mail = %+v", mail)
		}
	})
}

func TestMailboxCapIsCountedAndProtectsFindings(t *testing.T) {
	s := gwstest.New(t)
	// Eligible mailboxes sort by address: alex, casey, dana, erin, fran, gil, pat, sam.
	rep := collect(t, s, gws.Options{MaxMailboxes: 3}, nil)
	mail := check(rep, gws.GroupMailConfig)
	if rep.Status() != "partial" || rep.Counts.Skipped != 5 || rep.Counts.MailboxesRead != 3 || rep.Counts.MailboxesEligible != 8 {
		t.Fatalf("status %s counts %+v", rep.Status(), rep.Counts)
	}
	want := []string{gwstest.UserErin, gwstest.UserFran, gwstest.UserGil, gwstest.UserPat, gwstest.UserSam}
	var got []string
	for _, p := range mail.UnassessedPrefixes {
		got = append(got, strings.TrimSuffix(p, "/"))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !equal(got, want) {
		t.Errorf("unassessed prefixes = %v, want %v", got, want)
	}
	if len(mail.Findings) != 3 { // casey's, dana's two
		t.Errorf("findings = %v", keys(mail))
	}
	if !strings.Contains(rep.Reason(), "5 mailboxes were skipped") {
		t.Errorf("reason = %q", rep.Reason())
	}
}

func TestMailboxesTheLoopNeverReachedAreNotCleared(t *testing.T) {
	// The read runs out of time after the user list: the mailboxes not yet started are
	// neither read nor allowed to resolve what is open on them.
	s := gwstest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	src := &cancelAfterUsers{GoogleSource: newSource(t, s, nil), cancel: cancel}
	rep := gws.Collect(ctx, src, gws.Options{Concurrency: 1})
	mail := check(rep, gws.GroupMailConfig)
	if mail == nil {
		t.Fatal("no mail check")
	}
	if mail.Assessed {
		for _, id := range []string{gwstest.UserCasey, gwstest.UserDana, gwstest.UserSam} {
			if !contains(mail.UnassessedPrefixes, id+"/") {
				t.Errorf("%s was not read but is not protected: %v", id, mail.UnassessedPrefixes)
			}
		}
	}
	if rep.Status() == "ok" {
		t.Error("a read that was cut short is reported ok")
	}
}

func TestMailboxesTheLoopLeftOutAfterOneReadAreProtected(t *testing.T) {
	// The read is cut short after the first mailbox: that mailbox was read, the rest were
	// never started. The check is still assessed (it did read one), and the rest must be
	// in the unassessed prefixes so a finding open on them is not resolved as fixed.
	s := gwstest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	src := &cancelAfterFirstMailbox{GoogleSource: newSource(t, s, nil), cancel: cancel}
	rep := gws.Collect(ctx, src, gws.Options{Concurrency: 1})
	mail := check(rep, gws.GroupMailConfig)
	if mail == nil || !mail.Assessed {
		t.Fatalf("mail check = %+v, want assessed (one mailbox was read)", mail)
	}
	eligible := rep.Counts.MailboxesEligible
	if eligible < 3 {
		t.Fatalf("fixture has %d eligible mailboxes, the test needs at least 3", eligible)
	}
	if rep.Counts.MailboxesRead != 1 || rep.Counts.Skipped != eligible-1 {
		t.Errorf("read %d, skipped %d of %d eligible, want 1 and %d", rep.Counts.MailboxesRead, rep.Counts.Skipped, eligible, eligible-1)
	}
	if len(mail.UnassessedPrefixes) != eligible-1 {
		t.Errorf("%d prefixes protect the unread mailboxes, want %d: %v", len(mail.UnassessedPrefixes), eligible-1, mail.UnassessedPrefixes)
	}
}

type cancelAfterFirstMailbox struct {
	*gws.GoogleSource
	cancel func()
}

func (c *cancelAfterFirstMailbox) Filters(ctx context.Context, email string) ([]gws.Filter, error) {
	f, err := c.GoogleSource.Filters(ctx, email)
	c.cancel()
	return f, err
}

type cancelAfterUsers struct {
	*gws.GoogleSource
	cancel func()
}

func (c *cancelAfterUsers) Users(ctx context.Context) ([]gws.User, error) {
	u, err := c.GoogleSource.Users(ctx)
	c.cancel()
	return u, err
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestOptions(t *testing.T) {
	t.Run("super administrator limit", func(t *testing.T) {
		rep := collect(t, gwstest.New(t), gws.Options{SuperAdminMax: 1}, nil)
		admins := check(rep, gws.GroupAdmins)
		if len(admins.Findings) != 1 || admins.Findings[0].ID != gws.FindingSuperAdminCount {
			t.Errorf("findings = %v", keys(admins))
		}
	})
	t.Run("trusted domain", func(t *testing.T) {
		rep := collect(t, gwstest.New(t), gws.Options{TrustedDomains: []string{"mail.example.org"}}, nil)
		mail := check(rep, gws.GroupMailConfig)
		// Dana's forwarding is now to a trusted domain: the auto-forward finding goes,
		// and her filter is judged as a hiding one (it trashes a sender's mail, no finance word: medium).
		want := []string{
			"gmail.filter_hides_mail critical " + gwstest.UserCasey + "/ANe1BmCaseyFilter1",
			"gmail.filter_hides_mail high " + gwstest.UserFran + "/ANe1BmFranFilter1",
			"gmail.filter_hides_mail high " + gwstest.UserGil + "/ANe1BmGilFilter1",
			"gmail.filter_hides_mail medium " + gwstest.UserDana + "/ANe1BmDanaFilter1",
		}
		sort.Strings(want)
		if got := keys(mail); !equal(got, want) {
			t.Errorf("got %v\nwant %v", got, want)
		}
	})
	t.Run("extra finance terms", func(t *testing.T) {
		rep := collect(t, gwstest.New(t), gws.Options{ExtraFinanceTerms: []string{"security alert"}}, nil)
		mail := check(rep, gws.GroupMailConfig)
		var gil *gws.Finding
		for i := range mail.Findings {
			if strings.HasPrefix(mail.Findings[i].Subject, gwstest.UserGil) {
				gil = &mail.Findings[i]
			}
		}
		if gil == nil || gil.Severity != gws.SevCritical {
			t.Errorf("gil = %+v", gil)
		}
	})
	t.Run("the alternative Gmail scope", func(t *testing.T) {
		s := gwstest.New(t)
		s.DelegatedScopes[google.ScopeDirectoryUsers] = true
		s.DelegatedScopes[google.ScopeGmailSettingsBasic] = true
		rep := collect(t, s, gws.Options{}, func(c *google.Config) { c.GmailScope = google.ScopeGmailSettingsBasic })
		if rep.Status() != "ok" {
			t.Errorf("status %s (%s)", rep.Status(), rep.Reason())
		}
	})
}

func TestRunsAreReproducible(t *testing.T) {
	// Two reads of the same domain give the same findings in the same order, so a
	// stored finding's identity is stable from run to run.
	a := collect(t, gwstest.New(t), gws.Options{}, nil)
	b := collect(t, gwstest.New(t), gws.Options{Now: func() time.Time { return time.Unix(0, 0) }}, nil)
	for _, name := range []string{gws.GroupTwoStep, gws.GroupAdmins, gws.GroupMailConfig} {
		var ka, kb []string
		for _, f := range check(a, name).Findings {
			ka = append(ka, f.ID+" "+f.Subject+" "+f.SubjectLabel)
		}
		for _, f := range check(b, name).Findings {
			kb = append(kb, f.ID+" "+f.Subject+" "+f.SubjectLabel)
		}
		if !equal(ka, kb) {
			t.Errorf("%s differs between reads:\n%v\n%v", name, ka, kb)
		}
	}
}
