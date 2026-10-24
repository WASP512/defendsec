package gws

import (
	"strings"
	"testing"
)

func user(id, email string, mod func(*User)) User {
	u := User{ID: id, Email: email, MailboxSetup: true, Enrolled2SV: true, Enforced2SV: true}
	if mod != nil {
		mod(&u)
	}
	return u
}

func findingFor(res CheckResult, id, subject string) *Finding {
	for i := range res.Findings {
		if res.Findings[i].ID == id && res.Findings[i].Subject == subject {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestTwoStepSeverityByRole(t *testing.T) {
	users := []User{
		user("1", "super@example.com", func(u *User) { u.IsAdmin, u.Enrolled2SV, u.Enforced2SV = true, false, false }),
		user("2", "deleg@example.com", func(u *User) { u.IsDelegatedAdmin, u.Enrolled2SV, u.Enforced2SV = true, false, false }),
		user("3", "plain@example.com", func(u *User) { u.Enrolled2SV, u.Enforced2SV = false, false }),
		user("4", "ok@example.com", nil),
	}
	res := CheckTwoStep(users)
	if !res.Assessed {
		t.Fatalf("not assessed: %s", res.Reason)
	}
	for id, want := range map[string]Severity{"1": SevCritical, "2": SevHigh, "3": SevMedium} {
		f := findingFor(res, FindingNotEnrolled, id)
		if f == nil || f.Severity != want {
			t.Errorf("user %s: %+v, want severity %s", id, f, want)
		}
	}
	if findingFor(res, FindingNotEnrolled, "4") != nil {
		t.Error("an enrolled user has a finding")
	}
	// Ordered most urgent first.
	if res.Findings[0].Severity != SevCritical {
		t.Errorf("first finding is %s", res.Findings[0].Severity)
	}
	if got := res.Observed["administratorsNotEnrolled"]; got != 2 {
		t.Errorf("administratorsNotEnrolled = %v", got)
	}
	f := findingFor(res, FindingNotEnrolled, "1")
	if f.SubjectLabel != "super@example.com" || len(f.Controls) == 0 || f.Fix == "" || f.Evidence["isAdmin"] != true {
		t.Errorf("finding = %+v", f)
	}
}

// A user for whom 2-Step Verification is enforced but who has not enrolled yet is
// still a user without a second factor: enforcement is the domain's policy, not the
// user's enrolment (mutation: "if u.Enrolled2SV || u.Enforced2SV").
func TestTwoStepEnforcedButNotEnrolledIsNotEnrolled(t *testing.T) {
	users := []User{
		user("1", "late@example.com", func(u *User) { u.Enrolled2SV, u.Enforced2SV = false, true }),
		user("2", "ok@example.com", nil),
	}
	res := CheckTwoStep(users)
	f := findingFor(res, FindingNotEnrolled, "1")
	if f == nil || f.Severity != SevMedium {
		t.Fatalf("enforced, not enrolled: %+v", f)
	}
	if f.Evidence["isEnrolledIn2Sv"] != false || f.Evidence["isEnforcedIn2Sv"] != true {
		t.Errorf("evidence = %+v", f.Evidence)
	}
	if findingFor(res, FindingNotEnrolled, "2") != nil {
		t.Error("an enrolled user has a finding")
	}
	if res.Observed["notEnrolled"] != 1 {
		t.Errorf("observed = %+v", res.Observed)
	}
}

// The standing "not assessed" text is served on the page, by the status endpoint
// and stored in every run. The default Gmail scope (gmail.settings.basic) is a write
// scope for settings, so no text may claim the scopes are read-only.
func TestNotAssessedNeverClaimsReadOnlyScopes(t *testing.T) {
	if len(StandingNotAssessed) == 0 {
		t.Fatal("no standing not-assessed entries")
	}
	for _, n := range StandingNotAssessed {
		for _, bad := range []string{"read-only scopes", "read only scopes", "only for read"} {
			if strings.Contains(strings.ToLower(n.What+" "+n.Why), bad) {
				t.Errorf("%q says %q", n.What, bad)
			}
		}
	}
	var delegates *NotAssessed
	for i := range StandingNotAssessed {
		if strings.Contains(StandingNotAssessed[i].Why, "gmail.settings.sharing") {
			delegates = &StandingNotAssessed[i]
		}
	}
	if delegates == nil || !strings.Contains(delegates.Why, "only GET requests") {
		t.Errorf("delegation entry = %+v", delegates)
	}
}

func TestTwoStepLeavesOutGuestsSuspendedAndArchived(t *testing.T) {
	users := []User{
		user("1", "guest@other.example.org", func(u *User) { u.Guest, u.Enrolled2SV, u.Enforced2SV = true, false, false }),
		user("2", "gone@example.com", func(u *User) { u.Suspended, u.Enrolled2SV, u.Enforced2SV = true, false, false }),
		user("3", "old@example.com", func(u *User) { u.Archived, u.Enrolled2SV, u.Enforced2SV = true, false, false }),
		user("4", "ok@example.com", nil),
	}
	res := CheckTwoStep(users)
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
	if res.Observed["guestsSkipped"] != 1 || res.Observed["suspendedOrArchivedSkipped"] != 2 || res.Observed["activeUsers"] != 1 {
		t.Errorf("observed = %+v", res.Observed)
	}
}

func TestTwoStepEnforcementFinding(t *testing.T) {
	enrolledNotEnforced := func(id string) User {
		return user(id, id+"@example.com", func(u *User) { u.Enforced2SV = false })
	}
	for name, tc := range map[string]struct {
		users []User
		want  Severity // "" = no finding
		title string
	}{
		"everyone enforced": {[]User{user("1", "a@example.com", nil), user("2", "b@example.com", nil)}, "", ""},
		"only enrolled users lack enforcement": {[]User{enrolledNotEnforced("1"), user("2", "b@example.com", nil)}, SevLow,
			"not enforced for 1 of 2 active users"},
		"a user who is neither enrolled nor enforced": {[]User{
			user("1", "a@example.com", func(u *User) { u.Enrolled2SV, u.Enforced2SV = false, false }), user("2", "b@example.com", nil)}, SevMedium, ""},
		"enforced but not enrolled is not an enrolment": {[]User{
			user("1", "a@example.com", func(u *User) { u.Enrolled2SV, u.Enforced2SV = false, true }), user("2", "b@example.com", nil)}, "", ""},
		"an administrator is not covered": {[]User{
			user("1", "a@example.com", func(u *User) { u.IsAdmin, u.Enforced2SV = true, false }), user("2", "b@example.com", nil)}, SevHigh, ""},
		"a delegated administrator is not covered": {[]User{
			user("1", "a@example.com", func(u *User) { u.IsDelegatedAdmin, u.Enforced2SV = true, false })}, SevHigh, ""},
		"an inactive user does not count": {[]User{
			user("1", "a@example.com", func(u *User) { u.Suspended, u.Enforced2SV = true, false }), user("2", "b@example.com", nil)}, "", ""},
	} {
		res := CheckTwoStep(tc.users)
		f := findingFor(res, FindingNotEnforced, "tenant")
		switch {
		case tc.want == "" && f != nil:
			t.Errorf("%s: unexpected finding %+v", name, f)
		case tc.want != "" && f == nil:
			t.Errorf("%s: no enforcement finding", name)
		case f != nil && f.Severity != tc.want:
			t.Errorf("%s: severity %s, want %s", name, f.Severity, tc.want)
		case f != nil && tc.title != "" && !strings.Contains(f.Title, tc.title):
			t.Errorf("%s: title %q lacks %q", name, f.Title, tc.title)
		}
	}
}

func TestSuperAdminLimitBoundary(t *testing.T) {
	mk := func(n int) []User {
		var us []User
		for i := 0; i < n; i++ {
			e := string(rune('a'+i)) + "@example.com"
			us = append(us, user(e, e, func(u *User) { u.IsAdmin = true }))
		}
		return us
	}
	for _, tc := range []struct {
		n, max  int
		wantMed bool
		wantLow bool
	}{
		{1, 4, false, true}, {2, 4, false, false}, {4, 4, false, false}, {5, 4, true, false}, {2, 1, true, false}, {1, 1, false, true},
	} {
		res, facts := CheckSuperAdmins(mk(tc.n), tc.max)
		if !res.Assessed || len(facts.SuperAdmins) != tc.n {
			t.Fatalf("n=%d: %+v", tc.n, res)
		}
		if got := findingFor(res, FindingSuperAdminCount, "tenant") != nil; got != tc.wantMed {
			t.Errorf("n=%d max=%d: count finding = %v, want %v", tc.n, tc.max, got, tc.wantMed)
		}
		if got := findingFor(res, FindingSingleSuperAdmin, "tenant") != nil; got != tc.wantLow {
			t.Errorf("n=%d max=%d: single-admin finding = %v, want %v", tc.n, tc.max, got, tc.wantLow)
		}
	}
	res, _ := CheckSuperAdmins(mk(5), 4)
	f := findingFor(res, FindingSuperAdminCount, "tenant")
	if f.Severity != SevMedium || !strings.Contains(f.Title, "5 accounts") || !strings.Contains(f.Title, "limit 4") || !strings.Contains(f.Detail, "names no maximum") {
		t.Errorf("finding = %+v", f)
	}
}

func TestSuperAdminsCountOnlyActiveSuperAdmins(t *testing.T) {
	users := []User{
		user("1", "a@example.com", func(u *User) { u.IsAdmin = true }),
		user("2", "b@example.com", func(u *User) { u.IsAdmin, u.Suspended = true, true }),
		user("3", "c@example.com", func(u *User) { u.IsAdmin, u.Archived = true, true }),
		user("4", "d@example.com", func(u *User) { u.IsDelegatedAdmin = true }),
		user("5", "e@example.com", func(u *User) { u.IsAdmin, u.Guest = true, true }),
	}
	res, facts := CheckSuperAdmins(users, 4)
	if len(facts.SuperAdmins) != 1 || facts.SuperAdmins[0] != "a@example.com" || len(facts.Delegated) != 1 {
		t.Errorf("facts = %+v", facts)
	}
	if res.Observed["superAdmins"] != 1 || res.Observed["delegatedAdmins"] != 1 {
		t.Errorf("observed = %+v", res.Observed)
	}
}

func TestNoSuperAdminInTheListIsNotAssessed(t *testing.T) {
	res, _ := CheckSuperAdmins([]User{user("1", "a@example.com", nil)}, 4)
	if res.Assessed || !strings.Contains(res.Reason, "no super administrator") || len(res.Findings) != 0 {
		t.Errorf("result = %+v", res)
	}
}
