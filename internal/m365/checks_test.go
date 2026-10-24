package m365

import (
	"errors"
	"strings"
	"testing"

	"defendsec/internal/m365/graph"
)

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"|"+f.SubjectLabel+"|"+string(f.Severity))
	}
	return out
}

func TestMFASeverityByRole(t *testing.T) {
	regs := []MFARegistration{
		{ID: "ga", UPN: "ga@example.com", UserType: "member", IsAdmin: true},
		{ID: "hd", UPN: "hd@example.com", UserType: "member", IsAdmin: true},
		{ID: "role", UPN: "role@example.com", UserType: "member"}, // a privileged role the report did not flag
		{ID: "user", UPN: "user@example.com", UserType: "member"},
		{ID: "ok", UPN: "ok@example.com", UserType: "member", IsMfaRegistered: true},
		{ID: "guest", UPN: "g@example.net", UserType: "guest"},
		{ID: "gaok", UPN: "gaok@example.com", UserType: "member", IsAdmin: true, IsMfaRegistered: true},
	}
	facts := RoleFacts{Known: true, GlobalAdmins: map[string]string{"ga": "ga@example.com", "gaok": "gaok@example.com"}, Privileged: map[string][]string{"role": {"Exchange Administrator"}}}
	res := CheckMFA(regs, facts)
	if !res.Assessed {
		t.Fatal("not assessed")
	}
	got := map[string]Severity{}
	for _, f := range res.Findings {
		got[f.Subject] = f.Severity
	}
	want := map[string]Severity{"ga": SevCritical, "hd": SevHigh, "role": SevHigh, "user": SevMedium}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", ids(res.Findings), want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	for _, f := range res.Findings {
		if f.ID != FindingMFANotRegistered || f.Fix == "" || len(f.Controls) == 0 {
			t.Errorf("finding %+v lacks id, fix or control tags", f)
		}
	}
	if res.Observed["guestsSkipped"] != 1 || res.Observed["registered"] != 2 || res.Observed["notRegistered"] != 4 {
		t.Errorf("observed = %v", res.Observed)
	}
	// A user who is not in the report is not a pass: nothing says it was checked.
	if _, seen := got["missing"]; seen {
		t.Error("a user absent from the report got a finding")
	}
}

func TestMFAWithoutRoleFactsSaysSo(t *testing.T) {
	res := CheckMFA([]MFARegistration{{ID: "ga", UPN: "ga@example.com", UserType: "member", IsAdmin: true}}, RoleFacts{})
	if len(res.Findings) != 1 || res.Findings[0].Severity != SevHigh {
		t.Fatalf("findings = %v", ids(res.Findings))
	}
	if note, _ := res.Observed["note"].(string); !strings.Contains(note, "could be critical") {
		t.Errorf("observed note = %q", note)
	}
}

func asg(role, principal, typ, upn string) RoleAssignment {
	return RoleAssignment{ID: "a-" + principal + role, PrincipalID: principal, RoleDefinitionID: role, PrincipalType: typ, PrincipalUPN: upn}
}

func TestAdminRolesCountsOnlyDirectUserHolders(t *testing.T) {
	defs := []RoleDefinition{
		{ID: GlobalAdministratorTemplateID, TemplateID: GlobalAdministratorTemplateID, DisplayName: "Global Administrator"},
		{ID: "r-hd", DisplayName: "Helpdesk Administrator"},
		{ID: "r-gr", DisplayName: "Global Reader"},
	}
	as := []RoleAssignment{
		asg(GlobalAdministratorTemplateID, "u1", "user", "u1@example.com"),
		asg(GlobalAdministratorTemplateID, "u2", "user", "u2@example.com"),
		asg(GlobalAdministratorTemplateID, "u2", "user", "u2@example.com"), // the same account twice (two scopes)
		asg(GlobalAdministratorTemplateID, "g1", "group", ""),
		asg(GlobalAdministratorTemplateID, "sp1", "servicePrincipal", ""),
		asg("r-hd", "u3", "user", "u3@example.com"),
		asg("r-gr", "u4", "user", "u4@example.com"),
	}
	res, facts := CheckAdminRoles(defs, as, 2, DefaultPrivilegedRoles)
	if !res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("2 admins at limit 2: %v", ids(res.Findings))
	}
	if len(facts.GlobalAdmins) != 2 || facts.Privileged["u3"][0] != "Helpdesk Administrator" || len(facts.Privileged) != 1 {
		t.Errorf("facts = %+v", facts)
	}
	if res.Observed["globalAdminGroups"] != 1 || res.Observed["globalAdminServicePrincipals"] != 1 {
		t.Errorf("observed = %v", res.Observed)
	}
	res, _ = CheckAdminRoles(defs, as, 1, nil)
	if len(res.Findings) != 1 || res.Findings[0].ID != FindingTooManyGlobalAdmn || res.Findings[0].Severity != SevMedium {
		t.Fatalf("limit 1: %v", ids(res.Findings))
	}
	if !strings.Contains(res.Findings[0].Title, "2 accounts") || !strings.Contains(res.Findings[0].Detail, "u1@example.com") {
		t.Errorf("finding = %+v", res.Findings[0])
	}
}

func TestAdminRolesRecognisesGlobalAdminByTemplateIDEvenWithoutDefinition(t *testing.T) {
	res, facts := CheckAdminRoles(nil, []RoleAssignment{asg(strings.ToUpper(GlobalAdministratorTemplateID), "u1", "user", "u1@example.com")}, 4, nil)
	if len(facts.GlobalAdmins) != 1 || !res.Assessed {
		t.Errorf("facts = %+v", facts)
	}
}

var noCA []CAPolicy

func TestLegacyAuth(t *testing.T) {
	blockAll := CAPolicy{DisplayName: "Block legacy", State: "enabled", ClientAppTypes: []string{"exchangeActiveSync", "other"},
		IncludeUsers: []string{"All"}, IncludeApps: []string{"All"}, BuiltInControls: []string{"block"}, ExcludeGroups: []string{"breakglass"}}
	reportOnly := blockAll
	reportOnly.State = "enabledForReportingButNotEnforced"
	easOnly := blockAll
	easOnly.ClientAppTypes = []string{"exchangeActiveSync"}
	scoped := blockAll
	scoped.IncludeUsers = []string{}
	scoped.IncludeGroups = []string{"g"}
	disabled := blockAll
	disabled.State = "disabled"
	mfaOnly := CAPolicy{DisplayName: "MFA", State: "enabled", ClientAppTypes: []string{"all"}, IncludeUsers: []string{"All"}, IncludeApps: []string{"All"}, BuiltInControls: []string{"mfa"}}
	allClients := blockAll
	allClients.ClientAppTypes = []string{"all"}
	errForbidden := &graph.Error{Kind: graph.KindForbidden, Status: 403, Code: "Authorization_RequestDenied"}

	cases := []struct {
		name     string
		sd       SecurityDefaults
		sdErr    error
		pols     []CAPolicy
		caErr    error
		assessed bool
		want     []string // finding ids
		sev      Severity
	}{
		{"security defaults on", SecurityDefaults{Enabled: true}, nil, noCA, nil, true, nil, ""},
		{"security defaults on, CA unreadable: defaults decide", SecurityDefaults{Enabled: true}, nil, nil, errForbidden, true, nil, ""},
		{"defaults off, full block policy", SecurityDefaults{}, nil, []CAPolicy{blockAll}, nil, true, nil, ""},
		{"defaults off, block policy for all client types", SecurityDefaults{}, nil, []CAPolicy{allClients}, nil, true, nil, ""},
		{"defaults off, nothing blocks", SecurityDefaults{}, nil, []CAPolicy{mfaOnly}, nil, true, []string{FindingLegacyNotBlocked}, SevMedium},
		{"defaults off, no CA at all", SecurityDefaults{}, nil, noCA, nil, true, []string{FindingLegacyNotBlocked}, SevMedium},
		{"defaults off, report-only policy", SecurityDefaults{}, nil, []CAPolicy{reportOnly}, nil, true, []string{FindingLegacyNotBlocked}, SevMedium},
		{"defaults off, disabled policy", SecurityDefaults{}, nil, []CAPolicy{disabled}, nil, true, []string{FindingLegacyNotBlocked}, SevMedium},
		{"defaults off, one client type only", SecurityDefaults{}, nil, []CAPolicy{easOnly}, nil, true, []string{FindingLegacyPartial}, SevLow},
		{"defaults off, policy scoped to a group", SecurityDefaults{}, nil, []CAPolicy{scoped}, nil, true, []string{FindingLegacyPartial}, SevLow},
		{"CA unreadable, defaults off: not assessed", SecurityDefaults{}, nil, nil, errForbidden, false, nil, ""},
		{"defaults unreadable, no full block: not assessed", SecurityDefaults{}, errForbidden, []CAPolicy{mfaOnly}, nil, false, nil, ""},
		{"defaults unreadable, full block: assessed", SecurityDefaults{}, errForbidden, []CAPolicy{blockAll}, nil, true, nil, ""},
		{"both unreadable: not assessed", SecurityDefaults{}, errForbidden, nil, errForbidden, false, nil, ""},
	}
	for _, c := range cases {
		res := CheckLegacyAuth(c.sd, c.sdErr, c.pols, c.caErr)
		if res.Assessed != c.assessed {
			t.Errorf("%s: assessed = %v (%s)", c.name, res.Assessed, res.Reason)
			continue
		}
		if !c.assessed && (res.Reason == "" || len(res.Findings) != 0) {
			t.Errorf("%s: not assessed needs a reason and no findings: %q %v", c.name, res.Reason, ids(res.Findings))
		}
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.ID)
			if f.Severity != c.sev {
				t.Errorf("%s: severity %s, want %s", c.name, f.Severity, c.sev)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: findings %v, want %v", c.name, got, c.want)
		}
	}
	// A report-only policy is named so the fix is a switch, not a build.
	res := CheckLegacyAuth(SecurityDefaults{}, nil, []CAPolicy{reportOnly}, nil)
	if !strings.Contains(res.Findings[0].Detail, "report-only") {
		t.Errorf("detail does not mention the report-only policy: %s", res.Findings[0].Detail)
	}
	// And the finding says what DefendSec cannot see of Exchange.
	if !strings.Contains(res.Findings[0].Detail, "SMTP AUTH") {
		t.Errorf("detail lacks the Exchange caveat")
	}
	// A not-assessed reason is plain words, with no raw body.
	res = CheckLegacyAuth(SecurityDefaults{}, nil, nil, errors.New("boom"))
	if res.Assessed {
		t.Error("an unclassified CA error was assessed")
	}
}
