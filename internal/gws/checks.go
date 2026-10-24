package gws

import (
	"fmt"
	"sort"
	"strings"

	"defendsec/internal/controls"
)

// DefaultSuperAdminMax is the default for Options.SuperAdminMax. Google's guidance
// is only "more than one super administrator" and "use super admin accounts only
// when needed"; it names no ceiling, so this number is DefendSec's judgement (the
// same four as the Microsoft 365 Global Administrator limit) and the operator can
// change it.
const DefaultSuperAdminMax = 4

// StandingNotAssessed is what the collector does not see however the read goes,
// said once so every screen uses the same words. Each is a limit of the APIs or of
// the scopes DefendSec asks for, not a "no problem found".
var StandingNotAssessed = []NotAssessed{
	{
		What: "The domain's email routing: Gmail routing and compliance rules, and the Admin console's automatic-forwarding policy",
		Why:  "These are Admin console settings (Apps > Google Workspace > Gmail). The Directory and Gmail settings APIs DefendSec uses do not expose them, so a domain that forwards or copies mail by a routing rule would not show here, and DefendSec cannot say whether the domain allows users to set automatic forwarding at all.",
	},
	{
		What: "Mailbox delegation (another user allowed to read or send as a mailbox)",
		Why:  "Gmail's delegates list needs the gmail.settings.sharing scope, which can also grant access. DefendSec asks only for read-only scopes, so a mailbox opened to another user would not show here.",
	},
	{
		What: "Which 2-Step Verification methods a user has, and whether a sign-in is phishing-resistant",
		Why:  "The Directory API reports whether a user is enrolled in 2-Step Verification and whether it is enforced, not the methods (a phone prompt and a security key look the same). A password phished together with a one-time code is not told apart from a hardware key.",
	},
	{
		What: "What a delegated administrator may do, and administrator roles held through a group",
		Why:  "Only the super administrator and delegated administrator flags are read. The role assignments API needs a further scope (admin.directory.rolemanagement.readonly) that DefendSec does not ask for, so a delegated administrator is treated as an administrator without knowing which privileges it holds.",
	},
	{
		What: "Third-party app access (OAuth grants), app passwords and sign-in risk",
		Why:  "These come from other APIs (the Admin SDK Reports and Tokens APIs) with further scopes that are not requested.",
	},
	{
		What: "Users the administrator account used for the read cannot see",
		Why:  "The Directory API lists the users that account may read. A super administrator sees all of them; a delegated administrator limited to some organisational units sees only those, and the 2-Step Verification, super administrator and mailbox checks then cover only what was listed.",
	},
	{
		What: "Filters and forwarding in mailboxes that cannot be acted as",
		Why:  "A suspended or archived user, one without a Gmail licence, and Google Groups' collaborative inboxes have no mailbox to read through delegation. They are counted, not assessed.",
	},
}

// ---- 2-Step Verification -------------------------------------------------------------

// CheckTwoStep finds users who are not enrolled in 2-Step Verification, and the
// state of enforcement. A super administrator who is not enrolled is critical (the
// same as a Global Administrator without MFA in slice 12), a delegated
// administrator high, any other user medium. Suspended and archived users cannot
// sign in and guests sign in with their own account elsewhere: they are left out
// and counted.
//
// Enforcement is one finding for the domain, not one per user: when it is off for
// someone, a user can switch 2-Step Verification off again. It is high when an
// administrator is not covered, medium when some user is not enrolled and not
// covered, low when everyone not covered is at least enrolled.
func CheckTwoStep(users []User) CheckResult {
	res := CheckResult{Check: GroupTwoStep, Assessed: true}
	var active, enrolled, notEnrolled, adminsNotEnrolled, skippedInactive, guests int
	var notEnforced, adminsNotEnforced, enrolledNotEnforced int
	var adminsNotEnforcedList []string
	for _, u := range users {
		switch {
		case u.Guest:
			guests++
			continue
		case !u.Active():
			skippedInactive++
			continue
		}
		active++
		admin := u.IsAdmin || u.IsDelegatedAdmin
		if !u.Enforced2SV {
			notEnforced++
			if admin {
				adminsNotEnforced++
				adminsNotEnforcedList = append(adminsNotEnforcedList, u.Email)
			}
			if u.Enrolled2SV {
				enrolledNotEnforced++
			}
		}
		if u.Enrolled2SV {
			enrolled++
			continue
		}
		notEnrolled++
		sev, title, role := SevMedium, "User is not enrolled in 2-Step Verification", "a regular user"
		switch {
		case u.IsAdmin:
			sev, title, role = SevCritical, "Super administrator is not enrolled in 2-Step Verification", "a super administrator, who can take over the whole domain"
			adminsNotEnrolled++
		case u.IsDelegatedAdmin:
			sev, title, role = SevHigh, "Administrator is not enrolled in 2-Step Verification", "a delegated administrator"
			adminsNotEnrolled++
		}
		ev := map[string]any{
			"primaryEmail": u.Email, "isEnrolledIn2Sv": u.Enrolled2SV, "isEnforcedIn2Sv": u.Enforced2SV,
			"isAdmin": u.IsAdmin, "isDelegatedAdmin": u.IsDelegatedAdmin, "orgUnitPath": u.OrgUnit,
		}
		enforcedNote := "2-Step Verification is not enforced for this user either, so nothing makes them enrol."
		if u.Enforced2SV {
			enforcedNote = "2-Step Verification is enforced for this user, so Google will ask them to enrol; until they do it is a password alone."
		}
		res.Findings = append(res.Findings, Finding{
			ID: FindingNotEnrolled, Subject: u.ID, SubjectLabel: u.Email, Severity: sev, Title: title,
			Detail: fmt.Sprintf("%s (%s) is %s and is not enrolled in 2-Step Verification. With only a password, a phished or guessed password is a sign-in. %s DefendSec reads whether a user is enrolled and whether it is enforced, not which methods they have.",
				u.Email, nameOr(u.Name, u.Email), role, enforcedNote),
			Fix:      "Have the user turn on 2-Step Verification at myaccount.google.com/security (a security key or passkey is the strongest, a phone prompt or authenticator app the usual), then enforce it for everyone: Admin console > Security > Authentication > 2-Step verification > Allow users to turn on 2-Step Verification and Enforcement. Do administrators first.",
			Evidence: ev, Controls: tag(controls.SignalGWS2SV),
		})
	}
	res.Observed = map[string]any{
		"usersInReport": len(users), "activeUsers": active, "enrolled": enrolled, "notEnrolled": notEnrolled,
		"administratorsNotEnrolled": adminsNotEnrolled, "notEnforced": notEnforced,
		"administratorsNotEnforced": adminsNotEnforced,
		"guestsSkipped":             guests, "suspendedOrArchivedSkipped": skippedInactive,
	}
	if notEnforced > 0 {
		sort.Strings(adminsNotEnforcedList)
		if len(adminsNotEnforcedList) > 20 {
			adminsNotEnforcedList = adminsNotEnforcedList[:20]
		}
		sev, why := SevLow, "Everyone it does not cover is enrolled, so it is on for them today, but each can turn it off again."
		switch {
		case adminsNotEnforced > 0:
			sev, why = SevHigh, "An administrator is not covered, so an administrator can turn 2-Step Verification off, or never enrol."
		case notEnrolled > 0:
			sev, why = SevMedium, "Some users it does not cover have not enrolled, and those who have can turn it off again."
		}
		res.Findings = append(res.Findings, Finding{
			ID: FindingNotEnforced, Subject: "tenant", SubjectLabel: "Google Workspace domain", Severity: sev,
			Title: fmt.Sprintf("2-Step Verification is not enforced for %d of %d active users", notEnforced, active),
			Detail: fmt.Sprintf("%d of %d active users (%d of them administrators) are not covered by an enforcement setting. %s Enrolled is not enforced: enrolment is each user's choice, enforcement is the administrator's policy.",
				notEnforced, active, adminsNotEnforced, why),
			Fix: "Admin console > Security > Authentication > 2-Step verification: tick Allow users to turn on 2-Step Verification, set Enforcement to On for the top organisational unit (or from a date, with a new-user enrolment period), and choose the methods allowed. Try administrators' organisational unit first if everyone is not ready.",
			Evidence: map[string]any{
				"activeUsers": active, "notEnforced": notEnforced, "administratorsNotEnforced": adminsNotEnforced,
				"enrolledButNotEnforced": enrolledNotEnforced, "administrators": adminsNotEnforcedList,
			},
			Controls: tag(controls.SignalGWS2SV),
		})
	}
	sort.Slice(res.Findings, func(i, j int) bool {
		if a, b := res.Findings[i].Severity.Rank(), res.Findings[j].Severity.Rank(); a != b {
			return a > b
		}
		return res.Findings[i].SubjectLabel < res.Findings[j].SubjectLabel
	})
	return res
}

func nameOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// ---- super administrators -------------------------------------------------------------

// AdminFacts is what the administrator check learned.
type AdminFacts struct {
	SuperAdmins []string
	Delegated   []string
}

// CheckSuperAdmins counts the active super administrators. More than max is a
// finding, and so is exactly one (Google advises more than one, so the domain
// survives a lost account). It is not assessed when the list shows no super
// administrator at all, which cannot be true of a domain and means the account used
// for the read cannot see them.
func CheckSuperAdmins(users []User, max int) (CheckResult, AdminFacts) {
	res := CheckResult{Check: GroupAdmins, Assessed: true}
	var f AdminFacts
	for _, u := range users {
		if u.Guest || !u.Active() {
			continue
		}
		if u.IsAdmin {
			f.SuperAdmins = append(f.SuperAdmins, u.Email)
		} else if u.IsDelegatedAdmin {
			f.Delegated = append(f.Delegated, u.Email)
		}
	}
	sort.Strings(f.SuperAdmins)
	sort.Strings(f.Delegated)
	res.Observed = map[string]any{
		"superAdmins": len(f.SuperAdmins), "superAdminLimit": max, "delegatedAdmins": len(f.Delegated),
		"superAdminAccounts": f.SuperAdmins,
	}
	if len(f.SuperAdmins) == 0 {
		res.Assessed = false
		res.Reason = "the user list shows no super administrator, which no domain can have: the administrator account used for the read probably cannot see all users (a delegated administrator limited to some organisational units). Use a super administrator's address in the settings"
		return res, f
	}
	if len(f.SuperAdmins) > max {
		res.Findings = append(res.Findings, Finding{
			ID: FindingSuperAdminCount, Subject: "tenant", SubjectLabel: "Google Workspace domain", Severity: SevMedium,
			Title: fmt.Sprintf("%d accounts are super administrators (limit %d)", len(f.SuperAdmins), max),
			Detail: fmt.Sprintf("%d active accounts are super administrators: %s. Every one of them can take over the whole domain, so each is a prize for an attacker and a sign-in to protect. Google advises more than one, used only when needed, with day-to-day administration done from separate accounts. Google names no maximum; the limit here is %d, DefendSec's judgement, and can be changed in the identity settings.",
				len(f.SuperAdmins), strings.Join(f.SuperAdmins, ", "), max),
			Fix:      "Give day-to-day administration to delegated administrator roles (Admin console > Account > Admin roles) and keep super administrator for two or three named accounts, each with 2-Step Verification and, better, a security key. Remove the role from accounts that do not need it: Directory > Users > the user > Admin roles and privileges.",
			Evidence: map[string]any{"superAdmins": f.SuperAdmins, "limit": max},
			Controls: tag(controls.SignalGWSAdmins),
		})
	}
	if len(f.SuperAdmins) == 1 {
		res.Findings = append(res.Findings, Finding{
			ID: FindingSingleSuperAdmin, Subject: "tenant", SubjectLabel: "Google Workspace domain", Severity: SevLow,
			Title:    "Only one account is a super administrator",
			Detail:   fmt.Sprintf("%s is the only active super administrator. Google advises more than one, each managed by a separate person, so that if one account is lost or compromised another can recover it. This is a resilience finding, not an exposure.", f.SuperAdmins[0]),
			Fix:      "Make a second trusted person a super administrator (Directory > Users > the user > Admin roles and privileges), with 2-Step Verification, and keep it for emergencies.",
			Evidence: map[string]any{"superAdmins": f.SuperAdmins},
			Controls: tag(controls.SignalGWSAdmins),
		})
	}
	return res, f
}
