package m365

import (
	"fmt"
	"sort"
	"strings"

	"defendsec/internal/controls"
)

// GlobalAdministratorTemplateID is the role template id of Global Administrator,
// the same GUID in every tenant. Microsoft's Conditional Access examples use it
// in includeRoles, and a built-in role's assignment carries its template id as
// roleDefinitionId.
const GlobalAdministratorTemplateID = "62e90394-69f5-4237-9190-012177145e10"

// DefaultPrivilegedRoles are directory roles (by display name) whose holders are
// treated as administrators when ranking a missing MFA registration, besides
// Global Administrator and whoever the registration report itself marks as an
// admin. Display names, because a wrong GUID would be silently wrong and a
// renamed role merely falls back to the report's isAdmin flag.
var DefaultPrivilegedRoles = []string{
	"Privileged Role Administrator", "Privileged Authentication Administrator", "Security Administrator",
	"Exchange Administrator", "SharePoint Administrator", "User Administrator", "Authentication Administrator",
	"Conditional Access Administrator", "Application Administrator", "Cloud Application Administrator",
	"Helpdesk Administrator", "Intune Administrator", "Hybrid Identity Administrator", "Billing Administrator",
	"Teams Administrator", "Groups Administrator", "Password Administrator",
}

// StandingNotAssessed is what the collector does not see however the read goes,
// said once so every screen uses the same words. Each is a limit of Microsoft
// Graph or of the permissions DefendSec asks for, not a "no problem found".
var StandingNotAssessed = []NotAssessed{
	{
		What: "Mailbox-level forwarding (ForwardingSmtpAddress, ForwardingAddress) and transport rules",
		Why:  "These are Exchange Online settings. Microsoft Graph does not expose them; reading them needs Exchange Online PowerShell or its REST API with the Exchange.ManageAsApp permission and an Exchange role, which this version does not use. A mailbox forwarded this way would not show here.",
	},
	{
		What: "Roles held through a group, and roles that are eligible rather than active (Privileged Identity Management)",
		Why:  "Only active direct assignments are read. A group's members are not expanded and PIM eligibility needs further permissions (and Entra ID P2), so an administrator who holds a role that way is not counted.",
	},
	{
		What: "Whether MFA is enforced for a sign-in",
		Why:  "The registration report says who has a second factor, not whether a policy requires it. Per-user MFA settings and the effect of Conditional Access on a given sign-in are not read.",
	},
	{
		What: "Exchange Online authentication policies and the SMTP AUTH setting",
		Why:  "Microsoft Graph does not expose them. The legacy authentication check reads only security defaults and Conditional Access, so it cannot say what Exchange itself still allows.",
	},
	{
		What: "Inbox rules that exist only in an Outlook client",
		Why:  "Client-side rules are stored in the user's Outlook profile, not on the server, so Graph does not return them. Rules in folders other than the inbox are not read either.",
	},
}

// ---- roles -------------------------------------------------------------------------

// RoleFacts is what the role check learned that the MFA check uses: who holds
// Global Administrator and who holds another privileged role.
type RoleFacts struct {
	// GlobalAdmins maps a user's object id to its principal name.
	GlobalAdmins map[string]string
	// Privileged maps a user's object id to the privileged roles held (not Global Administrator).
	Privileged map[string][]string
	// Known is false when the role assignments could not be read.
	Known bool
}

func roleIsGlobalAdmin(d RoleDefinition) bool {
	return strings.EqualFold(d.TemplateID, GlobalAdministratorTemplateID) ||
		strings.EqualFold(d.ID, GlobalAdministratorTemplateID) ||
		strings.EqualFold(d.DisplayName, "Global Administrator") || strings.EqualFold(d.DisplayName, "Company Administrator")
}

// CheckAdminRoles counts the holders of Global Administrator and finds the other
// privileged-role holders. max is the most Global Administrators a tenant should
// have before it is a finding.
func CheckAdminRoles(defs []RoleDefinition, asg []RoleAssignment, max int, privileged []string) (CheckResult, RoleFacts) {
	res := CheckResult{Check: GroupAdminRoles, Assessed: true}
	facts := RoleFacts{GlobalAdmins: map[string]string{}, Privileged: map[string][]string{}, Known: true}
	byID := map[string]RoleDefinition{}
	for _, d := range defs {
		byID[strings.ToLower(d.ID)] = d
		if d.TemplateID != "" {
			byID[strings.ToLower(d.TemplateID)] = d
		}
	}
	privSet := map[string]bool{}
	for _, n := range privileged {
		privSet[strings.ToLower(n)] = true
	}
	var gaGroups, gaApps, unclassified int
	var otherRoles = map[string]bool{}
	for _, a := range asg {
		def, ok := byID[strings.ToLower(a.RoleDefinitionID)]
		if !ok && strings.EqualFold(a.RoleDefinitionID, GlobalAdministratorTemplateID) {
			def, ok = RoleDefinition{ID: a.RoleDefinitionID, TemplateID: a.RoleDefinitionID, DisplayName: "Global Administrator"}, true
		}
		if !ok {
			continue
		}
		isGA := roleIsGlobalAdmin(def)
		isPriv := privSet[strings.ToLower(def.DisplayName)]
		if !isGA && !isPriv {
			continue
		}
		switch a.PrincipalType {
		case "group":
			if isGA {
				gaGroups++
			}
			continue
		case "servicePrincipal":
			if isGA {
				gaApps++
			}
			continue
		case "user", "":
			if a.PrincipalType == "" {
				unclassified++
			}
		default:
			continue
		}
		label := a.PrincipalUPN
		if label == "" {
			label = a.PrincipalID
		}
		if isGA {
			facts.GlobalAdmins[a.PrincipalID] = label
		} else {
			facts.Privileged[a.PrincipalID] = append(facts.Privileged[a.PrincipalID], def.DisplayName)
			otherRoles[def.DisplayName] = true
		}
	}
	admins := make([]string, 0, len(facts.GlobalAdmins))
	for _, l := range facts.GlobalAdmins {
		admins = append(admins, l)
	}
	sort.Strings(admins)
	roles := make([]string, 0, len(otherRoles))
	for r := range otherRoles {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	res.Observed = map[string]any{
		"roleAssignments":                     len(asg),
		"globalAdmins":                        len(admins),
		"globalAdminLimit":                    max,
		"otherPrivilegedHolders":              len(facts.Privileged),
		"otherPrivilegedRoles":                roles,
		"globalAdminGroups":                   gaGroups,
		"globalAdminServicePrincipals":        gaApps,
		"assignmentsWithUnknownPrincipalType": unclassified,
	}
	res.Observed["globalAdminAccounts"] = admins
	if len(admins) > max {
		res.Findings = append(res.Findings, Finding{
			ID: FindingTooManyGlobalAdmn, Subject: "tenant", SubjectLabel: "Microsoft 365 tenant",
			Severity: SevMedium,
			Title:    fmt.Sprintf("%d accounts hold Global Administrator (limit %d)", len(admins), max),
			Detail: fmt.Sprintf("%d user accounts hold the Global Administrator role directly: %s. Every one of them can take over the whole tenant, so each is a prize for an attacker and a sign-in to protect. Microsoft advises fewer than five and at least two, so the tenant survives a lost account. The limit here is %d and can be changed in the identity settings.",
				len(admins), strings.Join(admins, ", "), max),
			Fix:      "Move day-to-day administration to narrower roles (User Administrator, Exchange Administrator, Helpdesk Administrator) and keep Global Administrator for two or three named accounts, each with MFA. Remove the role from accounts that do not need it: Microsoft Entra admin center > Roles & admins > Global Administrator.",
			Evidence: map[string]any{"globalAdmins": admins, "limit": max},
			Controls: tag(controls.SignalM365Roles),
		})
	}
	return res, facts
}

// ---- MFA ---------------------------------------------------------------------------

// CheckMFA finds users with no MFA method registered. A Global Administrator
// without one is critical, another administrator high, any other member user
// medium. Guests are left out: their own tenant is where they register. facts
// may be unknown (the role assignments could not be read): then only the
// report's own isAdmin flag separates administrators, and Observed says so.
func CheckMFA(regs []MFARegistration, facts RoleFacts) CheckResult {
	res := CheckResult{Check: GroupMFA, Assessed: true}
	var registered, guests, admins, none int
	for _, r := range regs {
		if strings.EqualFold(r.UserType, "guest") {
			guests++
			continue
		}
		if r.IsMfaRegistered {
			registered++
			continue
		}
		none++
		sev, title := SevMedium, "User has no MFA method registered"
		_, isGA := facts.GlobalAdmins[r.ID]
		privRoles := facts.Privileged[r.ID]
		switch {
		case isGA:
			sev, title = SevCritical, "Global Administrator has no MFA method registered"
			admins++
		case r.IsAdmin || len(privRoles) > 0:
			sev, title = SevHigh, "Administrator has no MFA method registered"
			admins++
		}
		methods := r.Methods
		if methods == nil {
			methods = []string{}
		}
		ev := map[string]any{
			"userPrincipalName": r.UPN, "isMfaRegistered": r.IsMfaRegistered, "isMfaCapable": r.IsMfaCapable,
			"isAdmin": r.IsAdmin, "methodsRegistered": methods, "userType": r.UserType,
		}
		if isGA {
			ev["globalAdministrator"] = true
		}
		if len(privRoles) > 0 {
			ev["privilegedRoles"] = privRoles
		}
		role := "a regular user"
		if isGA {
			role = "a Global Administrator, who can take over the whole tenant"
		} else if sev == SevHigh {
			role = "an administrator"
		}
		res.Findings = append(res.Findings, Finding{
			ID: FindingMFANotRegistered, Subject: r.ID, SubjectLabel: r.UPN, Severity: sev, Title: title,
			Detail: fmt.Sprintf("%s (%s) is %s and has not registered a multi-factor authentication method (registered: %s). With only a password, a phished or guessed password is a sign-in. Registered is not the same as enforced: DefendSec reads who has a second factor, not whether a policy requires it.",
				r.UPN, nameOr(r.DisplayName, r.UPN), role, methodsText(methods)),
			Fix:      "Have the user register the Microsoft Authenticator app or a security key at https://aka.ms/mysecurityinfo, then require MFA for everyone with security defaults or a Conditional Access policy (\"Require multifactor authentication for all users\"). Do administrators first.",
			Evidence: ev, Controls: tag(controls.SignalM365MFA),
		})
	}
	res.Observed = map[string]any{
		"usersInReport": len(regs), "registered": registered, "notRegistered": none,
		"administratorsWithoutMFA": admins, "guestsSkipped": guests,
		"globalAdminsIdentified": facts.Known,
	}
	if !facts.Known {
		res.Observed["note"] = "The role assignments could not be read, so Global Administrators were not told apart from other administrators: an administrator without MFA is at most high here, and could be critical."
	}
	sort.Slice(res.Findings, func(i, j int) bool { return res.Findings[i].SubjectLabel < res.Findings[j].SubjectLabel })
	return res
}

func nameOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func methodsText(m []string) string {
	if len(m) == 0 {
		return "none"
	}
	return strings.Join(m, ", ")
}

// ---- legacy authentication ----------------------------------------------------------

func hasAll(l []string, want string) bool {
	for _, s := range l {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// policyBlocksLegacy says how much of legacy authentication an enabled block
// policy covers: both client types for every user and every application is a
// full block.
func policyCoverage(p CAPolicy) (blocks bool, both bool, one bool, everyone bool, everyApp bool) {
	blocks = hasAll(p.BuiltInControls, "block")
	all := hasAll(p.ClientAppTypes, "all")
	eas := all || hasAll(p.ClientAppTypes, "exchangeActiveSync")
	other := all || hasAll(p.ClientAppTypes, "other")
	both, one = eas && other, eas || other
	everyone = hasAll(p.IncludeUsers, "All")
	everyApp = hasAll(p.IncludeApps, "All")
	return
}

// CheckLegacyAuth reads security defaults and Conditional Access. Legacy
// authentication counts as blocked when security defaults are on, or an enabled
// policy blocks both legacy client types for all users and all applications.
// sdErr and caErr are the reasons a policy source could not be read (nil if it
// was). The result is not assessed when the answer depends on a source that could
// not be read.
func CheckLegacyAuth(sd SecurityDefaults, sdErr error, pols []CAPolicy, caErr error) CheckResult {
	res := CheckResult{Check: GroupLegacyAuth}
	obs := map[string]any{}
	res.Observed = obs

	if sdErr == nil {
		obs["securityDefaultsEnabled"] = sd.Enabled
		if sd.Enabled {
			res.Assessed = true
			obs["blockedBy"] = "security defaults"
			return res
		}
	}
	if caErr != nil {
		res.Reason = "Conditional Access policies could not be read: " + why("policies", caErr)
		if sdErr != nil {
			res.Reason += "; security defaults could not be read either: " + why("policies", sdErr)
		}
		return res
	}
	enforcing, reportOnly := []string{}, []string{}
	var full []string
	var partial []map[string]any
	var exclusions bool
	for _, p := range pols {
		blocks, both, one, everyone, everyApp := policyCoverage(p)
		if !blocks || !one {
			continue
		}
		switch strings.ToLower(p.State) {
		case "enabled":
			enforcing = append(enforcing, p.DisplayName)
			if both && everyone && everyApp {
				full = append(full, p.DisplayName)
				if len(p.ExcludeUsers)+len(p.ExcludeGroups)+len(p.ExcludeRoles) > 0 {
					exclusions = true
				}
			} else {
				partial = append(partial, map[string]any{
					"policy": p.DisplayName, "clientAppTypes": p.ClientAppTypes, "allUsers": everyone, "allApplications": everyApp,
				})
			}
		case "enabledforreportingbutnotenforced":
			reportOnly = append(reportOnly, p.DisplayName)
		}
	}
	obs["conditionalAccessPolicies"] = len(pols)
	obs["enforcingBlockPolicies"] = enforcing
	obs["reportOnlyBlockPolicies"] = reportOnly
	if len(full) > 0 {
		res.Assessed = true
		obs["blockedBy"] = "Conditional Access: " + strings.Join(full, ", ")
		obs["policyHasExclusions"] = exclusions
		return res
	}
	if sdErr != nil {
		// Security defaults are unreadable and no policy blocks fully: they might be the block.
		res.Reason = "security defaults could not be read: " + why("policies", sdErr) + ", and no Conditional Access policy blocks legacy authentication for everyone"
		return res
	}
	res.Assessed = true
	fix := "Turn on security defaults (free; blocks legacy authentication and asks every user to register MFA), or, with Microsoft Entra ID P1, create a Conditional Access policy: users All, target resources All, client apps \"Exchange ActiveSync clients\" and \"Other clients\", grant Block access. Run it in report-only first and check that no scanner, printer or line-of-business app still signs in this way."
	caveat := " Exchange Online has switched Basic authentication off by default for most protocols, and DefendSec cannot read what this tenant's Exchange still allows (SMTP AUTH, authentication policies), so this says no Entra-level block was found, not that legacy sign-in works."
	if len(partial) > 0 {
		names := make([]string, 0, len(partial))
		for _, p := range partial {
			names = append(names, p["policy"].(string))
		}
		res.Findings = append(res.Findings, Finding{
			ID: FindingLegacyPartial, Subject: "tenant", SubjectLabel: "Microsoft 365 tenant", Severity: SevLow,
			Title:  "Legacy authentication is blocked only in part",
			Detail: "Security defaults are off. Conditional Access policy " + strings.Join(names, ", ") + " blocks some legacy sign-in, but not both legacy client types for all users and all applications, so a legacy client can still sign in where it does not apply." + caveat,
			Fix:    fix, Evidence: map[string]any{"policies": partial, "securityDefaultsEnabled": false},
			Controls: tag(controls.SignalM365LegacyAuth),
		})
		return res
	}
	detail := "Security defaults are off and no enabled Conditional Access policy blocks legacy authentication (Exchange ActiveSync and \"other\" clients). Legacy protocols do not support MFA, so a password sprayed against one skips the second factor."
	if len(reportOnly) > 0 {
		detail += " A policy that would block it, " + strings.Join(reportOnly, ", ") + ", exists in report-only mode and is not enforcing."
	}
	res.Findings = append(res.Findings, Finding{
		ID: FindingLegacyNotBlocked, Subject: "tenant", SubjectLabel: "Microsoft 365 tenant", Severity: SevMedium,
		Title:    "Legacy authentication is not blocked",
		Detail:   detail + caveat,
		Fix:      fix,
		Evidence: map[string]any{"securityDefaultsEnabled": false, "enabledBlockPolicies": enforcing, "reportOnlyBlockPolicies": reportOnly, "conditionalAccessPolicies": len(pols)},
		Controls: tag(controls.SignalM365LegacyAuth),
	})
	return res
}
