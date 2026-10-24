// Package m365 is the Microsoft 365 identity posture collector (slice 12): what
// a client's tenant says about how easily its accounts can be taken over and
// how mail could be hidden or redirected once one is, read through Microsoft
// Graph with read-only application permissions and nothing installed.
//
// It reads authentication metadata (who has registered MFA, which policies
// block legacy sign-in, who holds an administrator role) and the definitions of
// inbox rules (their names, conditions and actions). It never reads a message:
// no body, no subject, no sender of any mail, no attachment, and the
// permissions it asks for cannot reach one except the optional Mail.ReadBasic.All
// that docs/M365.md explains and leaves off by default.
//
// The principle of the product holds here too: what Graph cannot show is
// reported as not assessed, with the reason, and never as a pass. A check that
// could not run produces no finding and resolves none.
package m365

import (
	"context"
	"strings"
	"time"

	"defendsec/internal/controls"
)

// Provider names this integration in the shared identity tables.
const Provider = "m365"

// Severity of a finding, from most to least urgent.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
)

// Rank orders severities, higher is more urgent.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

// The check groups. A group is assessed or not as a whole, and its findings are
// resolved only when it was.
const (
	GroupMFA        = "mfa"
	GroupLegacyAuth = "legacy-auth"
	GroupAdminRoles = "admin-roles"
	GroupInboxRules = "inbox-rules"
)

// CheckLabels are the console's names for the check groups.
var CheckLabels = map[string]string{
	GroupMFA:        "MFA registration",
	GroupLegacyAuth: "Legacy authentication",
	GroupAdminRoles: "Administrator roles",
	GroupInboxRules: "Inbox rules",
}

// Finding ids (the condition; the subject tells apart several of one).
const (
	FindingMFANotRegistered  = "mfa.not_registered"
	FindingLegacyNotBlocked  = "legacyauth.not_blocked"
	FindingLegacyPartial     = "legacyauth.partial"
	FindingTooManyGlobalAdmn = "roles.global_admin_count"
	FindingRuleForward       = "inbox_rule.forward_external"
	FindingRuleHides         = "inbox_rule.hides_mail"
)

// Finding is one confirmed condition.
type Finding struct {
	ID string
	// Subject identifies the object: a user's object id, "<user id>/<rule id>"
	// for an inbox rule, "tenant" for a tenant-wide condition.
	Subject string
	// SubjectLabel is what a person reads: a user principal name, "name · rule
	// name", or the tenant.
	SubjectLabel string
	Severity     Severity
	Title        string
	Detail       string
	Fix          string
	// Evidence is what was observed, and only that: registration flags, policy
	// names and states, a rule's name, conditions and actions. Never message content.
	Evidence map[string]any
	Controls []string
}

// CheckResult is the outcome of one check group.
type CheckResult struct {
	Check string
	// Assessed is false when the check could not reach a conclusion. Reason says
	// why. Missing evidence is not a pass and not a failure.
	Assessed bool
	Reason   string
	// Observed is what the check saw, in counts and names, for the console.
	Observed map[string]any
	Findings []Finding
	// UnassessedPrefixes are subject prefixes (a user id) the check could not
	// cover although it ran: findings under them are neither confirmed nor
	// resolved by this run.
	UnassessedPrefixes []string
}

// NotAssessed is something Graph cannot show, said once so the console shows
// the same words every time.
type NotAssessed struct {
	What string `json:"what"`
	Why  string `json:"why"`
}

// Report is one read of a tenant.
type Report struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Checks     []CheckResult
	// NotAssessed is the standing list of what the collector does not see, plus
	// what this run could not read.
	NotAssessed []NotAssessed
	Requests    int
	Counts      Counts
	// Fatal is set when the credentials were refused: nothing was read.
	Fatal string
}

// Counts are what the read covered.
type Counts struct {
	Users             int `json:"users"`
	Registrations     int `json:"registrations"`
	MailboxesEligible int `json:"mailboxesEligible"`
	MailboxesRead     int `json:"mailboxesRead"`
	NoMailbox         int `json:"noMailbox"`
	Unreadable        int `json:"unreadable"`
	Skipped           int `json:"skipped"`
	Rules             int `json:"rules"`
	GlobalAdmins      int `json:"globalAdmins"`
}

// Status says how much of the tenant the read covered: ok (every check ran on
// everything), partial (some check or mailbox could not be read) or not_assessed
// (no check ran).
func (r *Report) Status() string {
	assessed, total := 0, len(r.Checks)
	for _, c := range r.Checks {
		if c.Assessed {
			assessed++
		}
	}
	switch {
	case total == 0 || assessed == 0:
		return "not_assessed"
	case assessed < total || r.Counts.Unreadable > 0 || r.Counts.Skipped > 0:
		return "partial"
	}
	return "ok"
}

// Reason summarises why a read is not ok, for the run record.
func (r *Report) Reason() string {
	if r.Fatal != "" {
		return r.Fatal
	}
	var parts []string
	for _, c := range r.Checks {
		if !c.Assessed {
			parts = append(parts, CheckLabels[c.Check]+": "+c.Reason)
		}
	}
	if r.Counts.Unreadable > 0 {
		parts = append(parts, plural(r.Counts.Unreadable, "mailbox")+" could not be read")
	}
	if r.Counts.Skipped > 0 {
		parts = append(parts, plural(r.Counts.Skipped, "mailbox")+" were skipped by the per-read limit")
	}
	return strings.Join(parts, "; ")
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + one + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---- what Graph returns ------------------------------------------------------------

// User is a directory user.
type User struct {
	ID             string
	UPN            string
	DisplayName    string
	Mail           string
	AccountEnabled bool
	UserType       string // member or guest
}

// MFARegistration is one row of the authentication methods registration report.
type MFARegistration struct {
	ID              string
	UPN             string
	DisplayName     string
	UserType        string
	IsAdmin         bool
	IsMfaRegistered bool
	IsMfaCapable    bool
	Methods         []string
}

// RoleDefinition is a directory role.
type RoleDefinition struct {
	ID          string
	DisplayName string
	TemplateID  string
}

// RoleAssignment is an active assignment of a directory role to a principal.
type RoleAssignment struct {
	ID               string
	PrincipalID      string
	RoleDefinitionID string
	// PrincipalType is user, group or servicePrincipal ("" when Graph did not say).
	PrincipalType string
	PrincipalUPN  string
	PrincipalName string
}

// CAPolicy is a Conditional Access policy, reduced to what the legacy
// authentication check reads.
type CAPolicy struct {
	ID              string
	DisplayName     string
	State           string // enabled, disabled, enabledForReportingButNotEnforced
	ClientAppTypes  []string
	IncludeUsers    []string
	ExcludeUsers    []string
	IncludeGroups   []string
	ExcludeGroups   []string
	IncludeRoles    []string
	ExcludeRoles    []string
	IncludeApps     []string
	ExcludeApps     []string
	BuiltInControls []string
	GrantOperator   string
}

// SecurityDefaults is the tenant's security defaults policy.
type SecurityDefaults struct{ Enabled bool }

// InboxRule is a mailbox rule's definition: its name, conditions and actions.
// No message is involved.
type InboxRule struct {
	ID       string
	Name     string
	Sequence int
	Enabled  bool
	HasError bool
	ReadOnly bool

	// Conditions that match on who sent a message or on words in it.
	SenderContains        []string
	FromAddresses         []string
	SubjectContains       []string
	BodyContains          []string
	BodyOrSubjectContains []string
	HeaderContains        []string
	RecipientContains     []string
	// OtherConditions names the other conditions the rule has (importance,
	// attachments, size...), without their values.
	OtherConditions []string

	Delete                bool
	PermanentDelete       bool
	MarkAsRead            bool
	MoveToFolder          string // a folder id
	CopyToFolder          string
	ForwardTo             []string // addresses
	RedirectTo            []string
	ForwardAsAttachmentTo []string
	OtherActions          []string

	// MoveToFolderName is the display name of MoveToFolder when it could be
	// resolved (needs the optional Mail.ReadBasic.All), else "".
	MoveToFolderName string
}

// Source reads a tenant. The Graph-backed implementation is GraphSource; tests
// use a fake. Every method is a read.
type Source interface {
	SecurityDefaults(ctx context.Context) (SecurityDefaults, error)
	ConditionalAccessPolicies(ctx context.Context) ([]CAPolicy, error)
	Users(ctx context.Context) ([]User, error)
	MFARegistrations(ctx context.Context) ([]MFARegistration, error)
	RoleDefinitions(ctx context.Context) ([]RoleDefinition, error)
	RoleAssignments(ctx context.Context) ([]RoleAssignment, error)
	InboxRules(ctx context.Context, userID string) ([]InboxRule, error)
	// FolderName is the display name of a mail folder of a user.
	FolderName(ctx context.Context, userID, folderID string) (string, error)
	// Requests is how many requests the source has made so far.
	Requests() int
}

// Control tagging. Identity findings are tagged with the signals below, which
// resolve to the catalog entries that name what each finding speaks to.
func tag(sig controls.Signal) []string { return controls.Tag(sig) }
