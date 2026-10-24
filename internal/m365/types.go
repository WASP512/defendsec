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

	"defendsec/internal/controls"
	"defendsec/internal/idposture"
)

// Provider names this integration in the shared identity tables.
const Provider = "m365"

// The shapes every identity collector shares live in internal/idposture (slice 13
// added Google Workspace beside this one); they are aliases here so this package
// reads as before.
type (
	Severity    = idposture.Severity
	Finding     = idposture.Finding
	CheckResult = idposture.CheckResult
	NotAssessed = idposture.NotAssessed
	Report      = idposture.Report
	Counts      = idposture.Counts
)

const (
	SevCritical = idposture.SevCritical
	SevHigh     = idposture.SevHigh
	SevMedium   = idposture.SevMedium
	SevLow      = idposture.SevLow
)

// The check groups. A group is assessed or not as a whole, and its findings are
// resolved only when it was.
const (
	GroupMFA        = idposture.GroupMFA
	GroupLegacyAuth = idposture.GroupLegacyAuth
	GroupAdminRoles = idposture.GroupAdminRoles
	GroupInboxRules = idposture.GroupInboxRules
)

// CheckLabels are the console's names for the check groups.
var CheckLabels = idposture.CheckLabels

// Finding ids (the condition; the subject tells apart several of one).
const (
	FindingMFANotRegistered  = "mfa.not_registered"
	FindingLegacyNotBlocked  = "legacyauth.not_blocked"
	FindingLegacyPartial     = "legacyauth.partial"
	FindingTooManyGlobalAdmn = "roles.global_admin_count"
	FindingRuleForward       = "inbox_rule.forward_external"
	FindingRuleHides         = "inbox_rule.hides_mail"
)

func itoa(n int) string { return idposture.Itoa(n) }

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
