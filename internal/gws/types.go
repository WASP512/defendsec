// Package gws is the Google Workspace identity posture collector (slice 13): what
// a client's domain says about how easily its accounts can be taken over and how
// mail could be hidden or redirected once one is, read through the Admin SDK
// Directory API and the Gmail settings API with read-only scopes and nothing
// installed. It is the counterpart of internal/m365 and fills the same Report.
//
// It reads who is enrolled in 2-Step Verification and who is a super
// administrator, and, for each mailbox, the auto-forwarding setting and the
// definitions of the filters (their criteria and actions). It never reads a
// message: no body, no subject, no sender of any mail, no attachment. The client
// (internal/gws/google) has no method that names a message, and a test proves the
// only paths it requests are the users list and the two settings resources.
//
// The principle of the product holds here too: what the APIs cannot show is
// reported as not assessed, with the reason, and never as a pass. A check that
// could not run produces no finding and resolves none.
package gws

import (
	"context"

	"defendsec/internal/controls"
	"defendsec/internal/idposture"
)

// Provider names this integration in the shared identity tables.
const Provider = "google"

// The shapes every identity collector shares live in internal/idposture.
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

// The check groups of a Google Workspace read. They reuse Microsoft 365's ids so the
// console, the ranking and the stored runs treat both alike; there is no
// legacy-auth group, because Google has no equivalent the Directory API shows.
const (
	GroupTwoStep    = idposture.GroupMFA
	GroupAdmins     = idposture.GroupAdminRoles
	GroupMailConfig = idposture.GroupInboxRules
)

// CheckLabels are the console's names for the check groups of this provider.
var CheckLabels = map[string]string{
	GroupTwoStep:    "2-Step Verification",
	GroupAdmins:     "Super administrators",
	GroupMailConfig: "Gmail forwarding and filters",
}

// CheckOrder is the order the console lists the groups in.
var CheckOrder = []string{GroupTwoStep, GroupAdmins, GroupMailConfig}

// Finding ids (the condition; the subject tells apart several of one).
const (
	FindingNotEnrolled      = "2sv.not_enrolled"
	FindingNotEnforced      = "2sv.not_enforced"
	FindingSuperAdminCount  = "roles.super_admin_count"
	FindingSingleSuperAdmin = "roles.single_super_admin"
	FindingAutoForward      = "gmail.autoforward_external"
	FindingFilterForward    = "gmail.filter_forward_external"
	FindingFilterHides      = "gmail.filter_hides_mail"
)

// User is a directory user.
type User struct {
	ID    string
	Email string // primary address
	Name  string
	// Aliases are the user's other addresses, which carry the domain's other names.
	Aliases          []string
	IsAdmin          bool // super administrator
	IsDelegatedAdmin bool
	Enrolled2SV      bool
	Enforced2SV      bool
	Suspended        bool
	Archived         bool
	Guest            bool
	// MailboxSetup is false only when the Directory API said the Google mailbox
	// does not exist (no Gmail licence or not yet created).
	MailboxSetup bool
	OrgUnit      string
}

// Active is a user who can sign in: not suspended, not archived.
func (u User) Active() bool { return !u.Suspended && !u.Archived }

// AutoForwarding is a mailbox's auto-forwarding setting: all incoming mail goes to
// one address.
type AutoForwarding struct {
	Enabled      bool
	EmailAddress string
	// Disposition is what Gmail does with the original: leaveInInbox, archive,
	// trash or markRead.
	Disposition string
}

// Filter is a Gmail filter's definition: its criteria and its actions. No message
// is involved.
type Filter struct {
	ID string
	// Criteria.
	From, To, Subject, Query, NegatedQuery string
	HasAttachment, ExcludeChats            bool
	Size                                   int64
	// Actions.
	AddLabelIDs, RemoveLabelIDs []string
	Forward                     string
}

// Source reads a domain. The Google-backed implementation is GoogleSource; tests use
// a fake. Every method is a read. The mailbox reads act as the user they name.
type Source interface {
	Users(ctx context.Context) ([]User, error)
	AutoForwarding(ctx context.Context, userEmail string) (AutoForwarding, error)
	Filters(ctx context.Context, userEmail string) ([]Filter, error)
	// Requests is how many API requests the source has made so far.
	Requests() int
}

// Control tagging. Identity findings are tagged with the signals below, which
// resolve to the catalog entries that name what each finding speaks to.
func tag(sig controls.Signal) []string { return controls.Tag(sig) }
