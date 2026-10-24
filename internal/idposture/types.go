// Package idposture holds what every identity posture collector shares: the
// shape of a finding, of a check group's result and of one read of a tenant
// (Report), and the word lists and matching rules that judge a mail rule or
// filter. Microsoft 365 (internal/m365, slice 12) and Google Workspace
// (internal/gws, slice 13) both produce a Report, and internal/storepg stores
// either one in the same identity tables.
//
// The principle of the product holds for both: what an API cannot show is
// reported as not assessed, with the reason, and never as a pass. A check that
// could not run produces no finding and resolves none.
package idposture

import (
	"strings"
	"time"
)

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
// resolved only when it was. The ids are shared by the providers: a group means
// the same thing in both, and each provider words it in its own labels.
const (
	GroupMFA        = "mfa"
	GroupLegacyAuth = "legacy-auth"
	GroupAdminRoles = "admin-roles"
	GroupInboxRules = "inbox-rules"
)

// CheckLabels are the console's default names for the check groups (Microsoft
// 365's words). A Report may carry its own, see Report.Labels.
var CheckLabels = map[string]string{
	GroupMFA:        "MFA registration",
	GroupLegacyAuth: "Legacy authentication",
	GroupAdminRoles: "Administrator roles",
	GroupInboxRules: "Inbox rules",
}

// Finding is one confirmed condition.
type Finding struct {
	ID string
	// Subject identifies the object: a user's id, "<user id>/<rule id>" for a
	// rule or filter, "tenant" for a tenant-wide condition.
	Subject string
	// SubjectLabel is what a person reads: an address, "address · rule name", or
	// the tenant.
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

// NotAssessed is something an API cannot show, said once so the console shows
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
	// Labels name the check groups in this provider's words; nil means CheckLabels.
	Labels map[string]string
}

// Counts are what the read covered. The names are Microsoft 365's; a provider
// maps its own onto them (Google Workspace: Registrations are the users the 2-Step
// Verification check covered, Rules the Gmail filters read, GlobalAdmins the super
// administrators).
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

// Label is the name of a check group in this report's provider's words.
func (r *Report) Label(check string) string {
	if l, ok := r.Labels[check]; ok {
		return l
	}
	if l, ok := CheckLabels[check]; ok {
		return l
	}
	return check
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
			parts = append(parts, r.Label(c.Check)+": "+c.Reason)
		}
	}
	if r.Counts.Unreadable > 0 {
		parts = append(parts, Plural(r.Counts.Unreadable, "mailbox")+" could not be read")
	}
	if r.Counts.Skipped > 0 {
		parts = append(parts, Plural(r.Counts.Skipped, "mailbox")+" were skipped by the per-read limit")
	}
	return strings.Join(parts, "; ")
}

// Plural is "1 mailbox" or "3 mailboxes" ("1 user", "3 users").
func Plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	if strings.HasSuffix(one, "x") || strings.HasSuffix(one, "s") {
		return Itoa(n) + " " + one + "es"
	}
	return Itoa(n) + " " + one + "s"
}

// Itoa formats an int without importing strconv into a file of words.
func Itoa(n int) string {
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
