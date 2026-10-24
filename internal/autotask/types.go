// Package autotask turns DefendSec's Fix-this-week list into Autotask tickets
// (slice 14): one ticket per remediation action, never one per CVE and host; a
// note on that ticket when hosts join or a finding closes, with the evidence; a
// dry-run that shows the exact tickets and changes nothing; and a ledger entry
// for every ticket action.
//
// This file holds the types. group.go decides what the actions are and how urgent
// each is, render.go words the ticket and its notes, and engine.go reconciles the
// actions with the tickets that exist. The REST client is in the client package;
// this package never talks HTTP itself.
package autotask

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/autotask/client"
)

// Sources of an action, the kinds of row Fix this week holds.
const (
	SourceVuln     = "vuln"
	SourceEOL      = "eol"
	SourceSurface  = "surface"
	SourceIdentity = "identity"
)

// Urgency levels. An action's urgency maps to an Autotask priority; low is never
// ticketed (the mapping has three levels, and "low" is what Fix this week ranks
// after everything that matters this week).
const (
	UrgencyCritical = "critical"
	UrgencyHigh     = "high"
	UrgencyMedium   = "medium"
	UrgencyLow      = "low"
)

// UrgencyRank orders the levels: critical 3 ... low 0.
func UrgencyRank(u string) int {
	switch u {
	case UrgencyCritical:
		return 3
	case UrgencyHigh:
		return 2
	case UrgencyMedium:
		return 1
	}
	return 0
}

// Modes.
const (
	ModeDryRun = "dry_run"
	ModeLive   = "live"
)

// States of a tracked ticket.
const (
	StateOpen = "open"
	// StateResolved: DefendSec no longer sees any open finding of the action.
	StateResolved = "resolved"
	// StateClosedInPSA: a technician completed the ticket while findings remain.
	// DefendSec does not reopen it or open another for the same findings.
	StateClosedInPSA = "closed_in_psa"
)

// Finding is one open finding of the Fix-this-week list, normalised across the
// four sources. The store fills it; only the fields of its Source are used.
type Finding struct {
	Source string
	// MemberKey and MemberLabel say where it applies: a host (device id and
	// hostname), an asset or an account.
	MemberKey   string
	MemberLabel string
	FirstSeen   time.Time

	// Vulnerabilities and end-of-life (one row per host, advisory and package family).
	Family         string
	Package        string
	Installed      string
	Fixed          string
	AdvisoryID     string
	CVE            string
	Severity       string
	KEV            bool
	EPSS           *float64
	CVSS           *float64
	PackageManager string
	Distro         string
	EOLProduct     string
	EOLCycle       string
	EOLStage       string
	EOLLabel       string
	EOLUpgrade     string
	EOLDate        string

	// Surface and identity findings.
	CheckID  string // the finding id ("spf.missing", "mfa.not_registered")
	Provider string // identity provider
	Subject  string
	Title    string
	Detail   string
	Fix      string
}

// Member is where an action applies: one host, asset or account.
type Member struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Line is the member's line in the ticket description.
	Line string `json:"line"`
	// Digest changes when what is open on the member changes, so a note is added
	// for a host whose advisories grew without the host being new.
	Digest string `json:"digest"`
}

// Group is one remediation action.
type Group struct {
	Key     string
	Source  string
	Title   string
	Urgency string
	// Why is the ranking reason, in words.
	Why string
	// Fix is the fix-it text.
	Fix string
	// Link is the DefendSec page; empty when no console URL is set.
	Link    string
	Members []Member
	// Advisories is how many advisories (or findings) the action closes.
	Advisories int
}

// MemberState is what a tracked ticket remembers of a member.
type MemberState struct {
	Label  string `json:"label"`
	Digest string `json:"digest"`
}

// Tracked is a ticket DefendSec created (or adopted) and follows.
type Tracked struct {
	GroupKey     string
	Generation   int
	Tag          string
	TicketID     int64
	TicketNumber string
	CompanyID    int64
	Title        string
	State        string
	Urgency      string
	Members      map[string]MemberState
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ResolvedAt   *time.Time
}

// MemberRef names a member of an action: which action, which host, asset or
// account, and since when the ticket has covered it.
type MemberRef struct {
	GroupKey  string
	MemberKey string
	// Since is when the ticket was opened: evidence is what closed after that.
	Since time.Time
}

// Evidence says how a member that was open is no longer.
type Evidence struct {
	Label      string
	ResolvedAt time.Time
	// Detail is the store's description ("openssl 3.0.2-0ubuntu1.19 observed; 3 advisories closed").
	Detail string
	// Found is false when DefendSec has no record of how it closed (a host or
	// asset that was removed).
	Found bool
}

// ---- settings -----------------------------------------------------------------------

// Settings map one DefendSec instance to one Autotask company and say how its
// tickets look. Every picklist value is an Autotask picklist value (a number as
// text) read from the live API on the settings page; nothing is a default in code.
type Settings struct {
	Mode string `json:"mode"`
	// APIUser is the API-only user's name (not a secret); the secret and the
	// integration code are files the operator points apid at.
	APIUser   string `json:"apiUser"`
	ZoneURL   string `json:"zoneUrl"`
	CompanyID int64  `json:"companyId"`

	QueueID      string `json:"queueId"`
	Status       string `json:"status"`
	Source       string `json:"source"`
	IssueType    string `json:"issueType"`
	SubIssueType string `json:"subIssueType"`

	PriorityCritical string `json:"priorityCritical"`
	PriorityHigh     string `json:"priorityHigh"`
	PriorityMedium   string `json:"priorityMedium"`

	NoteType    string `json:"noteType"`
	NotePublish string `json:"notePublish"`

	// AutoComplete completes a ticket (sets CompleteStatus) when DefendSec sees
	// every finding of its action resolved. Off by default.
	AutoComplete   bool   `json:"autoComplete"`
	CompleteStatus string `json:"completeStatus"`

	// MinUrgency is the lowest urgency that opens a new ticket.
	MinUrgency string `json:"minUrgency"`
	// DueDays is how many days from creation a ticket is due, by urgency.
	DueDaysCritical int `json:"dueDaysCritical"`
	DueDaysHigh     int `json:"dueDaysHigh"`
	DueDaysMedium   int `json:"dueDaysMedium"`

	// ConsoleURL is where the operator reaches the DefendSec console, for the link
	// in each ticket.
	ConsoleURL string `json:"consoleUrl"`
	// MaxCreates bounds the tickets one run opens (the rest wait for the next run).
	MaxCreates int `json:"maxCreates"`
}

// Limits and defaults.
const (
	DefaultMaxCreates = 10
	MaxMaxCreates     = 50
	MaxNotesPerRun    = 60
)

// ErrBadSettings is wrapped by validation errors an API can show.
var ErrBadSettings = errors.New("bad autotask settings")

// DefaultSettings are the settings of an instance that never saved any: a dry
// run, a high-and-up threshold, no auto-complete.
func DefaultSettings() Settings {
	return Settings{Mode: ModeDryRun, MinUrgency: UrgencyHigh, DueDaysCritical: 2, DueDaysHigh: 7, DueDaysMedium: 14, MaxCreates: DefaultMaxCreates}
}

var (
	pickRe = regexp.MustCompile(`^-?[0-9]{1,12}$`)
	userRe = regexp.MustCompile(`^[A-Za-z0-9._%+@-]{3,254}$`)
)

func badf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadSettings, fmt.Sprintf(format, a...))
}

// Normalize validates and cleans the settings in place. It checks the shape of
// every value; whether a picklist value exists is checked against the live
// picklists (CheckAgainst).
func (s *Settings) Normalize() error {
	s.APIUser = strings.TrimSpace(s.APIUser)
	if s.APIUser != "" && !userRe.MatchString(s.APIUser) {
		return badf("the API user name is not valid")
	}
	if z := strings.TrimSpace(s.ZoneURL); z != "" {
		c, err := client.CheckZoneURL(z)
		if err != nil {
			return badf("%v", err)
		}
		s.ZoneURL = c
	} else {
		s.ZoneURL = ""
	}
	if s.CompanyID < 0 || s.CompanyID > 1<<53 {
		return badf("the company id is not valid")
	}
	switch s.Mode {
	case "":
		s.Mode = ModeDryRun
	case ModeDryRun, ModeLive:
	default:
		return badf("mode must be dry_run or live")
	}
	for name, v := range map[string]*string{
		"queue": &s.QueueID, "status": &s.Status, "source": &s.Source, "issue type": &s.IssueType, "sub-issue type": &s.SubIssueType,
		"critical priority": &s.PriorityCritical, "high priority": &s.PriorityHigh, "medium priority": &s.PriorityMedium,
		"note type": &s.NoteType, "note visibility": &s.NotePublish, "completed status": &s.CompleteStatus,
	} {
		*v = strings.TrimSpace(*v)
		if *v != "" && !pickRe.MatchString(*v) {
			return badf("%s must be a picklist value read from Autotask", name)
		}
	}
	if s.SubIssueType != "" && s.IssueType == "" {
		return badf("a sub-issue type needs its issue type")
	}
	if s.AutoComplete && s.CompleteStatus == "" {
		return badf("auto-complete needs the status that means completed")
	}
	switch s.MinUrgency {
	case "":
		s.MinUrgency = UrgencyHigh
	case UrgencyCritical, UrgencyHigh, UrgencyMedium:
	default:
		return badf("the lowest urgency that opens a ticket must be critical, high or medium")
	}
	for name, d := range map[string]*int{"critical": &s.DueDaysCritical, "high": &s.DueDaysHigh, "medium": &s.DueDaysMedium} {
		if *d < 1 || *d > 90 {
			return badf("the %s due date must be 1 to 90 days away", name)
		}
	}
	if s.MaxCreates == 0 {
		s.MaxCreates = DefaultMaxCreates
	}
	if s.MaxCreates < 1 || s.MaxCreates > MaxMaxCreates {
		return badf("at most %d tickets per run (1 to %d)", MaxMaxCreates, MaxMaxCreates)
	}
	if c := strings.TrimSpace(s.ConsoleURL); c != "" {
		u, err := url.Parse(c)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return badf("the console URL must be an http(s) address with no credentials or query")
		}
		s.ConsoleURL = strings.TrimRight(u.String(), "/")
	} else {
		s.ConsoleURL = ""
	}
	return nil
}

// Priority returns the mapped priority value for an urgency ("" if unmapped or low).
func (s Settings) Priority(urgency string) string {
	switch urgency {
	case UrgencyCritical:
		return s.PriorityCritical
	case UrgencyHigh:
		return s.PriorityHigh
	case UrgencyMedium:
		return s.PriorityMedium
	}
	return ""
}

// DueDays returns the due-date offset for an urgency.
func (s Settings) DueDays(urgency string) int {
	switch urgency {
	case UrgencyCritical:
		return s.DueDaysCritical
	case UrgencyHigh:
		return s.DueDaysHigh
	}
	return s.DueDaysMedium
}

// Missing lists, in words, what has to be chosen before tickets can be shown or
// opened. Nothing is guessed: an Autotask taxonomy is the client's.
func (s Settings) Missing() []string {
	var m []string
	if s.APIUser == "" {
		m = append(m, "the API user's name")
	}
	if s.CompanyID == 0 {
		m = append(m, "the Autotask company (by id)")
	}
	if s.QueueID == "" {
		m = append(m, "the queue")
	}
	if s.Status == "" {
		m = append(m, "the status of a new ticket")
	}
	if s.PriorityCritical == "" || s.PriorityHigh == "" || s.PriorityMedium == "" {
		m = append(m, "a priority for each of critical, high and medium")
	}
	if s.NoteType == "" || s.NotePublish == "" {
		m = append(m, "the note type and who may see a note")
	}
	return m
}

// Fingerprint identifies everything a ticket's content and destination depend
// on. A live run needs a dry run with the same fingerprint behind it.
func (s Settings) Fingerprint() string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode([]any{
		s.APIUser, s.ZoneURL, s.CompanyID, s.QueueID, s.Status, s.Source, s.IssueType, s.SubIssueType,
		s.PriorityCritical, s.PriorityHigh, s.PriorityMedium, s.NoteType, s.NotePublish,
		s.AutoComplete, s.CompleteStatus, s.MinUrgency, s.DueDaysCritical, s.DueDaysHigh, s.DueDaysMedium, s.ConsoleURL,
	})
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// CheckAgainst checks the picklist choices against the live field lists and
// returns what is wrong, in words. Empty means every chosen value is an active
// Autotask value today.
func (s Settings) CheckAgainst(tf, nf client.Fields) []string {
	var bad []string
	check := func(label, field, val string, f client.Fields) {
		if val == "" {
			return
		}
		if !f.HasActive(field, val) {
			bad = append(bad, fmt.Sprintf("%s (%s) is not an active value of Autotask's %s list any more", label, val, field))
		}
	}
	check("the queue", "queueID", s.QueueID, tf)
	check("the status of a new ticket", "status", s.Status, tf)
	check("the source", "source", s.Source, tf)
	check("the issue type", "issueType", s.IssueType, tf)
	check("the critical priority", "priority", s.PriorityCritical, tf)
	check("the high priority", "priority", s.PriorityHigh, tf)
	check("the medium priority", "priority", s.PriorityMedium, tf)
	check("the completed status", "status", s.CompleteStatus, tf)
	check("the note type", "noteType", s.NoteType, nf)
	check("who may see a note", "publish", s.NotePublish, nf)
	if s.SubIssueType != "" {
		ok := false
		for _, v := range tf.Active("subIssueType") {
			if v.Value == s.SubIssueType {
				ok = true
				if v.ParentValue != s.IssueType {
					bad = append(bad, fmt.Sprintf("the sub-issue type (%s) belongs to another issue type than the one chosen", s.SubIssueType))
				}
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("the sub-issue type (%s) is not an active value of Autotask's list any more", s.SubIssueType))
		}
	}
	if s.AutoComplete && s.CompleteStatus == s.Status {
		bad = append(bad, "the completed status is the same as the status of a new ticket")
	}
	return bad
}

func pickInt(v string) (*int64, bool) {
	if v == "" {
		return nil, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, false
	}
	return &n, true
}

// ---- operations and results -------------------------------------------------------------

// Operation kinds.
const (
	OpCreate   = "create"
	OpAdopt    = "adopt"
	OpNote     = "note"
	OpComplete = "complete"
	OpFlag     = "flag"
)

// Operation statuses.
const (
	OpPlanned  = "planned"  // dry run: this is what would happen
	OpDone     = "done"     // live: it happened
	OpFailed   = "failed"   // live: it was refused or failed; the reason says why
	OpDeferred = "deferred" // over the run's limit; the next run does it
	OpSkipped  = "skipped"  // the run stopped before it
)

// Op is one thing a run did or would do.
type Op struct {
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	GroupKey string `json:"groupKey"`
	Tag      string `json:"tag"`
	Urgency  string `json:"urgency,omitempty"`
	// TicketID is the Autotask ticket (0 until created).
	TicketID     int64  `json:"ticketId,omitempty"`
	TicketNumber string `json:"ticketNumber,omitempty"`
	Title        string `json:"title"`
	// Create is the exact ticket that is or would be created.
	Create *client.TicketCreate `json:"create,omitempty"`
	// Labels name the picklist values of Create, as Autotask's lists give them
	// (only when the run read Autotask).
	Labels map[string]string `json:"labels,omitempty"`
	// Note is the exact note text.
	Note   string `json:"note,omitempty"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
	// Members is how many hosts, assets or accounts the action covers.
	Members int `json:"members,omitempty"`
}

// Result is what a run found and did.
type Result struct {
	Mode string `json:"mode"`
	// Verified is true when the run could read Autotask (company, picklists,
	// existing tickets). A dry run that could not is still shown, marked so.
	Verified       bool     `json:"verified"`
	UnverifiedWhy  string   `json:"unverifiedWhy,omitempty"`
	CompanyName    string   `json:"companyName,omitempty"`
	Problems       []string `json:"problems"`
	Ops            []Op     `json:"ops"`
	Groups         int      `json:"groups"`
	BelowThreshold int      `json:"belowThreshold"`
	Requests       int      `json:"requests"`
	Fingerprint    string   `json:"fingerprint"`
	// Created, Noted, Completed, Failed count the live outcomes (dry run: what is planned).
	Created   int `json:"created"`
	Noted     int `json:"noted"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Deferred  int `json:"deferred"`
	// Flagged counts the tickets that need a person's look (completed in Autotask
	// while their findings are open, or gone from Autotask).
	Flagged int `json:"flagged"`
}

// Status summarises a run for the history: ok, partial (something failed or was
// deferred), or not_run (nothing was attempted: settings incomplete, credentials
// refused, threshold, or a live run without its dry run).
func (r Result) Status() string {
	switch {
	case len(r.Problems) > 0 && len(r.Ops) == 0:
		return "not_run"
	case len(r.Problems) > 0 || r.Failed > 0 || r.Deferred > 0:
		return "partial"
	}
	return "ok"
}

// ---- ports ------------------------------------------------------------------------------

// Desk is the part of the Autotask client the engine uses (*client.Client).
type Desk interface {
	Threshold(ctx context.Context) (client.Threshold, error)
	Company(ctx context.Context, id int64) (client.Company, error)
	TicketFields(ctx context.Context) (client.Fields, error)
	NoteFields(ctx context.Context) (client.Fields, error)
	GetTickets(ctx context.Context, ids []int64) (map[int64]client.Ticket, error)
	FindTickets(ctx context.Context, companyID int64, tag string) ([]client.Ticket, error)
	CreateTicket(ctx context.Context, t client.TicketCreate) (int64, error)
	SetTicketStatus(ctx context.Context, id, status int64) error
	CreateNote(ctx context.Context, n client.NoteCreate) (int64, error)
	Requests() int
}

// Change is one committed ticket action: the tracked row's new state and the
// ledger entry that goes with it, written together.
type Change struct {
	// Action is the ledger action: autotask_ticket_created, autotask_ticket_adopted,
	// autotask_ticket_note_added, autotask_ticket_completed, autotask_ticket_state.
	Action  string
	Tracked Tracked
	Detail  map[string]any
}

// Store is what the engine needs from persistence.
type Store interface {
	// Tracked returns every ticket DefendSec follows.
	Tracked(ctx context.Context) ([]Tracked, error)
	// Commit saves the tracked row and its ledger entry atomically.
	Commit(ctx context.Context, actor string, ch Change) error
	// Evidence says how the members that were open are no longer.
	Evidence(ctx context.Context, refs []MemberRef) (map[MemberRef]Evidence, error)
}
