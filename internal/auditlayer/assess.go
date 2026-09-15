// Package auditlayer turns tagged records into the sentence an assessor needs:
// whether a control held across a period, what the evidence was, and what the
// exceptions were (roadmap 1.9, §3.9).
//
// This is a layer, not a pivot. It maps what DefendSec already observes to
// control identifiers and reports per-control status with the evidence behind
// it. It is not a GRC platform: there is no policy document management, no
// approval routing, no risk register and no questionnaire engine. The moment
// those arrive, the signed action channel stops being the product.
//
// # The distinction the whole layer turns on
//
// "DefendSec cannot evidence this control" and "DefendSec can evidence this
// control and saw nothing" are completely different facts that look identical
// in every compliance dashboard that reports a green tick or a percentage.
// The first is a scope boundary the agency has to cover another way. The
// second usually means a check never ran — which is a failure being reported
// as a pass. They are separate statuses here, and neither is ever rendered as
// satisfied.
package auditlayer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"defendsec/internal/controls"
)

// Status is a control's outcome over a period.
type Status string

const (
	// StatusSatisfied — DefendSec produced evidence across the period and
	// nothing was outstanding at the end of it.
	StatusSatisfied Status = "satisfied"
	// StatusDeficient — findings tagged to this control were still open when
	// the period closed.
	StatusDeficient Status = "deficient"
	// StatusExcepted — deficient, but a documented, time-limited exception
	// covers it. This is not a pass; it is a deficiency somebody accepted in
	// writing, and it is rendered as its own thing so it cannot be mistaken
	// for one.
	StatusExcepted Status = "excepted"
	// StatusNoEvidence — DefendSec can evidence this control, and produced
	// nothing in the window. Usually this means the check never ran. It is
	// never a pass, because silence is not evidence.
	StatusNoEvidence Status = "no-evidence"
	// StatusNotEvidenced — DefendSec cannot evidence this control at all.
	// The agency has to cover it another way; the catalog says how.
	StatusNotEvidenced Status = "not-evidenced"
)

// Period is the window under review.
type Period struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Framework string     `json:"framework"`
	StartsAt  time.Time  `json:"startsAt"`
	EndsAt    time.Time  `json:"endsAt"`
	Notes     string     `json:"notes,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy string     `json:"createdBy,omitempty"`
	ClosedAt  *time.Time `json:"closedAt,omitempty"`
	ClosedBy  string     `json:"closedBy,omitempty"`
}

// Closed reports whether the period has been declared final.
func (p Period) Closed() bool { return p.ClosedAt != nil }

// Exception is a documented, time-limited acceptance of a deficiency.
type Exception struct {
	ID          string     `json:"id"`
	ControlID   string     `json:"controlId"`
	PeriodID    string     `json:"periodId,omitempty"`
	Reason      string     `json:"reason"`
	Remediation string     `json:"remediation,omitempty"`
	Owner       string     `json:"owner,omitempty"`
	OpenedAt    time.Time  `json:"openedAt"`
	OpenedBy    string     `json:"openedBy,omitempty"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	ClosedAt    *time.Time `json:"closedAt,omitempty"`
	ClosedBy    string     `json:"closedBy,omitempty"`
}

// ActiveAt reports whether the exception was in force at a moment. An expired
// exception stops covering a deficiency; that is what makes it time-limited
// rather than a permanent excuse.
func (e Exception) ActiveAt(t time.Time) bool {
	if t.Before(e.OpenedAt) || !t.Before(e.ExpiresAt) {
		return false
	}
	return e.ClosedAt == nil || t.Before(*e.ClosedAt)
}

// Evidence is what DefendSec recorded for a control during the period.
type Evidence struct {
	Alerts int `json:"alerts"`
	// OpenAlerts is how many findings are open now.
	OpenAlerts int `json:"openAlerts"`
	// OpenAtEnd is how many were still open when the window closed, which is
	// what a finished period is judged on. It is reconstructed rather than
	// recorded; see storepg.ControlRecordCounts for exactly how, and the
	// assessment's caveats for what that costs.
	OpenAtEnd    int `json:"openAtEnd"`
	Commands     int `json:"commands"`
	AuditEntries int `json:"auditEntries"`
}

// Any reports whether anything at all was recorded.
func (e Evidence) Any() bool {
	return e.Alerts > 0 || e.Commands > 0 || e.AuditEntries > 0
}

// ControlStatus is one control's outcome, with everything behind it.
type ControlStatus struct {
	Control  controls.Control `json:"control"`
	Status   Status           `json:"status"`
	Evidence Evidence         `json:"evidence"`
	// Qualified is set when the catalog says DefendSec evidences this control
	// only in part. A qualified satisfied is still not a full pass, and the
	// control's own note says which part is missing.
	Qualified  bool        `json:"qualified"`
	Exceptions []Exception `json:"exceptions,omitempty"`
	// Statement is the sentence an assessor reads. It is generated from the
	// same numbers shown alongside it, so it cannot drift from them.
	Statement string `json:"statement"`
}

// Assessment is a whole framework over a period.
type Assessment struct {
	Framework   string          `json:"framework"`
	Title       string          `json:"title"`
	Period      Period          `json:"period"`
	Controls    []ControlStatus `json:"controls"`
	Counts      map[Status]int  `json:"counts"`
	GeneratedAt time.Time       `json:"generatedAt"`
	// Caveats are the things a reader must know before believing any of it.
	Caveats []string `json:"caveats"`
}

// Input is everything Assess needs, gathered by the caller so this package
// stays free of database and clock dependencies and can be tested exhaustively.
type Input struct {
	Framework  controls.Framework
	Period     Period
	Evidence   map[string]Evidence
	Exceptions []Exception
	// Now is when the assessment is being produced. For a period that has not
	// finished yet, it bounds "at the end of the period" to the present.
	Now time.Time
}

// Assess produces the per-control status for a framework over a period.
func Assess(in Input) Assessment {
	// A period still running cannot be judged at its own end date, so the
	// deficiency check is made at whichever comes first.
	asOf := in.Period.EndsAt
	if in.Now.Before(asOf) {
		asOf = in.Now
	}

	byControl := map[string][]Exception{}
	for _, e := range in.Exceptions {
		byControl[e.ControlID] = append(byControl[e.ControlID], e)
	}

	out := Assessment{
		Framework:   string(in.Framework),
		Title:       controls.FrameworkTitle(in.Framework),
		Period:      in.Period,
		Counts:      map[Status]int{},
		GeneratedAt: in.Now,
	}

	for _, c := range controls.ForFramework(in.Framework) {
		cs := ControlStatus{
			Control:    c,
			Evidence:   in.Evidence[string(c.ID)],
			Exceptions: byControl[string(c.ID)],
			Qualified:  c.Coverage == controls.CoveragePartial,
		}
		sort.Slice(cs.Exceptions, func(i, j int) bool {
			return cs.Exceptions[i].OpenedAt.Before(cs.Exceptions[j].OpenedAt)
		})

		switch {
		case c.Coverage == controls.CoverageNone:
			// Never anything else, whatever records happen to carry the tag.
			// Claiming a pass on a control DefendSec cannot see is the single
			// most damaging thing a compliance view can do.
			cs.Status = StatusNotEvidenced

		case cs.Evidence.OpenAtEnd > 0:
			cs.Status = StatusDeficient
			for _, e := range cs.Exceptions {
				if e.ActiveAt(asOf) {
					cs.Status = StatusExcepted
					break
				}
			}

		case !cs.Evidence.Any():
			cs.Status = StatusNoEvidence

		default:
			cs.Status = StatusSatisfied
		}

		cs.Statement = statement(cs, in.Period, asOf)
		out.Controls = append(out.Controls, cs)
		out.Counts[cs.Status]++
	}

	out.Caveats = caveats(out)
	return out
}

// statement writes the sentence, from the same numbers rendered beside it.
func statement(cs ControlStatus, p Period, asOf time.Time) string {
	window := fmt.Sprintf("%s to %s",
		p.StartsAt.UTC().Format("2006-01-02"), p.EndsAt.UTC().Format("2006-01-02"))

	switch cs.Status {
	case StatusNotEvidenced:
		return "DefendSec cannot evidence this control. " + cs.Control.Note

	case StatusNoEvidence:
		return fmt.Sprintf(
			"No evidence was recorded in the window %s. DefendSec can evidence this control, so an empty window usually means the check did not run — it is not a pass.",
			window)

	case StatusDeficient:
		return fmt.Sprintf(
			"%s recorded in the window %s, of which %s still open as of %s. No documented exception covers this.",
			plural(cs.Evidence.Alerts, "finding was", "findings were"),
			window, plural(cs.Evidence.OpenAtEnd, "finding is", "findings are"),
			asOf.UTC().Format("2006-01-02"))

	case StatusExcepted:
		var reasons []string
		for _, e := range cs.Exceptions {
			if e.ActiveAt(asOf) {
				reasons = append(reasons, fmt.Sprintf("%s (expires %s)",
					e.Reason, e.ExpiresAt.UTC().Format("2006-01-02")))
			}
		}
		return fmt.Sprintf(
			"%s still open as of %s, covered by a documented exception: %s. This is an accepted deficiency, not a satisfied control.",
			plural(cs.Evidence.OpenAtEnd, "finding is", "findings are"),
			asOf.UTC().Format("2006-01-02"), strings.Join(reasons, "; "))

	default:
		base := fmt.Sprintf(
			"Held continuously across the window %s: %d signed actions, %d ledger entries and %d findings recorded, none outstanding at the close of the window.",
			window, cs.Evidence.Commands, cs.Evidence.AuditEntries, cs.Evidence.Alerts)
		if cs.Qualified {
			return base + " DefendSec evidences this control only in part — " + cs.Control.Note
		}
		return base
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// caveats are what a reader must know before believing the numbers above.
// They are generated rather than written into a template, so they cannot
// describe a report other than the one they are attached to.
func caveats(a Assessment) []string {
	out := []string{
		"Statuses describe what DefendSec observed. A control can be satisfied here and still fail an assessment for reasons outside what an agent can see.",
	}
	if n := a.Counts[StatusNotEvidenced]; n > 0 {
		out = append(out, fmt.Sprintf(
			"%d of %d controls cannot be evidenced by DefendSec at all. Each says why, and each has to be covered another way.",
			n, len(a.Controls)))
	}
	if n := a.Counts[StatusNoEvidence]; n > 0 {
		out = append(out, fmt.Sprintf(
			"%d controls produced no records in this window. Confirm the relevant checks actually ran before treating any of them as met.",
			n))
	}
	if n := a.Counts[StatusExcepted]; n > 0 {
		out = append(out, fmt.Sprintf(
			"%d controls are covered by documented exceptions. Those are accepted deficiencies and an assessor will ask about every one.",
			n))
	}
	var qualified int
	for _, c := range a.Controls {
		if c.Qualified && c.Status == StatusSatisfied {
			qualified++
		}
	}
	if qualified > 0 {
		out = append(out, fmt.Sprintf(
			"%d satisfied controls are only partly within DefendSec's scope. Read each control's note for the part it does not cover.",
			qualified))
	}
	var deficient int
	for _, c := range a.Controls {
		if c.Status == StatusDeficient || c.Status == StatusExcepted {
			deficient++
		}
	}
	if deficient > 0 {
		out = append(out,
			"Whether a finding was still open at the close of the window is reconstructed from its current status and the time it last changed, not from a stored transition history. That is exact unless a finding was resolved inside the window and reopened after it.")
	}
	out = append(out,
		"No coverage percentage is given on purpose. A percentage lets a control nobody has looked at disappear into a rounding error.")
	return out
}
