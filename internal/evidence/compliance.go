package evidence

import (
	"fmt"
	"sort"
	"time"

	"defendsec/internal/controls"
)

// Control-scoped evidence (roadmap 1.9, §3.6 item 4).
//
// A bundle can carry a compliance assessment alongside the cryptographic
// proof, so an export can be scoped to a control or a framework rather than
// only to a host or an incident.
//
// # What is and is not proven
//
// The chain, the checkpoints and the command signatures verify on their own.
// An assessment does not: it is derived partly from alerts, which are not
// chained, so a bundle carrying one would otherwise place an unverifiable
// claim next to verifiable ones — the exact confusion the chain exists to
// remove.
//
// So the assessment is carried with its provenance made explicit, and the one
// part that *can* be checked is checked. Audit-entry counts are recomputed
// from the bundle's own chain entries, because a record's control tag is a
// pure function of its action and the action is hashed. A tampered count is
// therefore detected. Alert and command counts are marked as derived from
// records outside the chain, and Verify says so rather than implying they
// carry the same weight.

// ControlSummary is one control's outcome, flattened for the bundle.
type ControlSummary struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Coverage string `json:"coverage"`
	Status   string `json:"status"`
	// Statement is the sentence an assessor reads.
	Statement string `json:"statement"`
	Note      string `json:"note,omitempty"`

	// AuditEntries is recomputed and checked by Verify.
	AuditEntries int `json:"auditEntries"`
	// Alerts, OpenAtEnd and Commands come from records outside the chain and
	// are not independently verifiable from this bundle.
	Alerts    int `json:"alerts"`
	OpenAtEnd int `json:"openAtEnd"`
	Commands  int `json:"commands"`

	Exceptions []ExceptionRecord `json:"exceptions,omitempty"`
}

// ExceptionRecord is a documented acceptance, carried so an assessor reading
// the bundle offline sees the same accepted deficiencies the console shows.
type ExceptionRecord struct {
	ID          string     `json:"id"`
	Reason      string     `json:"reason"`
	Remediation string     `json:"remediation,omitempty"`
	Owner       string     `json:"owner,omitempty"`
	OpenedAt    time.Time  `json:"openedAt"`
	OpenedBy    string     `json:"openedBy,omitempty"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	ClosedAt    *time.Time `json:"closedAt,omitempty"`
}

// ComplianceScope is the assessment a bundle carries.
type ComplianceScope struct {
	Framework      string    `json:"framework"`
	FrameworkTitle string    `json:"frameworkTitle"`
	PeriodID       string    `json:"periodId,omitempty"`
	PeriodName     string    `json:"periodName,omitempty"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`

	Controls []ControlSummary `json:"controls"`
	Caveats  []string         `json:"caveats,omitempty"`

	// Provenance is stated in the bundle itself, not only in documentation,
	// because a bundle is read by people who will never see the docs.
	Provenance string `json:"provenance"`
}

// ComplianceProvenance is the sentence every scoped bundle carries.
const ComplianceProvenance = "Audit-entry counts are recomputed from this bundle's chained entries and are verified. " +
	"Alert and command counts are derived from records that are not part of the hash chain and cannot be verified from this bundle alone. " +
	"The assessment is a reading of those records, not a cryptographic claim."

// auditCountsByControl recomputes per-control audit-entry counts from the
// bundle's own chain entries, bounded to a window.
//
// This is the recomputation Verify compares against. It works because the tag
// is a pure function of the action, which the chain hashes: an attacker who
// edits an entry breaks the chain, and one who edits only the summary is
// caught here.
func (b *Bundle) auditCountsByControl(from, to time.Time) map[string]int {
	out := map[string]int{}
	for _, e := range b.Audit {
		if e.At.Before(from) || !e.At.Before(to) {
			continue
		}
		for _, id := range controls.TagAuditAction(e.Action) {
			out[id]++
		}
	}
	return out
}

// verifyCompliance checks the part of a scoped assessment that can be checked.
func (b *Bundle) verifyCompliance() []string {
	c := b.Compliance
	if c == nil {
		return nil
	}

	var problems []string
	if c.Provenance != ComplianceProvenance {
		// A bundle whose provenance note was edited is a bundle trying to
		// present derived numbers as proven ones.
		problems = append(problems, "the compliance section's provenance statement does not match the expected text")
	}
	if !c.To.After(c.From) {
		problems = append(problems, "the compliance window ends before it starts")
	}

	// The recomputation is only sound if no chained entry inside the window is
	// missing from the bundle. Exactly one side of that is decidable from the
	// bundle alone.
	//
	// If the window starts before the bundle's first entry and the bundle does
	// not begin at the start of the chain, entries inside the window are
	// missing and the counts below are understated. That is caught here.
	//
	// The other side is not decidable: a window ending after the bundle's last
	// entry may mean the tail was withheld, or simply that nothing happened
	// since. The bundle cannot tell, so Verify does not pretend to — the
	// checkpoint verification is what makes a withheld tail detectable, and it
	// runs separately.
	if len(b.Audit) > 0 {
		first := b.Audit[0].At
		startsAtChainBeginning := b.Manifest.FromSeq <= 1 || b.Manifest.PrevHash == ""
		if c.From.Before(first) && !startsAtChainBeginning {
			problems = append(problems, fmt.Sprintf(
				"the compliance window starts at %s, before this bundle's first audit entry at %s, and the bundle does not begin at the start of the chain — entries inside the window are missing",
				c.From.Format(time.RFC3339), first.Format(time.RFC3339)))
		}
	} else if len(c.Controls) > 0 {
		problems = append(problems, "the bundle carries a compliance assessment but no audit entries to support it")
	}

	recomputed := b.auditCountsByControl(c.From, c.To)
	for _, cs := range c.Controls {
		if got := recomputed[cs.ID]; got != cs.AuditEntries {
			problems = append(problems, fmt.Sprintf(
				"control %s claims %d audit entries, but %d are present in the chain",
				cs.ID, cs.AuditEntries, got))
		}
	}
	return problems
}

// SortControlSummaries orders summaries stably, because a bundle's bytes
// should not change for reasons that are not substantive.
func SortControlSummaries(cs []ControlSummary) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
}
