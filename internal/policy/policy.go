// Package policy decides whether a command may be issued, before it is signed
// (roadmap 2.1).
//
// Placement is the whole design. The engine sits between the API and the
// signer, so a command policy does not permit is never signed at all. That
// makes the constraint cryptographic rather than cosmetic: an attacker who
// bypasses the console, forges a request, or finds a hole in a handler still
// cannot produce a signed envelope an agent will execute, because the agent
// checks the signature and the signature was never created.
//
// A UI that hides a button enforces nothing. An unsigned command is inert.
//
// # Deny by default
//
// Nothing is permitted unless a rule permits it. The alternative — allow
// unless denied — means every capability added later is live from the moment
// it exists, against every host, for everyone, until somebody remembers to
// write a rule. That is how a response tool becomes an outage generator.
//
// An explicit deny always beats an allow, whatever order the rules are in.
// Order-dependent policy is policy nobody can reason about, and a rule added
// at the bottom of a file should never quietly re-enable something a security
// rule above it forbade.
package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Effect is what a decision permits.
type Effect string

const (
	// EffectPermit — the command may be signed.
	EffectPermit Effect = "permit"
	// EffectDeny — the command must not be signed.
	EffectDeny Effect = "deny"
	// EffectRequireApproval — permitted in principle, but not yet: it needs
	// more approvals than it has (roadmap 2.3). Distinct from deny because a
	// denial is final and this is a pending state an operator can resolve.
	EffectRequireApproval Effect = "require-approval"
)

// Request is what the engine is asked about.
type Request struct {
	// Actor is the identity that would authorise the command, in the same
	// form the ledger records: "user:alice", or an unattributed marker.
	Actor string
	// Role is the actor's role.
	Role string
	// CommandType is the command being issued.
	CommandType string
	// DeviceID and Hostname identify the target.
	DeviceID string
	Hostname string
	// HostClasses are the target's tags: production, critical, and so on.
	HostClasses []string
	// At is when the request is being made, used for time windows and rate
	// limits. Passed in rather than read from the clock so decisions are
	// reproducible and testable.
	At time.Time
	// Approvals are the distinct actors who have approved this command,
	// including the one issuing it.
	Approvals []string
	// BreakGlass is set when a time-boxed emergency bypass is in force
	// (roadmap 2.4).
	BreakGlass *BreakGlass
}

// Decision is the engine's answer.
type Decision struct {
	Effect Effect `json:"effect"`
	// RuleID names the rule that decided, or "" when nothing matched and the
	// default denied.
	RuleID string `json:"ruleId,omitempty"`
	// Reason is written for the person who will read it in the ledger months
	// later, not for the developer who wrote the rule.
	Reason string `json:"reason"`
	// RequiredApprovals and HaveApprovals explain a require-approval outcome.
	RequiredApprovals int `json:"requiredApprovals,omitempty"`
	HaveApprovals     int `json:"haveApprovals,omitempty"`
	// PolicyHash identifies the document that produced this decision, so
	// "which policy allowed this?" is answerable from the ledger afterwards
	// rather than from whatever the file says today.
	PolicyHash string `json:"policyHash,omitempty"`
	// PolicyName is the document's name.
	PolicyName string `json:"policyName,omitempty"`
	// Autonomous is true when the permitting rule allows an AI agent to
	// execute without a human approval (roadmap 4.4). Meaningless on any
	// effect other than permit, and false there.
	Autonomous bool `json:"autonomous,omitempty"`
	// BreakGlassUsed records that an emergency bypass carried this decision.
	// It is a separate field rather than a note in Reason because it is the
	// thing an auditor searches for.
	BreakGlassUsed bool `json:"breakGlassUsed,omitempty"`
	// LimitExceeded names the blast-radius limit that stopped this, if any.
	LimitExceeded string `json:"limitExceeded,omitempty"`
}

// Allowed reports whether the command may be signed now.
func (d Decision) Allowed() bool { return d.Effect == EffectPermit }

// BreakGlass is a time-boxed bypass (roadmap 2.4).
type BreakGlass struct {
	ID string `json:"id"`
	// Justification is required. An emergency nobody wrote down is
	// indistinguishable from an abuse afterwards.
	Justification string     `json:"justification"`
	OpenedBy      string     `json:"openedBy"`
	OpenedAt      time.Time  `json:"openedAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	ClosedAt      *time.Time `json:"closedAt,omitempty"`
}

// ActiveAt reports whether the bypass is in force at a moment.
func (b *BreakGlass) ActiveAt(t time.Time) bool {
	if b == nil {
		return false
	}
	if t.Before(b.OpenedAt) || !t.Before(b.ExpiresAt) {
		return false
	}
	return b.ClosedAt == nil || t.Before(*b.ClosedAt)
}

// Usage is how many matching commands have already been issued, supplied by
// the caller so this package stays free of database dependencies.
type Usage struct {
	// FleetCount is the number of matching commands issued fleet-wide inside
	// the limit's window.
	FleetCount int
	// HostCount is the number issued to this host inside the window.
	HostCount int
}

// UsageFunc answers "how many of these have been issued lately".
type UsageFunc func(commandTypes []string, since time.Time, deviceID string) (Usage, error)

// Engine evaluates requests against a document.
type Engine struct {
	doc *Document
}

// NewEngine builds an engine over a validated document.
func NewEngine(doc *Document) *Engine { return &Engine{doc: doc} }

// Document returns the policy in force, for reporting.
func (e *Engine) Document() *Document {
	if e == nil {
		return nil
	}
	return e.doc
}

// Evaluate decides a request.
//
// usage may be nil when no limits need checking; a nil usage with limits
// configured is treated as an error rather than as zero, because reporting
// "under the limit" when the count could not be read would defeat the limit
// exactly when the database is struggling.
func (e *Engine) Evaluate(req Request, usage UsageFunc) (Decision, error) {
	if e == nil || e.doc == nil {
		// No policy loaded is not "allow everything". A deployment with no
		// policy file is unconfigured, and an unconfigured response tool
		// should refuse rather than guess.
		return Decision{
			Effect: EffectDeny,
			Reason: "No policy is loaded, and DefendSec denies by default. Configure DEFENDSEC_POLICY_FILE before issuing commands.",
		}, nil
	}

	d := Decision{PolicyHash: e.doc.Hash, PolicyName: e.doc.Name}

	// Explicit denies are evaluated first and cannot be overridden. A rule
	// added later in a file must never quietly re-enable something a security
	// rule already forbade.
	for _, r := range e.doc.Rules {
		if r.Effect != EffectDeny || !r.matches(req) {
			continue
		}
		d.Effect = EffectDeny
		d.RuleID = r.ID
		d.Reason = r.denyReason(req)
		// Break-glass does not override an explicit deny. A bypass is for
		// reaching something policy has not anticipated, not for doing the
		// one thing policy went out of its way to forbid.
		return d, nil
	}

	var matched *Rule
	for i := range e.doc.Rules {
		r := &e.doc.Rules[i]
		if r.Effect == EffectPermit && r.matches(req) {
			// The strictest matching permit wins: where two rules both allow
			// a command, the one demanding more approvals is the one that was
			// written with more care.
			//
			// On equal approvals, a rule that withholds autonomy beats one
			// that grants it (roadmap 4.4). Autonomy is the most
			// consequential thing a rule can confer, and where the document
			// says two things about the same command the safe reading is the
			// one that keeps a human in the loop. The consequence is worth
			// knowing when writing policy: a broad non-autonomous permit
			// shadows a narrower autonomous one, so autonomy belongs on the
			// only rule matching that command rather than added alongside an
			// existing permit.
			if matched == nil ||
				r.RequireApprovals > matched.RequireApprovals ||
				(r.RequireApprovals == matched.RequireApprovals &&
					matched.Autonomous && !r.Autonomous) {
				matched = r
			}
		}
	}

	breakGlass := req.BreakGlass.ActiveAt(req.At)

	if matched == nil {
		if breakGlass {
			d.Effect = EffectPermit
			d.BreakGlassUsed = true
			d.Reason = fmt.Sprintf(
				"No rule permits %s on this host, but break-glass %s is in force: %q, opened by %s, expires %s.",
				req.CommandType, req.BreakGlass.ID, req.BreakGlass.Justification,
				req.BreakGlass.OpenedBy, req.BreakGlass.ExpiresAt.UTC().Format(time.RFC3339))
			return d, nil
		}
		d.Effect = EffectDeny
		d.Reason = fmt.Sprintf(
			"No rule in policy %q permits %s for role %q on a host classed %s. DefendSec denies by default.",
			e.doc.Name, req.CommandType, req.Role, describeClasses(req.HostClasses))
		return d, nil
	}

	d.RuleID = matched.ID

	// Blast-radius limits (roadmap 2.2). Checked after a rule matches, so a
	// limit report always names a command the policy would otherwise allow.
	if limit, exceeded, err := e.checkLimits(req, usage); err != nil {
		return Decision{}, err
	} else if exceeded != nil {
		if breakGlass {
			d.Effect = EffectPermit
			d.BreakGlassUsed = true
			d.LimitExceeded = limit
			d.Reason = fmt.Sprintf("%s Break-glass %s overrides it: %q.",
				*exceeded, req.BreakGlass.ID, req.BreakGlass.Justification)
			return d, nil
		}
		d.Effect = EffectDeny
		d.LimitExceeded = limit
		d.Reason = *exceeded
		return d, nil
	}

	// Two-person integrity (roadmap 2.3). Approvals are counted as distinct
	// actors: the same person clicking twice is one person.
	if need := matched.RequireApprovals; need > 1 {
		have := countDistinct(req.Approvals)
		if have < need {
			// Break-glass does not satisfy a two-person requirement either.
			// The entire point of that control is that one person cannot act
			// alone, and a bypass one person can open would remove it.
			d.Effect = EffectRequireApproval
			d.RequiredApprovals = need
			d.HaveApprovals = have
			d.Reason = fmt.Sprintf(
				"Rule %q requires %d distinct approvals for %s; %d given. A second administrator must approve before this can be signed.",
				matched.ID, need, req.CommandType, have)
			return d, nil
		}
		d.RequiredApprovals = need
		d.HaveApprovals = have
	}

	d.Effect = EffectPermit
	// Autonomy is carried from the matching rule, never inferred (roadmap
	// 4.4). A caller that wants to act without a human has to be looking at
	// a rule that says so by name.
	d.Autonomous = matched.Autonomous
	if d.Reason == "" {
		d.Reason = fmt.Sprintf("Rule %q permits %s for role %q on %s.",
			matched.ID, req.CommandType, req.Role, describeClasses(req.HostClasses))
	}
	return d, nil
}

// checkLimits returns the id and message of the first limit exceeded.
func (e *Engine) checkLimits(req Request, usage UsageFunc) (string, *string, error) {
	for _, l := range e.doc.Limits {
		if !l.covers(req.CommandType) {
			continue
		}
		if usage == nil {
			// Refusing is the safe direction. Reporting "under the limit"
			// because the count could not be read would disable the limit
			// exactly when the system is least healthy.
			return l.ID, nil, fmt.Errorf(
				"limit %q applies to %s but command usage could not be read", l.ID, req.CommandType)
		}
		u, err := usage(l.Commands, req.At.Add(-l.window), req.DeviceID)
		if err != nil {
			return l.ID, nil, fmt.Errorf("read usage for limit %q: %w", l.ID, err)
		}
		count := u.FleetCount
		scope := "fleet-wide"
		if l.Scope == ScopeHost {
			count = u.HostCount
			scope = "on this host"
		}
		// The limit counts what has already been issued, so the request under
		// consideration is the (count+1)th.
		if count+1 > l.Max {
			msg := fmt.Sprintf(
				"Blast-radius limit %q allows at most %d %s %s per %s; %d have already been issued. This would be number %d.",
				l.ID, l.Max, strings.Join(l.Commands, "/"), scope, l.Per, count, count+1)
			return l.ID, &msg, nil
		}
	}
	return "", nil, nil
}

func countDistinct(actors []string) int {
	seen := map[string]bool{}
	for _, a := range actors {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		seen[a] = true
	}
	return len(seen)
}

func describeClasses(classes []string) string {
	if len(classes) == 0 {
		return "no class"
	}
	c := append([]string(nil), classes...)
	sort.Strings(c)
	return strings.Join(c, ", ")
}
