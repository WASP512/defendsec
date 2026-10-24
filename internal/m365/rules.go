package m365

import (
	"defendsec/internal/controls"
	"defendsec/internal/idposture"
	"fmt"
	"strings"
)

// DefaultFinanceTerms and DefaultSecurityTerms are shared with the other identity
// collectors (internal/idposture).
var (
	DefaultFinanceTerms  = idposture.DefaultFinanceTerms
	DefaultSecurityTerms = idposture.DefaultSecurityTerms
)

// DefaultHidingFolders are the folders a rule's mail disappears into: nobody
// reads them. Names are English; a mailbox in another language names them
// differently, and that is a stated limit.
var DefaultHidingFolders = []string{
	"RSS Feeds", "RSS Subscriptions", "Archive", "Conversation History", "Deleted Items", "Junk Email",
}

// RuleContext is what judging a rule needs besides the rule.
type RuleContext struct {
	// InternalDomains are the domains whose addresses are not "outside": the
	// tenant's own (read from its users' principal names and mail addresses) plus
	// the operator's trusted domains. Lower case.
	InternalDomains map[string]bool
	FinanceTerms    []string
	SecurityTerms   []string
	HidingFolders   []string
}

// DefaultRuleContext returns the default word lists with the given domains.
func DefaultRuleContext(internal map[string]bool, extraFinance []string) RuleContext {
	fin := idposture.WithExtraTerms(extraFinance)
	return RuleContext{
		InternalDomains: internal,
		FinanceTerms:    fin,
		SecurityTerms:   DefaultSecurityTerms,
		HidingFolders:   DefaultHidingFolders,
	}
}

func containsTerm(haystack, term string) bool { return idposture.ContainsTerm(haystack, term) }

// conditionText is one of a rule's conditions with where it is.
type conditionText = idposture.ConditionText

func (r InboxRule) texts() []conditionText {
	var out []conditionText
	add := func(where string, l []string) {
		for _, s := range l {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, conditionText{Where: where, Text: s})
			}
		}
	}
	add("sender", r.SenderContains)
	add("sender", r.FromAddresses)
	add("subject keyword", r.SubjectContains)
	add("body keyword", r.BodyContains)
	add("subject or body keyword", r.BodyOrSubjectContains)
	add("header keyword", r.HeaderContains)
	add("recipient", r.RecipientContains)
	return out
}

// hasMatchConditions: the rule matches on a sender or on words, not only on
// something like importance.
func (r InboxRule) hasMatchConditions() bool { return len(r.texts()) > 0 }

func (r InboxRule) hasAnyCondition() bool {
	return r.hasMatchConditions() || len(r.OtherConditions) > 0
}

type match = idposture.Match

func findTerms(texts []conditionText, terms []string) []match {
	return idposture.FindTerms(texts, terms)
}

func domainOf(addr string) string { return idposture.DomainOf(addr) }

// externalRecipients are the addresses a rule sends mail to outside the
// internal domains. An address with no domain (an Exchange legacy DN) is not
// counted: it is internal addressing.
func (c RuleContext) externalRecipients(r InboxRule) (ext []string, kinds []string) {
	check := func(kind string, l []string) {
		hit := false
		for _, a := range l {
			d := domainOf(a)
			if d == "" || c.InternalDomains[d] {
				continue
			}
			ext = append(ext, a)
			hit = true
		}
		if hit {
			kinds = append(kinds, kind)
		}
	}
	check("forwardTo", r.ForwardTo)
	check("redirectTo", r.RedirectTo)
	check("forwardAsAttachmentTo", r.ForwardAsAttachmentTo)
	return dedupe(ext), kinds
}

func dedupe(l []string) []string { return idposture.Dedupe(l) }

func (c RuleContext) isHidingFolder(name string) bool {
	for _, f := range c.HidingFolders {
		if strings.EqualFold(strings.TrimSpace(name), f) {
			return true
		}
	}
	return false
}

// hideActions lists what the rule does that takes mail out of the owner's sight.
func (c RuleContext) hideActions(r InboxRule) (acts []string, unresolvedMove bool) {
	if r.PermanentDelete {
		acts = append(acts, "permanently deletes the mail")
	}
	if r.Delete {
		acts = append(acts, "moves the mail to Deleted Items")
	}
	if r.MarkAsRead {
		acts = append(acts, "marks the mail as read")
	}
	if r.MoveToFolder != "" {
		switch {
		case r.MoveToFolderName == "":
			unresolvedMove = true
		case c.isHidingFolder(r.MoveToFolderName):
			acts = append(acts, "moves the mail to "+r.MoveToFolderName)
		}
	}
	return acts, unresolvedMove
}

func evidenceOf(r InboxRule, userUPN string) map[string]any {
	cond := map[string]any{}
	put := func(k string, l []string) {
		if len(l) > 0 {
			cond[k] = l
		}
	}
	put("senderContains", r.SenderContains)
	put("fromAddresses", r.FromAddresses)
	put("subjectContains", r.SubjectContains)
	put("bodyContains", r.BodyContains)
	put("bodyOrSubjectContains", r.BodyOrSubjectContains)
	put("headerContains", r.HeaderContains)
	put("recipientContains", r.RecipientContains)
	put("otherConditions", r.OtherConditions)
	act := map[string]any{}
	if r.Delete {
		act["delete"] = true
	}
	if r.PermanentDelete {
		act["permanentDelete"] = true
	}
	if r.MarkAsRead {
		act["markAsRead"] = true
	}
	if r.MoveToFolder != "" {
		m := map[string]any{"folderId": r.MoveToFolder}
		if r.MoveToFolderName != "" {
			m["folderName"] = r.MoveToFolderName
		} else {
			m["folderName"] = "not resolved"
		}
		act["moveToFolder"] = m
	}
	if r.CopyToFolder != "" {
		act["copyToFolder"] = r.CopyToFolder
	}
	put2 := func(k string, l []string) {
		if len(l) > 0 {
			act[k] = l
		}
	}
	put2("forwardTo", r.ForwardTo)
	put2("redirectTo", r.RedirectTo)
	put2("forwardAsAttachmentTo", r.ForwardAsAttachmentTo)
	put2("otherActions", r.OtherActions)
	return map[string]any{
		"mailbox":    userUPN,
		"ruleId":     r.ID,
		"ruleName":   r.Name,
		"sequence":   r.Sequence,
		"enabled":    r.Enabled,
		"hasError":   r.HasError,
		"conditions": cond,
		"actions":    act,
	}
}

func conditionSummary(r InboxRule) string {
	if !r.hasAnyCondition() {
		return "every incoming message"
	}
	var parts []string
	add := func(label string, l []string) {
		if len(l) > 0 {
			parts = append(parts, label+" "+quoteList(l))
		}
	}
	add("from", append(append([]string{}, r.SenderContains...), r.FromAddresses...))
	add("with a subject containing", r.SubjectContains)
	add("with a body containing", r.BodyContains)
	add("with a subject or body containing", r.BodyOrSubjectContains)
	add("with a header containing", r.HeaderContains)
	add("addressed to", r.RecipientContains)
	if len(r.OtherConditions) > 0 {
		parts = append(parts, "other conditions ("+strings.Join(r.OtherConditions, ", ")+")")
	}
	return "mail " + strings.Join(parts, " and ")
}

func quoteList(l []string) string { return idposture.QuoteList(l) }

func termList(ms []match) string { return idposture.TermList(ms) }

const ruleFix = "Ask the mailbox owner whether they made this rule. If they did not, treat the account as possibly compromised: reset the password, sign the user out of every session, review recent sign-ins and the sent items for payment requests, remove the rule, and look for other rules and forwarding on the mailbox. " +
	"To review rules: Outlook, Home > Rules > Manage Rules & Alerts, or Outlook on the web, Settings > Mail > Rules. If the rule is legitimate, nothing needs doing and it can be left as is."

// AnalyzeRule judges one inbox rule. It returns no finding for a rule that
// neither sends mail outside nor hides it. At most one finding per rule: a rule
// that forwards outside and hides is one finding, worded and ranked for both.
func (c RuleContext) AnalyzeRule(u User, r InboxRule) []Finding {
	ext, fwdKinds := c.externalRecipients(r)
	hide, unresolved := c.hideActions(r)
	texts := r.texts()
	finance := findTerms(texts, c.FinanceTerms)
	security := findTerms(texts, c.SecurityTerms)
	label := u.UPN + " · " + r.Name
	subject := u.ID + "/" + r.ID

	capDisabled := func(s Severity) Severity {
		if !r.Enabled && s.Rank() > SevLow.Rank() {
			return SevLow
		}
		return s
	}
	disabledNote := ""
	suffix := ""
	if !r.Enabled {
		disabledNote = " The rule is currently disabled, so it is not acting now; a disabled rule that looks like this is still worth asking about."
		suffix = " (rule is disabled)"
	}
	cond := conditionSummary(r)

	switch {
	case len(ext) > 0:
		sev := SevHigh
		var why []string
		if len(hide) > 0 {
			why = append(why, "it also "+strings.Join(hide, " and ")+", so the owner would not see the original")
			sev = SevCritical
		}
		if len(finance) > 0 {
			why = append(why, "it matches finance terms ("+termList(finance)+")")
			sev = SevCritical
		}
		ev := evidenceOf(r, u.UPN)
		ev["externalRecipients"] = ext
		ev["via"] = fwdKinds
		if len(finance) > 0 {
			ev["financeMatches"] = finance
		}
		detail := fmt.Sprintf("The rule “%s” on %s sends a copy of %s to %s, outside the organisation.", r.Name, u.UPN, cond, strings.Join(ext, ", "))
		if len(why) > 0 {
			detail += " It ranks higher because " + strings.Join(why, " and ") + "."
		}
		detail += " Automatic external forwarding is a common way for an intruder to keep reading a mailbox after a password change; it can also be a deliberate arrangement, which is why DefendSec says \"reachable\" here and not \"compromised\"." + disabledNote
		return []Finding{{
			ID: FindingRuleForward, Subject: subject, SubjectLabel: label,
			Severity: capDisabled(sev),
			Title:    "Inbox rule forwards mail outside the organisation" + suffix,
			Detail:   detail, Fix: ruleFix, Evidence: ev, Controls: tag(controls.SignalM365MailRules),
		}}

	case len(hide) > 0 || (unresolved && len(finance) > 0):
		sev := SevMedium
		var why string
		matches := r.hasMatchConditions()
		switch {
		case len(finance) > 0:
			sev = SevCritical
			why = "its conditions match finance terms (" + termList(finance) + "): this is how a payment-redirection fraud is kept out of sight"
			if len(hide) == 0 {
				// The destination folder is not known: mail is moved somewhere
				// DefendSec cannot name, so it cannot say it is hidden.
				sev = SevHigh
				why = "its conditions match finance terms (" + termList(finance) + ") and moves the mail to a folder DefendSec could not name (see docs/M365.md, Mail.ReadBasic.All), so it cannot tell whether that folder hides it"
			}
		case matches && len(security) > 0:
			sev = SevHigh
			why = "its conditions match security-notice terms (" + termList(security) + "): hiding those would keep a sign-in alert from the owner"
		case !r.hasAnyCondition() && (r.Delete || r.PermanentDelete || hasMove(r, c)):
			sev = SevHigh
			why = "it has no condition, so it acts on every incoming message"
		case matches:
			why = "it acts only on mail matching a sender or keyword, which is how both newsletters filing and fraud hiding look"
		default:
			why = "it has no sender or keyword condition to tell what it hides"
		}
		ev := evidenceOf(r, u.UPN)
		if len(finance) > 0 {
			ev["financeMatches"] = finance
		}
		if len(security) > 0 {
			ev["securityMatches"] = security
		}
		what := strings.Join(hide, ", and ")
		title := "Inbox rule hides mail"
		if len(finance) > 0 {
			title = "Inbox rule hides finance mail"
		}
		if what == "" {
			what = "moves the mail to a folder DefendSec could not name"
		}
		detail := fmt.Sprintf("The rule “%s” on %s acts on %s: it %s. It ranks %s because %s.", r.Name, u.UPN, cond, what, sev, why)
		detail += " Filing rules are normal; this one is worth a question to the owner, not a verdict." + disabledNote
		return []Finding{{
			ID: FindingRuleHides, Subject: subject, SubjectLabel: label,
			Severity: capDisabled(sev),
			Title:    title + suffix,
			Detail:   detail, Fix: ruleFix, Evidence: ev, Controls: tag(controls.SignalM365MailRules),
		}}
	}
	return nil
}

func hasMove(r InboxRule, c RuleContext) bool {
	return r.MoveToFolder != "" && r.MoveToFolderName != "" && c.isHidingFolder(r.MoveToFolderName)
}
