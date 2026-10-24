package gws

import (
	"fmt"
	"strings"

	"defendsec/internal/controls"
	"defendsec/internal/idposture"
)

// RuleContext is what judging a filter or a forwarding setting needs besides it.
type RuleContext struct {
	// InternalDomains are the domains whose addresses are not "outside": the
	// domain's own (read from its users' primary addresses and aliases) plus the
	// operator's trusted domains. Lower case.
	InternalDomains map[string]bool
	FinanceTerms    []string
	SecurityTerms   []string
}

// DefaultRuleContext returns the default word lists with the given domains.
func DefaultRuleContext(internal map[string]bool, extraFinance []string) RuleContext {
	return RuleContext{
		InternalDomains: internal,
		FinanceTerms:    idposture.WithExtraTerms(extraFinance),
		SecurityTerms:   idposture.DefaultSecurityTerms,
	}
}

// Gmail's system label ids, which a filter's actions name. A label id that is not
// one of these (Label_123) is a user label: filing, not hiding.
const (
	labelInbox  = "INBOX"
	labelTrash  = "TRASH"
	labelSpam   = "SPAM"
	labelUnread = "UNREAD"
)

var systemLabels = map[string]bool{
	"INBOX": true, "TRASH": true, "SPAM": true, "UNREAD": true, "STARRED": true, "IMPORTANT": true,
	"SENT": true, "DRAFT": true, "CHAT": true,
}

func hasLabel(l []string, want string) bool {
	for _, s := range l {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// userLabels counts the labels a filter adds that are not Gmail's own or one of its
// inbox categories.
func (f Filter) userLabels() int {
	n := 0
	for _, l := range f.AddLabelIDs {
		if !systemLabels[strings.ToUpper(l)] && !strings.HasPrefix(strings.ToUpper(l), "CATEGORY_") {
			n++
		}
	}
	return n
}

func (f Filter) texts() []idposture.ConditionText {
	var out []idposture.ConditionText
	add := func(where, s string) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, idposture.ConditionText{Where: where, Text: s})
		}
	}
	add("sender", f.From)
	add("recipient", f.To)
	add("subject keyword", f.Subject)
	// A filter's query is Gmail search syntax over words in the message; the words
	// are what the filter acts on, so they are read as keywords.
	add("subject or body keyword", f.Query)
	return out
}

func (f Filter) hasMatchConditions() bool { return len(f.texts()) > 0 }

// otherConditions names the conditions that are not a sender or a word.
func (f Filter) otherConditions() []string {
	var o []string
	if f.NegatedQuery != "" {
		o = append(o, "excludes mail matching a search")
	}
	if f.HasAttachment {
		o = append(o, "has an attachment")
	}
	if f.Size > 0 {
		o = append(o, "size")
	}
	if f.ExcludeChats {
		o = append(o, "excludes chats")
	}
	return o
}

func (f Filter) hasAnyCondition() bool { return f.hasMatchConditions() || len(f.otherConditions()) > 0 }

func (f Filter) conditionSummary() string {
	if !f.hasAnyCondition() {
		return "every incoming message"
	}
	var parts []string
	add := func(label, s string) {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, label+" "+idposture.QuoteList([]string{s}))
		}
	}
	add("from", f.From)
	add("addressed to", f.To)
	add("with a subject containing", f.Subject)
	add("matching the search", f.Query)
	if o := f.otherConditions(); len(o) > 0 {
		parts = append(parts, "other conditions ("+strings.Join(o, ", ")+")")
	}
	return "mail " + strings.Join(parts, " and ")
}

// hideActions lists what the filter does that takes mail out of the owner's sight.
// filing is a filter that only skips the inbox into a label of the user's own: the
// usual way people file mail, which cannot be told from hiding without reading the
// label's name.
func (f Filter) hideActions() (acts []string, filing bool) {
	trash := hasLabel(f.AddLabelIDs, labelTrash)
	spam := hasLabel(f.AddLabelIDs, labelSpam)
	read := hasLabel(f.RemoveLabelIDs, labelUnread)
	skip := hasLabel(f.RemoveLabelIDs, labelInbox)
	if trash {
		acts = append(acts, "moves the mail to Trash")
	}
	if spam {
		acts = append(acts, "moves the mail to Spam")
	}
	if read {
		acts = append(acts, "marks the mail as read")
	}
	if skip {
		if f.userLabels() > 0 && !trash && !spam && !read {
			return nil, true
		}
		acts = append(acts, "skips the inbox (archives the mail)")
	}
	return acts, false
}

func (f Filter) evidence(userEmail string) map[string]any {
	cond := map[string]any{}
	put := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			cond[k] = v
		}
	}
	put("from", f.From)
	put("to", f.To)
	put("subject", f.Subject)
	put("query", f.Query)
	put("negatedQuery", f.NegatedQuery)
	if f.HasAttachment {
		cond["hasAttachment"] = true
	}
	if f.ExcludeChats {
		cond["excludeChats"] = true
	}
	if f.Size > 0 {
		cond["size"] = f.Size
	}
	act := map[string]any{}
	if len(f.AddLabelIDs) > 0 {
		act["addLabelIds"] = f.AddLabelIDs
	}
	if len(f.RemoveLabelIDs) > 0 {
		act["removeLabelIds"] = f.RemoveLabelIDs
	}
	if f.Forward != "" {
		act["forward"] = f.Forward
	}
	return map[string]any{"mailbox": userEmail, "filterId": f.ID, "criteria": cond, "actions": act}
}

// isExternal reports whether an address is outside the internal domains. An address
// with no domain is not counted.
func (c RuleContext) isExternal(addr string) bool {
	d := idposture.DomainOf(strings.TrimSpace(addr))
	return d != "" && !c.InternalDomains[d]
}

const filterFix = "Ask the mailbox owner whether they made this filter. If they did not, treat the account as possibly compromised: reset the password, sign the user out of every session, review recent sign-ins and the sent mail for payment requests, remove the filter, and look for other filters and forwarding on the mailbox. " +
	"To review: in Gmail, Settings (gear) > See all settings > Filters and Blocked Addresses, and Forwarding and POP/IMAP. If the filter is legitimate, nothing needs doing and it can be left as is."

// AnalyzeFilter judges one Gmail filter. It returns no finding for a filter that
// neither sends mail outside nor hides it. At most one finding per filter: one that
// forwards outside and hides is one finding, worded and ranked for both.
func (c RuleContext) AnalyzeFilter(u User, f Filter) []Finding {
	external := f.Forward != "" && c.isExternal(f.Forward)
	hide, filing := f.hideActions()
	texts := f.texts()
	finance := idposture.FindTerms(texts, c.FinanceTerms)
	security := idposture.FindTerms(texts, c.SecurityTerms)
	cond := f.conditionSummary()
	label := u.Email + " · filter on " + shorten(cond, 60)
	subject := u.ID + "/" + f.ID

	switch {
	case external:
		sev := SevHigh
		var why []string
		if len(hide) > 0 {
			why = append(why, "it also "+strings.Join(hide, " and ")+", so the owner would not see the original")
			sev = SevCritical
		}
		if len(finance) > 0 {
			why = append(why, "it matches finance terms ("+idposture.TermList(finance)+")")
			sev = SevCritical
		}
		ev := f.evidence(u.Email)
		ev["externalRecipients"] = []string{f.Forward}
		if len(finance) > 0 {
			ev["financeMatches"] = finance
		}
		detail := fmt.Sprintf("A filter on %s forwards %s to %s, outside the organisation.", u.Email, cond, f.Forward)
		if len(why) > 0 {
			detail += " It ranks higher because " + strings.Join(why, " and ") + "."
		}
		detail += " A filter that forwards mail is a common way for an intruder to keep reading a mailbox after a password change; it can also be a deliberate arrangement, which is why DefendSec says \"reachable\" here and not \"compromised\"."
		return []Finding{{
			ID: FindingFilterForward, Subject: subject, SubjectLabel: label, Severity: sev,
			Title:  "Gmail filter forwards mail outside the organisation",
			Detail: detail, Fix: filterFix, Evidence: ev, Controls: tag(controls.SignalGWSMailFilters),
		}}

	case len(hide) > 0 || (filing && len(finance) > 0):
		sev := SevMedium
		var why string
		matches := f.hasMatchConditions()
		switch {
		case len(finance) > 0:
			sev = SevCritical
			why = "its conditions match finance terms (" + idposture.TermList(finance) + "): this is how a payment-redirection fraud is kept out of sight"
			if len(hide) == 0 {
				// It files the mail under a label of the user's own: DefendSec does not
				// read label names, so it cannot say the label hides it.
				sev = SevHigh
				why = "its conditions match finance terms (" + idposture.TermList(finance) + ") and it skips the inbox into a label of the user's own that DefendSec cannot name, so it cannot tell whether that label hides it"
			}
		case matches && len(security) > 0:
			sev = SevHigh
			why = "its conditions match security-notice terms (" + idposture.TermList(security) + "): hiding those would keep a sign-in alert from the owner"
		case !f.hasAnyCondition() && (hasLabel(f.AddLabelIDs, labelTrash) || hasLabel(f.AddLabelIDs, labelSpam) || hasLabel(f.RemoveLabelIDs, labelInbox)):
			sev = SevHigh
			why = "it has no condition, so it acts on every incoming message"
		case matches:
			why = "it acts only on mail matching a sender or keyword, which is how both filing newsletters and fraud hiding look"
		default:
			why = "it has no sender or keyword condition to tell what it hides"
		}
		ev := f.evidence(u.Email)
		if len(finance) > 0 {
			ev["financeMatches"] = finance
		}
		if len(security) > 0 {
			ev["securityMatches"] = security
		}
		what := strings.Join(hide, ", and ")
		title := "Gmail filter hides mail"
		if len(finance) > 0 {
			title = "Gmail filter hides finance mail"
		}
		if what == "" {
			what = "skips the inbox into a label DefendSec could not name"
		}
		detail := fmt.Sprintf("A filter on %s acts on %s: it %s. It ranks %s because %s. Filing filters are normal; this one is worth a question to the owner, not a verdict.", u.Email, cond, what, sev, why)
		return []Finding{{
			ID: FindingFilterHides, Subject: subject, SubjectLabel: label, Severity: sev, Title: title,
			Detail: detail, Fix: filterFix, Evidence: ev, Controls: tag(controls.SignalGWSMailFilters),
		}}
	}
	return nil
}

// AnalyzeAutoForwarding judges a mailbox's auto-forwarding setting. Forwarding all
// mail to an address outside the organisation is high; it is critical when Gmail
// also removes the original from the owner's inbox (archive, trash, mark as read).
func (c RuleContext) AnalyzeAutoForwarding(u User, a AutoForwarding) []Finding {
	if !a.Enabled || strings.TrimSpace(a.EmailAddress) == "" || !c.isExternal(a.EmailAddress) {
		return nil
	}
	sev := SevHigh
	disp := a.Disposition
	var after string
	switch disp {
	case "archive":
		sev, after = SevCritical, "then archives the original, so the owner no longer sees it in the inbox"
	case "trash":
		sev, after = SevCritical, "then moves the original to Trash, so the owner would not see it"
	case "markRead":
		sev, after = SevCritical, "and marks the original as read, so the owner is not prompted to look at it"
	case "leaveInInbox":
		after = "and leaves the original in the inbox"
	default:
		after = "and leaves the original as Gmail's setting says (" + nonEmpty(disp, "not stated") + ")"
	}
	detail := fmt.Sprintf("Gmail on %s forwards every incoming message to %s, outside the organisation, %s. Automatic forwarding is a common way for an intruder to keep reading a mailbox after a password change; it can also be a deliberate arrangement, which is why DefendSec says \"reachable\" here and not \"compromised\".", u.Email, a.EmailAddress, after)
	return []Finding{{
		ID: FindingAutoForward, Subject: u.ID + "/autoforward", SubjectLabel: u.Email + " · automatic forwarding", Severity: sev,
		Title:  "Gmail forwards all of a user's mail outside the organisation",
		Detail: detail, Fix: filterFix,
		Evidence: map[string]any{"mailbox": u.Email, "enabled": true, "emailAddress": a.EmailAddress, "disposition": disp, "externalRecipients": []string{a.EmailAddress}},
		Controls: tag(controls.SignalGWSMailFilters),
	}}
}

func nonEmpty(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

// shorten cuts s to at most n runes, with an ellipsis.
func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
