package m365

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContainsTermMatchesWholeWordsOnly(t *testing.T) {
	cases := []struct {
		hay, term string
		want      bool
	}{
		{"ACH payment", "ach", true},
		{"reach out", "ach", false},
		{"each one", "ach", false},
		{"wire transfer", "wire", true},
		{"wireless", "wire", false},
		{"quickbooks@intuit.com", "intuit", true},
		{"quickbooks@intuit.com", "quickbooks", true},
		{"no-reply@intuit.com", "intuit.com", true},
		{"Invoice #123", "invoice", true},
		{"invoices", "invoice", false}, // a different word: the list carries the forms that matter
		{"remittance advice", "REMITTANCE", true},
		{"Purchase  Order", "purchase order", false}, // whitespace is not normalised: a rule typed that way is rare
		{"new purchase order 5", "purchase order", true},
		{"bill.com", "bill.com", true},
		{"bank", "bank", true},
		{"embankment", "bank", false},
		{"", "bank", false},
		{"anything", "", false},
	}
	for _, c := range cases {
		if got := containsTerm(c.hay, c.term); got != c.want {
			t.Errorf("containsTerm(%q, %q) = %v, want %v", c.hay, c.term, got, c.want)
		}
	}
}

func ctx(domains ...string) RuleContext {
	in := map[string]bool{}
	for _, d := range domains {
		in[d] = true
	}
	return DefaultRuleContext(in, nil)
}

var casey = User{ID: "u-casey", UPN: "casey@example.com", DisplayName: "Casey Example"}

func rule(mod func(*InboxRule)) InboxRule {
	r := InboxRule{ID: "r1", Name: "A rule", Enabled: true}
	mod(&r)
	return r
}

func one(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	return fs[0]
}

// The AMP lesson: a rule that moves every QuickBooks/Intuit message to an RSS
// folder, so payment-redirection fraud never reaches the owner's eyes.
func TestAMPLikeRuleIsCritical(t *testing.T) {
	r := rule(func(r *InboxRule) {
		r.Name = "Intuit stuff"
		r.SenderContains = []string{"quickbooks", "intuit.com"}
		r.MarkAsRead = true
		r.MoveToFolder = "AAMk-rss"
		r.MoveToFolderName = "RSS Feeds"
	})
	f := one(t, ctx("example.com").AnalyzeRule(casey, r))
	if f.ID != FindingRuleHides || f.Severity != SevCritical {
		t.Fatalf("finding = %s %s, want %s critical", f.ID, f.Severity, FindingRuleHides)
	}
	if f.Subject != "u-casey/r1" || f.SubjectLabel != "casey@example.com · Intuit stuff" {
		t.Errorf("subject = %q label = %q", f.Subject, f.SubjectLabel)
	}
	if !strings.Contains(f.Title, "finance") {
		t.Errorf("title %q does not say finance mail", f.Title)
	}
	for _, want := range []string{"quickbooks", "RSS Feeds", "marks the mail as read", "possibly compromised"} {
		if !strings.Contains(f.Detail+f.Fix, want) {
			t.Errorf("detail+fix lacks %q: %s", want, f.Detail)
		}
	}
	ev, _ := json.Marshal(f.Evidence)
	for _, want := range []string{"Intuit stuff", "senderContains", "RSS Feeds", "financeMatches"} {
		if !strings.Contains(string(ev), want) {
			t.Errorf("evidence lacks %q: %s", want, ev)
		}
	}
	// Reachable, not compromised: the detail must not claim a verdict.
	if strings.Contains(strings.ToLower(f.Detail), "hacked") || strings.Contains(strings.ToLower(f.Detail), "is compromised") {
		t.Errorf("the detail claims a verdict: %s", f.Detail)
	}
}

func TestHidingRuleSeverityLadder(t *testing.T) {
	rc := ctx("example.com")
	cases := []struct {
		name string
		mod  func(*InboxRule)
		want Severity // "" = no finding
	}{
		{"finance sender, deletes", func(r *InboxRule) { r.SenderContains = []string{"intuit"}; r.Delete = true }, SevCritical},
		{"finance keyword in subject, permanently deletes", func(r *InboxRule) { r.SubjectContains = []string{"wire transfer"}; r.PermanentDelete = true }, SevCritical},
		{"finance in body-or-subject, archive", func(r *InboxRule) {
			r.BodyOrSubjectContains = []string{"ACH"}
			r.MoveToFolder, r.MoveToFolderName = "f", "Archive"
		}, SevCritical},
		{"finance, moves to a folder that could not be named", func(r *InboxRule) {
			r.SenderContains = []string{"quickbooks"}
			r.MoveToFolder = "f"
		}, SevHigh},
		{"finance, moves to an ordinary folder", func(r *InboxRule) {
			r.SenderContains = []string{"quickbooks"}
			r.MoveToFolder, r.MoveToFolderName = "f", "Accounting"
		}, ""},
		{"security notice, hidden", func(r *InboxRule) {
			r.SubjectContains = []string{"Security Alert"}
			r.MoveToFolder, r.MoveToFolderName = "f", "Conversation History"
		}, SevHigh},
		{"no condition, deletes everything", func(r *InboxRule) { r.Delete = true }, SevHigh},
		{"no condition, everything to deleted items folder name", func(r *InboxRule) { r.MoveToFolder, r.MoveToFolderName = "f", "Deleted Items" }, SevHigh},
		{"no condition, only marks read", func(r *InboxRule) { r.MarkAsRead = true }, SevMedium},
		{"newsletter sender, junk", func(r *InboxRule) {
			r.SenderContains = []string{"news@example.org"}
			r.MoveToFolder, r.MoveToFolderName = "f", "Junk Email"
		}, SevMedium},
		{"other condition only, deletes", func(r *InboxRule) { r.OtherConditions = []string{"hasAttachments"}; r.Delete = true }, SevMedium},
		{"newsletter sender, ordinary folder", func(r *InboxRule) {
			r.SenderContains = []string{"news@example.org"}
			r.MoveToFolder, r.MoveToFolderName = "f", "Newsletters"
		}, ""},
		{"sets a category only", func(r *InboxRule) { r.OtherActions = []string{"assignCategories"} }, ""},
		{"mark read, finance, internal forward", func(r *InboxRule) {
			r.SenderContains = []string{"invoice"}
			r.MarkAsRead = true
			r.ForwardTo = []string{"boss@example.com"}
		}, SevCritical},
	}
	for _, c := range cases {
		fs := rc.AnalyzeRule(casey, rule(c.mod))
		if c.want == "" {
			if len(fs) != 0 {
				t.Errorf("%s: finding %s %s, want none", c.name, fs[0].ID, fs[0].Severity)
			}
			continue
		}
		if len(fs) != 1 || fs[0].Severity != c.want || fs[0].ID != FindingRuleHides {
			t.Errorf("%s: %+v, want one %s %s", c.name, fs, FindingRuleHides, c.want)
		}
	}
}

func TestExternalForwardingRules(t *testing.T) {
	rc := ctx("example.com")
	ext := []string{"outside@example.net"}
	cases := []struct {
		name string
		mod  func(*InboxRule)
		want Severity
	}{
		{"forward all mail outside", func(r *InboxRule) { r.ForwardTo = ext }, SevHigh},
		{"redirect outside", func(r *InboxRule) { r.RedirectTo = ext }, SevHigh},
		{"forward as attachment outside", func(r *InboxRule) { r.ForwardAsAttachmentTo = ext }, SevHigh},
		{"forward outside and delete the original", func(r *InboxRule) { r.ForwardTo = ext; r.Delete = true }, SevCritical},
		{"forward outside and mark read", func(r *InboxRule) { r.ForwardTo = ext; r.MarkAsRead = true }, SevCritical},
		{"forward outside, finance subject", func(r *InboxRule) { r.ForwardTo = ext; r.SubjectContains = []string{"payment"} }, SevCritical},
		{"forward outside, disabled rule", func(r *InboxRule) { r.ForwardTo = ext; r.Enabled = false }, SevLow},
		{"forward outside, disabled, critical pattern", func(r *InboxRule) { r.ForwardTo = ext; r.Delete = true; r.Enabled = false }, SevLow},
		{"forward inside", func(r *InboxRule) { r.ForwardTo = []string{"colleague@example.com"} }, ""},
		{"forward inside, upper case domain", func(r *InboxRule) { r.ForwardTo = []string{"Colleague@EXAMPLE.COM"} }, ""},
		{"forward to an Exchange legacy DN", func(r *InboxRule) { r.ForwardTo = []string{"/o=ExchangeLabs/ou=x/cn=y"} }, ""},
	}
	for _, c := range cases {
		fs := rc.AnalyzeRule(casey, rule(c.mod))
		if c.want == "" {
			if len(fs) != 0 {
				t.Errorf("%s: finding %s, want none", c.name, fs[0].ID)
			}
			continue
		}
		if len(fs) != 1 || fs[0].Severity != c.want || fs[0].ID != FindingRuleForward {
			t.Errorf("%s: %+v, want one %s %s", c.name, fs, FindingRuleForward, c.want)
		}
	}

	// A trusted domain is not outside.
	rc2 := ctx("example.com", "partner.example.org")
	if fs := rc2.AnalyzeRule(casey, rule(func(r *InboxRule) { r.ForwardTo = []string{"x@partner.example.org"} })); len(fs) != 0 {
		t.Errorf("a trusted domain was reported: %+v", fs)
	}
	// One finding for a rule that forwards outside and also hides, not two.
	fs := rc.AnalyzeRule(casey, rule(func(r *InboxRule) { r.ForwardTo = ext; r.Delete = true; r.SenderContains = []string{"intuit"} }))
	if len(fs) != 1 {
		t.Errorf("a forwarding and hiding rule gave %d findings, want 1", len(fs))
	}
	if !strings.Contains(fs[0].Detail, "outside.example.net") && !strings.Contains(fs[0].Detail, "outside@example.net") {
		t.Errorf("the detail does not name the recipient: %s", fs[0].Detail)
	}
}

func TestDisabledHidingRuleIsCappedAtLow(t *testing.T) {
	r := rule(func(r *InboxRule) { r.SenderContains = []string{"intuit"}; r.Delete = true; r.Enabled = false })
	f := one(t, ctx("example.com").AnalyzeRule(casey, r))
	if f.Severity != SevLow || !strings.Contains(f.Title, "disabled") {
		t.Errorf("disabled rule: %s %q", f.Severity, f.Title)
	}
}

func TestExtraFinanceTermsAreHonoured(t *testing.T) {
	rc := DefaultRuleContext(map[string]bool{"example.com": true}, []string{"Tax Refund"})
	r := rule(func(r *InboxRule) { r.SubjectContains = []string{"your tax refund"}; r.Delete = true })
	if f := one(t, rc.AnalyzeRule(casey, r)); f.Severity != SevCritical {
		t.Errorf("custom finance term: %s, want critical", f.Severity)
	}
	if f := one(t, ctx("example.com").AnalyzeRule(casey, r)); f.Severity != SevMedium {
		t.Errorf("without the term: %s, want medium", f.Severity)
	}
}

// Privacy: the evidence of a rule is its definition; the finding never carries
// a field that could hold message content.
func TestEvidenceHoldsNoMessageFields(t *testing.T) {
	r := rule(func(r *InboxRule) {
		r.SenderContains = []string{"intuit"}
		r.Delete = true
		r.ForwardTo = []string{"x@example.net"}
	})
	f := one(t, ctx("example.com").AnalyzeRule(casey, r))
	raw, _ := json.Marshal(f.Evidence)
	for _, banned := range []string{`"body"`, `"bodyPreview"`, `"subject"`, `"attachments"`, `"messageId"`, `"internetMessageId"`} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("evidence has a message field %s: %s", banned, raw)
		}
	}
	allowed := map[string]bool{"mailbox": true, "ruleId": true, "ruleName": true, "sequence": true, "enabled": true, "hasError": true,
		"conditions": true, "actions": true, "externalRecipients": true, "via": true, "financeMatches": true, "securityMatches": true}
	for k := range f.Evidence {
		if !allowed[k] {
			t.Errorf("unexpected evidence key %q", k)
		}
	}
}
