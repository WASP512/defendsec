package gws

import (
	"encoding/json"
	"strings"
	"testing"
)

func testContext() RuleContext {
	return DefaultRuleContext(map[string]bool{"example.com": true, "alias.example.net": true}, nil)
}

func casey() User { return User{ID: "u-1", Email: "casey@example.com", MailboxSetup: true} }

func TestAnalyzeFilter(t *testing.T) {
	type tc struct {
		name   string
		f      Filter
		want   Severity // "" = no finding
		id     string
		titleH string
	}
	cases := []tc{
		// Forwarding outside.
		{"forward outside", Filter{ID: "f", From: "boss@vendor.example.net", Forward: "me@mail.example.org"}, SevHigh, FindingFilterForward, "forwards mail outside"},
		{"forward outside, case differs", Filter{ID: "f", Forward: "Me@Mail.Example.ORG"}, SevHigh, FindingFilterForward, ""},
		{"forward outside and trash", Filter{ID: "f", Forward: "me@mail.example.org", AddLabelIDs: []string{"TRASH"}}, SevCritical, FindingFilterForward, ""},
		{"forward outside and skip inbox", Filter{ID: "f", Forward: "me@mail.example.org", RemoveLabelIDs: []string{"INBOX"}}, SevCritical, FindingFilterForward, ""},
		{"forward outside and mark read", Filter{ID: "f", Forward: "me@mail.example.org", RemoveLabelIDs: []string{"UNREAD"}}, SevCritical, FindingFilterForward, ""},
		{"forward outside with finance words", Filter{ID: "f", Subject: "wire transfer", Forward: "me@mail.example.org"}, SevCritical, FindingFilterForward, ""},
		{"forward outside, only filing", Filter{ID: "f", Forward: "me@mail.example.org", AddLabelIDs: []string{"Label_9"}, RemoveLabelIDs: []string{"INBOX"}}, SevHigh, FindingFilterForward, ""},
		{"forward to the domain itself", Filter{ID: "f", Forward: "help@example.com"}, "", "", ""},
		{"forward to a domain alias", Filter{ID: "f", Forward: "help@alias.example.net"}, "", "", ""},
		{"forward to a look-alike domain", Filter{ID: "f", Forward: "help@example.com.evil.example.org"}, SevHigh, FindingFilterForward, ""},
		{"forward to a sibling domain", Filter{ID: "f", Forward: "help@notexample.com"}, SevHigh, FindingFilterForward, ""},

		// Hiding.
		{"AMP lookalike: invoices marked read and out of the inbox",
			Filter{ID: "f", From: "noreply@intuit.com", Subject: "invoice", RemoveLabelIDs: []string{"INBOX", "UNREAD"}}, SevCritical, FindingFilterHides, "hides finance mail"},
		{"finance words in the query", Filter{ID: "f", Query: "remittance advice", AddLabelIDs: []string{"TRASH"}}, SevCritical, FindingFilterHides, "hides finance mail"},
		{"finance sender", Filter{ID: "f", From: "quickbooks@notification.intuit.com", RemoveLabelIDs: []string{"INBOX"}}, SevCritical, FindingFilterHides, ""},
		{"ach as a whole word", Filter{ID: "f", Subject: "ACH payment", RemoveLabelIDs: []string{"INBOX"}}, SevCritical, FindingFilterHides, ""},
		{"ach inside a word is not finance", Filter{ID: "f", Subject: "reach out", RemoveLabelIDs: []string{"INBOX"}}, SevMedium, FindingFilterHides, "Gmail filter hides mail"},
		{"finance mail filed under a label of the user's own", Filter{ID: "f", Subject: "invoice", AddLabelIDs: []string{"Label_17"}, RemoveLabelIDs: []string{"INBOX"}}, SevHigh, FindingFilterHides, "hides finance mail"},
		{"ordinary filing is not reported", Filter{ID: "f", From: "newsletter@list.example.net", AddLabelIDs: []string{"Label_17"}, RemoveLabelIDs: []string{"INBOX"}}, "", "", ""},
		{"filing with a security word is not reported", Filter{ID: "f", Subject: "password", AddLabelIDs: []string{"Label_17"}, RemoveLabelIDs: []string{"INBOX"}}, "", "", ""},
		{"security notices out of the inbox", Filter{ID: "f", Subject: "security alert", RemoveLabelIDs: []string{"INBOX"}}, SevHigh, FindingFilterHides, ""},
		{"verification codes in the trash", Filter{ID: "f", Query: "verification code", AddLabelIDs: []string{"TRASH"}}, SevHigh, FindingFilterHides, ""},
		{"no condition, trash", Filter{ID: "f", AddLabelIDs: []string{"TRASH"}}, SevHigh, FindingFilterHides, ""},
		{"no condition, spam", Filter{ID: "f", AddLabelIDs: []string{"SPAM"}}, SevHigh, FindingFilterHides, ""},
		{"no condition, skip inbox", Filter{ID: "f", RemoveLabelIDs: []string{"INBOX"}}, SevHigh, FindingFilterHides, ""},
		{"no condition, only mark read", Filter{ID: "f", RemoveLabelIDs: []string{"UNREAD"}}, SevMedium, FindingFilterHides, ""},
		{"a condition that is not a sender or a word", Filter{ID: "f", HasAttachment: true, AddLabelIDs: []string{"TRASH"}}, SevMedium, FindingFilterHides, ""},
		{"sender only, mark read", Filter{ID: "f", From: "news@example.net", RemoveLabelIDs: []string{"UNREAD"}}, SevMedium, FindingFilterHides, ""},
		{"skip inbox and a category is not filing", Filter{ID: "f", From: "news@example.net", AddLabelIDs: []string{"CATEGORY_UPDATES"}, RemoveLabelIDs: []string{"INBOX"}}, SevMedium, FindingFilterHides, ""},
		{"label and also mark read", Filter{ID: "f", From: "news@example.net", AddLabelIDs: []string{"Label_17"}, RemoveLabelIDs: []string{"INBOX", "UNREAD"}}, SevMedium, FindingFilterHides, ""},

		// Nothing to report.
		{"star and category only", Filter{ID: "f", Query: "has:attachment", AddLabelIDs: []string{"STARRED", "CATEGORY_UPDATES"}}, "", "", ""},
		{"never send to spam", Filter{ID: "f", From: "friend@example.net", RemoveLabelIDs: []string{"SPAM"}}, "", "", ""},
		{"mark important", Filter{ID: "f", From: "friend@example.net", AddLabelIDs: []string{"IMPORTANT"}}, "", "", ""},
		{"empty filter", Filter{ID: "f"}, "", "", ""},
	}
	rc := testContext()
	for _, c := range cases {
		got := rc.AnalyzeFilter(casey(), c.f)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected %+v", c.name, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Errorf("%s: %d findings, want 1", c.name, len(got))
			continue
		}
		f := got[0]
		if f.Severity != c.want || f.ID != c.id {
			t.Errorf("%s: %s %s, want %s %s (%s)", c.name, f.ID, f.Severity, c.id, c.want, f.Detail)
		}
		if c.titleH != "" && !strings.Contains(f.Title, c.titleH) {
			t.Errorf("%s: title %q lacks %q", c.name, f.Title, c.titleH)
		}
		if f.Subject != "u-1/f" || len(f.Controls) == 0 || f.Fix == "" || !strings.HasPrefix(f.SubjectLabel, "casey@example.com · filter on ") {
			t.Errorf("%s: finding = %+v", c.name, f)
		}
	}
}

func TestExtraFinanceTermsAndTrustedDomains(t *testing.T) {
	f := Filter{ID: "f", Subject: "tax refund", RemoveLabelIDs: []string{"INBOX"}}
	if got := testContext().AnalyzeFilter(casey(), f); len(got) != 1 || got[0].Severity != SevMedium {
		t.Fatalf("without the extra term: %+v", got)
	}
	rc := DefaultRuleContext(map[string]bool{"example.com": true}, []string{"tax refund"})
	if got := rc.AnalyzeFilter(casey(), f); len(got) != 1 || got[0].Severity != SevCritical {
		t.Errorf("with the extra term: %+v", got)
	}
	fw := Filter{ID: "f", Forward: "me@partner.example.org"}
	if got := testContext().AnalyzeFilter(casey(), fw); len(got) != 1 {
		t.Fatalf("untrusted: %+v", got)
	}
	rc = DefaultRuleContext(map[string]bool{"example.com": true, "partner.example.org": true}, nil)
	if got := rc.AnalyzeFilter(casey(), fw); len(got) != 0 {
		t.Errorf("trusted domain still reported: %+v", got)
	}
}

func TestFilterEvidenceHoldsDefinitionsOnly(t *testing.T) {
	f := Filter{ID: "f1", From: "noreply@intuit.com", Subject: "invoice", Query: "has:attachment", NegatedQuery: "from:me", HasAttachment: true, Size: 10,
		RemoveLabelIDs: []string{"INBOX", "UNREAD"}, AddLabelIDs: []string{"Label_1"}}
	got := testContext().AnalyzeFilter(casey(), f)
	if len(got) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	raw, _ := json.Marshal(got[0].Evidence)
	var ev map[string]any
	_ = json.Unmarshal(raw, &ev)
	keys := map[string]bool{}
	for k := range ev {
		keys[k] = true
	}
	for _, k := range []string{"mailbox", "filterId", "criteria", "actions", "financeMatches"} {
		if !keys[k] {
			t.Errorf("evidence lacks %s: %s", k, raw)
		}
	}
	for k := range keys {
		switch k {
		case "mailbox", "filterId", "criteria", "actions", "financeMatches", "securityMatches", "externalRecipients":
		default:
			t.Errorf("unexpected evidence key %q: nothing but definitions belongs here", k)
		}
	}
	crit := ev["criteria"].(map[string]any)
	for _, k := range []string{"from", "subject", "query", "negatedQuery", "hasAttachment", "size"} {
		if _, ok := crit[k]; !ok {
			t.Errorf("criteria lacks %s: %v", k, crit)
		}
	}
}

func TestAnalyzeAutoForwarding(t *testing.T) {
	rc := testContext()
	for _, c := range []struct {
		name string
		a    AutoForwarding
		want Severity
	}{
		{"disabled", AutoForwarding{Enabled: false, EmailAddress: "x@mail.example.org", Disposition: "archive"}, ""},
		{"enabled without an address", AutoForwarding{Enabled: true}, ""},
		{"internal address", AutoForwarding{Enabled: true, EmailAddress: "help@example.com", Disposition: "archive"}, ""},
		{"alias domain", AutoForwarding{Enabled: true, EmailAddress: "help@alias.example.net", Disposition: "trash"}, ""},
		{"external, original stays", AutoForwarding{Enabled: true, EmailAddress: "x@mail.example.org", Disposition: "leaveInInbox"}, SevHigh},
		{"external, archived", AutoForwarding{Enabled: true, EmailAddress: "x@mail.example.org", Disposition: "archive"}, SevCritical},
		{"external, trashed", AutoForwarding{Enabled: true, EmailAddress: "x@mail.example.org", Disposition: "trash"}, SevCritical},
		{"external, marked read", AutoForwarding{Enabled: true, EmailAddress: "x@mail.example.org", Disposition: "markRead"}, SevCritical},
		{"external, disposition not stated", AutoForwarding{Enabled: true, EmailAddress: "x@mail.example.org"}, SevHigh},
	} {
		got := rc.AnalyzeAutoForwarding(casey(), c.a)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected %+v", c.name, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != c.want || got[0].ID != FindingAutoForward || got[0].Subject != "u-1/autoforward" {
			t.Errorf("%s: %+v, want %s", c.name, got, c.want)
			continue
		}
		if !strings.Contains(got[0].Detail, "x@mail.example.org") || len(got[0].Controls) == 0 {
			t.Errorf("%s: finding = %+v", c.name, got[0])
		}
	}
}
