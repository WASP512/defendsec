package storepg

import (
	"context"
	"testing"
	"time"

	"defendsec/internal/m365"
)

// A mailbox the run skipped (past the per-read cap) is not covered: a finding open on
// it stays open and shows as unconfirmed; a mailbox that was read and no longer has
// the rule is resolved. The prefix is the user id plus a slash, so a user whose id
// merely starts the same way is not caught by it.
func TestIdentitySkippedMailboxKeepsItsFinding(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-72 * time.Hour).Round(time.Microsecond)

	skipped := idnFinding("inbox_rule.hides_mail", "u-casey/r1", "casey@example.com · Intuit stuff", m365.SevCritical)
	sibling := idnFinding("inbox_rule.hides_mail", "u-casey2/r1", "casey2@example.com · Invoices", m365.SevCritical)
	read := idnFinding("inbox_rule.forward_external", "u-dana/r9", "dana@example.com · From partner", m365.SevHigh)

	report := func(at time.Time, rules m365.CheckResult) *m365.Report {
		return idnReport(at,
			idnCheck(m365.GroupMFA, true, ""),
			rules,
			idnCheck(m365.GroupLegacyAuth, true, ""),
			idnCheck(m365.GroupAdminRoles, true, ""))
	}
	if _, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", report(t0,
		idnCheck(m365.GroupInboxRules, true, "", skipped, sibling, read))); err != nil {
		t.Fatal(err)
	}
	if n := len(idnAll(t, s, false)); n != 3 {
		t.Fatalf("%d open after run 1, want 3", n)
	}

	// Run 2: the cap cut u-casey off. Dana and casey2 were read and still have their rules.
	rules := idnCheck(m365.GroupInboxRules, true, "", sibling, read)
	rules.UnassessedPrefixes = []string{"u-casey/"}
	rep := report(t0.Add(24*time.Hour), rules)
	rep.Counts.Skipped = 1
	run2, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", rep)
	if err != nil {
		t.Fatal(err)
	}
	if run2.Status != "partial" || run2.Resolved != 0 || run2.Open != 3 {
		t.Fatalf("run 2 = %+v, want partial, nothing resolved, 3 open", run2)
	}
	open := idnAll(t, s, false)
	f, ok := open["inbox_rule.hides_mail/u-casey/r1"]
	if !ok || !f.Unconfirmed {
		t.Fatalf("skipped mailbox's finding: open=%v unconfirmed=%v, want open and unconfirmed", ok, f.Unconfirmed)
	}
	if open["inbox_rule.hides_mail/u-casey2/r1"].Unconfirmed || open["inbox_rule.forward_external/u-dana/r9"].Unconfirmed {
		t.Error("a finding on a mailbox that was read is unconfirmed")
	}
	if n := len(idnAll(t, s, true)); n != 0 {
		t.Errorf("%d findings resolved, want 0", n)
	}

	// The same run without the prefix would have closed it: this is what the cap bug did.
	// Run 3: the mailbox is read again and the rule is gone, so now it is resolved.
	run3, err := s.RecordIdentityRun(ctx, "m365", "tenant-1", "schedule", report(t0.Add(48*time.Hour),
		idnCheck(m365.GroupInboxRules, true, "", sibling, read)))
	if err != nil {
		t.Fatal(err)
	}
	if run3.Resolved != 1 {
		t.Fatalf("run 3 resolved %d, want 1", run3.Resolved)
	}
	if _, still := idnAll(t, s, false)["inbox_rule.hides_mail/u-casey/r1"]; still {
		t.Error("the finding stayed open although its mailbox was read and the rule is gone")
	}
}
