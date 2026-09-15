package storepg

import (
	"context"
	"errors"
	"testing"
	"time"

	"defendsec/internal/auditlayer"
	"defendsec/internal/controls"
	"defendsec/internal/evidence"
	"defendsec/internal/sign"
)

func newPeriod(t *testing.T, s *Store, start, end time.Time) auditlayer.Period {
	t.Helper()
	p, err := s.CreateAuditPeriod(context.Background(), auditlayer.Period{
		ID: randID(t), Name: "test period", Framework: string(controls.CISv8),
		StartsAt: start, EndsAt: end, CreatedBy: "user:alice",
	})
	if err != nil {
		t.Fatalf("create period: %v", err)
	}
	return p
}

func TestCreateAuditPeriodValidates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	bad := map[string]auditlayer.Period{
		"no id":             {Name: "x", Framework: "cis-v8", StartsAt: start, EndsAt: start.Add(time.Hour)},
		"no name":           {ID: randID(t), Framework: "cis-v8", StartsAt: start, EndsAt: start.Add(time.Hour)},
		"unknown framework": {ID: randID(t), Name: "x", Framework: "made-up", StartsAt: start, EndsAt: start.Add(time.Hour)},
		"ends before start": {ID: randID(t), Name: "x", Framework: "cis-v8", StartsAt: start, EndsAt: start.Add(-time.Hour)},
		"zero length":       {ID: randID(t), Name: "x", Framework: "cis-v8", StartsAt: start, EndsAt: start},
	}
	for name, p := range bad {
		if _, err := s.CreateAuditPeriod(ctx, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAuditPeriodRoundTripAndClose(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := newPeriod(t, s, start, start.Add(90*24*time.Hour))

	if p.Closed() {
		t.Error("a new period must not be closed")
	}
	got, err := s.GetAuditPeriod(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StartsAt.Equal(start) || got.CreatedBy != "user:alice" {
		t.Errorf("round trip lost data: %+v", got)
	}

	closed, err := s.CloseAuditPeriod(ctx, p.ID, "user:bob", true)
	if err != nil {
		t.Fatal(err)
	}
	if !closed.Closed() || closed.ClosedBy != "user:bob" {
		t.Errorf("close did not take: %+v", closed)
	}

	// Reopening is allowed, but it is an action the caller records — the row
	// must actually return to open so the next assessment is not judged
	// against a stale final state.
	reopened, err := s.CloseAuditPeriod(ctx, p.ID, "user:bob", false)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Closed() || reopened.ClosedBy != "" {
		t.Errorf("reopen did not take: %+v", reopened)
	}

	if _, err := s.GetAuditPeriod(ctx, "no-such-period"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if _, err := s.CloseAuditPeriod(ctx, "no-such-period", "x", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// An exception with no reason, or no expiry, is exactly what this table exists
// to replace. Both must be refused.
func TestCreateControlExceptionValidates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	bad := map[string]auditlayer.Exception{
		"no id":          {ControlID: "cis-v8:5.4", Reason: "r", ExpiresAt: now.Add(time.Hour)},
		"bad control":    {ID: randID(t), ControlID: "not-a-control", Reason: "r", ExpiresAt: now.Add(time.Hour)},
		"no reason":      {ID: randID(t), ControlID: "cis-v8:5.4", ExpiresAt: now.Add(time.Hour)},
		"blank reason":   {ID: randID(t), ControlID: "cis-v8:5.4", Reason: "   ", ExpiresAt: now.Add(time.Hour)},
		"no expiry":      {ID: randID(t), ControlID: "cis-v8:5.4", Reason: "r"},
		"past expiry":    {ID: randID(t), ControlID: "cis-v8:5.4", Reason: "r", OpenedAt: now, ExpiresAt: now.Add(-time.Hour)},
		"expiry at open": {ID: randID(t), ControlID: "cis-v8:5.4", Reason: "r", OpenedAt: now, ExpiresAt: now},
	}
	for name, e := range bad {
		if _, err := s.CreateControlException(ctx, e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestControlExceptionLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	p := newPeriod(t, s, start, start.Add(90*24*time.Hour))

	e, err := s.CreateControlException(ctx, auditlayer.Exception{
		ID: randID(t), ControlID: "cis-v8:5.4", PeriodID: p.ID,
		Reason: "legacy appliance", Remediation: "replace in Q3", Owner: "ops",
		OpenedAt: start, ExpiresAt: start.Add(60 * 24 * time.Hour), OpenedBy: "user:alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.PeriodID != p.ID || e.Remediation != "replace in Q3" {
		t.Errorf("round trip lost data: %+v", e)
	}
	if !e.ActiveAt(start.Add(24 * time.Hour)) {
		t.Error("a fresh exception is not active inside its window")
	}

	list, err := s.ListControlExceptions(ctx, p.StartsAt, p.EndsAt)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, x := range list {
		if x.ID == e.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("the exception is not listed for its own period")
	}

	closed, err := s.CloseControlException(ctx, e.ID, "user:bob")
	if err != nil {
		t.Fatal(err)
	}
	if closed.ClosedAt == nil || closed.ClosedBy != "user:bob" {
		t.Errorf("close did not take: %+v", closed)
	}
	// Closing twice must not silently succeed and rewrite who closed it.
	if _, err := s.CloseControlException(ctx, e.ID, "user:carol"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound on a second close", err)
	}

	// A closed exception that overlapped the window is still listed: a reader
	// should see that one existed and ended, not infer there never was one.
	list, err = s.ListControlExceptions(ctx, p.StartsAt, p.EndsAt)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, x := range list {
		if x.ID == e.ID {
			found = true
			if x.ClosedAt == nil {
				t.Error("the listed exception does not show as closed")
			}
		}
	}
	if !found {
		t.Error("a closed exception vanished from its own period")
	}
}

// End to end: findings in a window drive the control's status, and an
// exception changes it from deficient to accepted without ever making it pass.
func TestAssessPeriodEndToEnd(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	start := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	clearWindow(t, s, start.Add(-time.Hour), end.Add(time.Hour))

	p := newPeriod(t, s, start, end)
	dev := randID(t)
	seedDevice(t, s, dev)

	at := start.Add(24 * time.Hour).Format(time.RFC3339)
	if err := s.InsertAlert(ctx, Alert{
		ID: randID(t), DeviceID: dev, Kind: "sca", Severity: "high",
		Title: "root login permitted", Status: "open",
		CreatedAt: at, DetectedAt: at,
		Signal: string(controls.SignalSCA), ControlIDs: []string{"cis-v8:5.4"},
	}); err != nil {
		t.Fatal(err)
	}

	a, err := s.AssessPeriod(ctx, controls.CISv8, p, end.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var target auditlayer.ControlStatus
	for _, cs := range a.Controls {
		if string(cs.Control.ID) == "cis-v8:5.4" {
			target = cs
		}
	}
	if target.Status != auditlayer.StatusDeficient {
		t.Fatalf("status = %s, want deficient with an open finding", target.Status)
	}
	if target.Evidence.Alerts != 1 || target.Evidence.OpenAtEnd != 1 {
		t.Errorf("evidence = %+v", target.Evidence)
	}

	// Accept it, and the status must become excepted — never satisfied.
	if _, err := s.CreateControlException(ctx, auditlayer.Exception{
		ID: randID(t), ControlID: "cis-v8:5.4", PeriodID: p.ID,
		Reason: "jump host pending decommission", OpenedAt: start,
		ExpiresAt: end.Add(24 * time.Hour), OpenedBy: "user:alice",
	}); err != nil {
		t.Fatal(err)
	}
	a, err = s.AssessPeriod(ctx, controls.CISv8, p, end.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, cs := range a.Controls {
		if string(cs.Control.ID) == "cis-v8:5.4" {
			if cs.Status != auditlayer.StatusExcepted {
				t.Fatalf("status = %s, want excepted", cs.Status)
			}
			if len(cs.Exceptions) != 1 {
				t.Errorf("the exception is not attached to the control: %+v", cs.Exceptions)
			}
		}
	}
}

// A scoped bundle must carry the assessment and still verify as a bundle: the
// audit range is not narrowed, because a hash chain filtered by content is not
// a chain.
func TestExportScopedEvidenceVerifies(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	key, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Audit(ctx, "user:alice", "command_issue", "", map[string]any{"type": "isolate"}); err != nil {
		t.Fatal(err)
	}

	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	p := newPeriod(t, s, start, time.Now().UTC().Add(24*time.Hour))

	b, err := s.ExportScopedEvidence(ctx, string(key.PublicPEM()), "test",
		controls.CISv8, p, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if b.Compliance == nil {
		t.Fatal("the bundle carries no compliance section")
	}
	if len(b.Compliance.Controls) != len(controls.ForFramework(controls.CISv8)) {
		t.Errorf("assessed %d controls, framework has %d",
			len(b.Compliance.Controls), len(controls.ForFramework(controls.CISv8)))
	}
	if b.Compliance.Provenance != evidence.ComplianceProvenance {
		t.Error("the provenance statement is missing or altered")
	}
	// The audit range must not have been narrowed to the window.
	if len(b.Audit) == 0 {
		t.Fatal("the scoped bundle carries no audit entries")
	}

	// The shared test database accumulates checkpoints and commands signed by
	// keys from earlier tests, so whole-bundle verification is not meaningful
	// here. The chain and the compliance section are what this test is about;
	// signature verification has its own coverage in internal/evidence.
	check := func(rep evidence.Report, name string) evidence.Check {
		t.Helper()
		for _, c := range rep.Checks {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no %q check in the report", name)
		return evidence.Check{}
	}
	rep := evidence.Verify(b)
	if c := check(rep, "audit chain"); !c.OK {
		t.Fatalf("audit chain: %s", c.Detail)
	}
	if c := check(rep, "compliance assessment"); !c.OK {
		t.Fatalf("compliance assessment: %s", c.Detail)
	}
	if rep.ComplianceControls == 0 {
		t.Error("the report does not count the asserted controls")
	}

	// And the recomputation must actually bite: inflate a count and it fails.
	for i := range b.Compliance.Controls {
		if b.Compliance.Controls[i].AuditEntries > 0 {
			b.Compliance.Controls[i].AuditEntries++
			if c := check(evidence.Verify(b), "compliance assessment"); c.OK {
				t.Fatal("an inflated audit-entry count survived verification")
			}
			return
		}
	}
	t.Fatal("no control accumulated audit entries, so the recomputation was never exercised")
}
