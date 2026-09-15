package storepg

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"defendsec/internal/cmdlog"
	"defendsec/internal/policy"
)

// cmdRecord is a minimal issued command, for counting against limits.
func cmdRecord(marker string, i int, deviceID string, at time.Time) cmdlog.Record {
	stamp := at.Format(time.RFC3339)
	return cmdlog.Record{
		ID:       marker + "-" + strconv.Itoa(i),
		DeviceID: deviceID, Hostname: "host", Type: "isolate",
		Payload: "{}", Status: "sent",
		CreatedAt: stamp, UpdatedAt: stamp,
	}
}

func resetPolicy(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`TRUNCATE policy_decisions, pending_commands, pending_command_approvals, break_glass CASCADE`); err != nil {
		t.Fatalf("reset policy tables: %v", err)
	}
}

// Denials are evidence: a tool that records only what it did cannot answer
// "did anyone try".
func TestPolicyDecisionsRecordDenials(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetPolicy(t, s)

	now := time.Now().UTC().Truncate(time.Second)
	for _, d := range []PolicyDecision{
		{
			ID: randID(t), At: now, Actor: "user:alice", Role: "admin",
			CommandType: "isolate", DeviceID: "dev-1", HostClasses: []string{"production"},
			Effect: policy.EffectPermit, RuleID: "allow", Reason: "permitted",
			PolicyName: "default", PolicyHash: "abc", CommandID: "cmd-1",
		},
		{
			ID: randID(t), At: now, Actor: "user:bob", Role: "admin",
			CommandType: "kill_process", DeviceID: "dev-2", HostClasses: []string{"critical"},
			Effect: policy.EffectDeny, RuleID: "never-kill-critical",
			Reason: "this host runs the estate", PolicyName: "default", PolicyHash: "abc",
		},
	} {
		if err := s.RecordPolicyDecision(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.ListPolicyDecisions(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("stored %d decisions, want 2", len(all))
	}

	denials, err := s.ListPolicyDecisions(ctx, string(policy.EffectDeny), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(denials) != 1 || denials[0].RuleID != "never-kill-critical" {
		t.Fatalf("denials = %+v", denials)
	}
	// The rule, the reason and the policy that decided must all survive, or
	// the record cannot answer what happened months later.
	if denials[0].Reason == "" || denials[0].PolicyHash != "abc" ||
		len(denials[0].HostClasses) != 1 {
		t.Errorf("denial lost detail: %+v", denials[0])
	}
}

// Limits count what was actually issued, not what was evaluated: counting
// evaluations would let a caller exhaust a limit with requests that were all
// denied anyway.
func TestCommandUsageCountsIssuedCommands(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	dev := randID(t)
	seedDevice(t, s, dev)
	other := randID(t)
	seedDevice(t, s, other)

	marker := randID(t)
	now := time.Now().UTC()
	for i, target := range []string{dev, dev, other} {
		if err := s.AppendCommand(ctx, cmdRecord(marker, i, target, now)); err != nil {
			t.Fatal(err)
		}
	}

	u, err := s.CommandUsage(ctx, []string{"isolate"}, now.Add(-time.Hour), dev)
	if err != nil {
		t.Fatal(err)
	}
	if u.FleetCount < 3 {
		t.Errorf("fleet count = %d, want at least the 3 just issued", u.FleetCount)
	}
	if u.HostCount < 2 {
		t.Errorf("host count = %d, want at least the 2 issued to this host", u.HostCount)
	}

	// A window that excludes them must not count them, or a limit would never
	// reset.
	future, err := s.CommandUsage(ctx, []string{"isolate"}, now.Add(time.Hour), dev)
	if err != nil {
		t.Fatal(err)
	}
	if future.FleetCount != 0 || future.HostCount != 0 {
		t.Errorf("a window after the commands counted %+v", future)
	}
}

func TestDeviceClasses(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	dev := randID(t)
	seedDevice(t, s, dev)

	classes, err := s.DeviceClasses(ctx, dev)
	if err != nil || len(classes) != 0 {
		t.Fatalf("a fresh device has classes %v, %v", classes, err)
	}

	if err := s.SetDeviceClasses(ctx, dev, []string{"production", "critical"}); err != nil {
		t.Fatal(err)
	}
	classes, err = s.DeviceClasses(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 2 {
		t.Fatalf("classes = %v", classes)
	}

	// A host the database has never seen evaluates as unclassified rather
	// than failing, or an unknown host would be unmanageable at exactly the
	// moment somebody needs to isolate it.
	classes, err = s.DeviceClasses(ctx, "no-such-device")
	if err != nil {
		t.Errorf("an unknown device errored rather than reporting no classes: %v", err)
	}
	if len(classes) != 0 {
		t.Errorf("an unknown device reported classes %v", classes)
	}

	if err := s.SetDeviceClasses(ctx, "no-such-device", []string{"x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("setting classes on an unknown device = %v, want ErrNotFound", err)
	}
}

func TestTwoPersonApprovalFlow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetPolicy(t, s)

	dev := randID(t)
	seedDevice(t, s, dev)
	now := time.Now().UTC()

	p, err := s.CreatePendingCommand(ctx, PendingCommand{
		ID: randID(t), CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		DeviceID: dev, CommandType: "isolate", Payload: "{}",
		RequestedBy: "user:alice", RequiredApprovals: 2, RuleID: "needs-two",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The requester's approval counts as one: they asked for it, and making
	// them click approve afterwards adds a step and no safety.
	if len(p.Approvals) != 1 || p.Approvals[0] != "user:alice" {
		t.Fatalf("approvals = %v", p.Approvals)
	}
	if p.Approved() {
		t.Fatal("one approval satisfied a two-person command")
	}

	// The same person approving again must not count twice.
	p, err = s.ApprovePendingCommand(ctx, p.ID, "user:alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Approvals) != 1 {
		t.Fatalf("one person approving twice produced %d approvals", len(p.Approvals))
	}
	if p.Approved() {
		t.Fatal("one person approving twice satisfied two-person integrity")
	}

	// A second, distinct administrator completes it.
	p, err = s.ApprovePendingCommand(ctx, p.ID, "user:bob", now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Approved() || len(p.Approvals) != 2 {
		t.Fatalf("two distinct approvals did not complete the request: %+v", p)
	}

	// It must appear in the pending list until resolved, then disappear.
	list, err := s.ListPendingCommands(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("pending list = %+v", list)
	}
	if err := s.ResolvePendingCommand(ctx, p.ID, "issued", "cmd-1"); err != nil {
		t.Fatal(err)
	}
	list, err = s.ListPendingCommands(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("a resolved request is still pending: %+v", list)
	}
}

// Two approvers racing to the final approval must not both issue a command.
func TestResolvePendingCommandIsOnceOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetPolicy(t, s)

	dev := randID(t)
	seedDevice(t, s, dev)
	now := time.Now().UTC()
	p, err := s.CreatePendingCommand(ctx, PendingCommand{
		ID: randID(t), CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		DeviceID: dev, CommandType: "isolate", Payload: "{}",
		RequestedBy: "user:alice", RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ResolvePendingCommand(ctx, p.ID, "issued", "cmd-1"); err != nil {
		t.Fatal(err)
	}
	// The second attempt must fail, so exactly one command is produced.
	if err := s.ResolvePendingCommand(ctx, p.ID, "issued", "cmd-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second resolve succeeded: %v", err)
	}

	got, err := s.GetPendingCommand(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommandID != "cmd-1" {
		t.Errorf("commandId = %q, want the first one", got.CommandID)
	}
}

// An approval request that never expires becomes a way to get a command signed
// weeks later, under conditions nobody re-examined.
func TestExpiredRequestsCannotBeApproved(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetPolicy(t, s)

	dev := randID(t)
	seedDevice(t, s, dev)
	now := time.Now().UTC()
	p, err := s.CreatePendingCommand(ctx, PendingCommand{
		ID: randID(t), CreatedAt: now, ExpiresAt: now.Add(time.Minute),
		DeviceID: dev, CommandType: "isolate", Payload: "{}",
		RequestedBy: "user:alice", RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Minute)
	if _, err := s.ApprovePendingCommand(ctx, p.ID, "user:bob", later); err == nil {
		t.Fatal("an expired request was approved")
	}
	list, err := s.ListPendingCommands(ctx, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("an expired request is still listed as pending: %+v", list)
	}
}

func TestCreatePendingCommandValidates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	bad := map[string]PendingCommand{
		"no id":         {CreatedAt: now, ExpiresAt: now.Add(time.Minute), RequestedBy: "user:alice"},
		"no requester":  {ID: randID(t), CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		"no expiry":     {ID: randID(t), CreatedAt: now, RequestedBy: "user:alice"},
		"expiry before": {ID: randID(t), CreatedAt: now, ExpiresAt: now.Add(-time.Minute), RequestedBy: "user:alice"},
	}
	for name, p := range bad {
		if _, err := s.CreatePendingCommand(ctx, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBreakGlassLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetPolicy(t, s)

	now := time.Now().UTC()
	if _, err := s.ActiveBreakGlass(ctx, now); err != nil {
		t.Fatal(err)
	}
	if active, _ := s.ActiveBreakGlass(ctx, now); active != nil {
		t.Fatal("a bypass was active with none opened")
	}

	bg, err := s.OpenBreakGlass(ctx, policy.BreakGlass{
		ID: randID(t), Justification: "active ransomware on the finance segment",
		OpenedBy: "user:alice", OpenedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	active, err := s.ActiveBreakGlass(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.ID != bg.ID {
		t.Fatalf("the open bypass was not found: %+v", active)
	}

	// Time-boxed means time-boxed.
	if active, _ := s.ActiveBreakGlass(ctx, now.Add(time.Hour)); active != nil {
		t.Error("an expired bypass was still active")
	}

	// Closing early takes effect at once.
	if err := s.CloseBreakGlass(ctx, bg.ID, "user:bob"); err != nil {
		t.Fatal(err)
	}
	if active, _ := s.ActiveBreakGlass(ctx, now.Add(time.Minute)); active != nil {
		t.Error("a closed bypass was still active")
	}
	if err := s.CloseBreakGlass(ctx, bg.ID, "user:bob"); !errors.Is(err, ErrNotFound) {
		t.Errorf("closing twice = %v, want ErrNotFound", err)
	}

	// The history keeps it, because a bypass that vanishes cannot be audited.
	history, err := s.ListBreakGlass(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].ClosedAt == nil {
		t.Fatalf("history = %+v", history)
	}
	if !strings.Contains(history[0].Justification, "ransomware") {
		t.Error("the justification was lost")
	}
}

// An emergency nobody wrote down is indistinguishable from an abuse
// afterwards, and one with no expiry is permanent.
func TestOpenBreakGlassValidates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	bad := map[string]policy.BreakGlass{
		"no justification":    {ID: randID(t), OpenedAt: now, ExpiresAt: now.Add(time.Minute)},
		"blank justification": {ID: randID(t), Justification: "   ", OpenedAt: now, ExpiresAt: now.Add(time.Minute)},
		"no expiry":           {ID: randID(t), Justification: "because", OpenedAt: now},
		"expiry in the past":  {ID: randID(t), Justification: "because", OpenedAt: now, ExpiresAt: now.Add(-time.Minute)},
	}
	for name, b := range bad {
		if _, err := s.OpenBreakGlass(ctx, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
