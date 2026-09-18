package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"defendsec/internal/presence"
	"defendsec/internal/storepg"
	"defendsec/internal/triage"
)

// End-to-end triage: real recorded package history, a real stored alert, and
// the explanation an operator or an agent would actually get.
//
// The pure correlation is tested in internal/triage. What this covers is the
// wiring in between — the alert's path being found, the history window being
// queried, and the timestamps lining up — which is where an explanation that
// is right in principle goes wrong in practice.

func triageServer(t *testing.T) (*Server, *storepg.Store) {
	t.Helper()
	return agentServer(t, `
version: 1
name: triage-tests
rules:
  - id: permit-admin
    effect: permit
    roles: [admin]
    commands: [live_query]
`)
}

// insertFimAlert stores a file-integrity alert with the changed path in its
// detail, as the FIM path raises them.
func insertFimAlert(t *testing.T, store *storepg.Store, id, deviceID, path string, at time.Time) {
	t.Helper()
	detail, _ := json.Marshal(map[string]any{
		"path": path, "previous": "old-hash", "current": "new-hash", "action": "modified",
	})
	if err := store.InsertAlert(context.Background(), storepg.Alert{
		ID: id, DeviceID: deviceID, Hostname: "web-01",
		Kind: "fim", Severity: "high", Status: "open",
		Title:      path + " changed",
		Summary:    "file integrity drift",
		CreatedAt:  at.Format(time.RFC3339),
		UpdatedAt:  at.Format(time.RFC3339),
		DetectedAt: at.Format(time.RFC3339),
		SourceType: "fim", SourceID: path,
		Detail: detail,
	}); err != nil {
		t.Fatal(err)
	}
}

// The roadmap's example, end to end.
func TestDriftIsExplainedFromRecordedPackageHistory(t *testing.T) {
	s, store := triageServer(t)
	ctx := context.Background()
	enrolHost(t, s, "dev-1", "web-01")

	// An upgrade observed a few minutes before the file change.
	if err := store.RecordPackageChanges(ctx, "dev-1", "web-01",
		[]presence.PackageChange{
			{Package: "openssh-server", PreviousVersion: "9.6p1-3", NewVersion: "9.6p1-4"},
		}); err != nil {
		t.Fatal(err)
	}
	// RecordPackageChanges stamps now(), so the alert is dated just after.
	insertFimAlert(t, store, "alert-1", "dev-1", "/etc/ssh/sshd_config",
		time.Now().UTC().Add(time.Minute))

	exp, why, err := s.ExplainAlertDrift(ctx, "alert-1")
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil {
		t.Fatalf("no explanation: %s", why)
	}
	if exp.Verdict != triage.VerdictPackageUpgrade {
		t.Fatalf("verdict = %q, want %q (summary: %s)",
			exp.Verdict, triage.VerdictPackageUpgrade, exp.Summary)
	}
	if !strings.Contains(exp.Summary, "openssh-server") {
		t.Errorf("summary = %q", exp.Summary)
	}
	if exp.AutoResolvable {
		t.Error("the explanation offers itself as grounds to auto-resolve")
	}
	if exp.Caveat == "" {
		t.Error("an explained drift carries no caveat")
	}
}

// The security-relevant case: no package history accounts for the change.
func TestDriftWithNoPackageActivityIsUnexplained(t *testing.T) {
	s, store := triageServer(t)
	enrolHost(t, s, "dev-1", "web-01")
	insertFimAlert(t, store, "alert-2", "dev-1", "/etc/ssh/sshd_config", time.Now().UTC())

	exp, _, err := s.ExplainAlertDrift(context.Background(), "alert-2")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Verdict != triage.VerdictUnexplained {
		t.Fatalf("verdict = %q, want %q", exp.Verdict, triage.VerdictUnexplained)
	}
	if !strings.Contains(exp.Summary, "edited this file directly") {
		t.Errorf("summary = %q", exp.Summary)
	}
}

// Another host's upgrade must not explain this host's file change.
func TestAnotherHostsUpgradeDoesNotExplainThisHost(t *testing.T) {
	s, store := triageServer(t)
	ctx := context.Background()
	enrolHost(t, s, "dev-1", "web-01")
	enrolHost(t, s, "dev-2", "web-02")

	if err := store.RecordPackageChanges(ctx, "dev-2", "web-02",
		[]presence.PackageChange{
			{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2"},
		}); err != nil {
		t.Fatal(err)
	}
	insertFimAlert(t, store, "alert-3", "dev-1", "/etc/ssh/sshd_config",
		time.Now().UTC().Add(time.Minute))

	exp, _, err := s.ExplainAlertDrift(ctx, "alert-3")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Verdict == triage.VerdictPackageUpgrade {
		t.Fatalf("a different host's upgrade explained this one: %+v", exp)
	}
}

// Package transitions must actually be recorded as inventory arrives, or the
// correlation has nothing to work with.
func TestInventoryRecordsPackageTransitions(t *testing.T) {
	_, store := triageServer(t)
	ctx := context.Background()

	// A first inventory establishes the baseline and records nothing: the
	// first heartbeat from a host is not a thousand installs.
	first := presence.DiffSoftware(nil, []presence.Software{{Name: "openssh-server", Version: "1"}})
	if len(first) != 0 {
		t.Errorf("the first inventory produced %d changes, want none", len(first))
	}

	// The second one shows the upgrade.
	changes := presence.DiffSoftware(
		[]presence.Software{{Name: "openssh-server", Version: "1"}, {Name: "curl", Version: "8"}},
		[]presence.Software{{Name: "openssh-server", Version: "2"}, {Name: "nginx", Version: "1"}},
	)
	if err := store.RecordPackageChanges(ctx, "dev-9", "web-09", changes); err != nil {
		t.Fatal(err)
	}
	stored, err := store.RecentPackageChanges(ctx, "dev-9", 50)
	if err != nil {
		t.Fatal(err)
	}
	byPkg := map[string]storepg.PackageChange{}
	for _, c := range stored {
		byPkg[c.Package] = c
	}
	if got := byPkg["openssh-server"]; got.PreviousVersion != "1" || got.NewVersion != "2" {
		t.Errorf("upgrade = %+v", got)
	}
	if got := byPkg["nginx"]; got.PreviousVersion != "" || got.NewVersion != "1" {
		t.Errorf("install = %+v, want an absent previous version", got)
	}
	if got := byPkg["curl"]; got.PreviousVersion != "8" || got.NewVersion != "" {
		t.Errorf("removal = %+v, want an absent new version", got)
	}
	if !byPkg["openssh-server"].Upgrade() {
		t.Error("an upgrade is not reported as one")
	}
	if byPkg["nginx"].Upgrade() {
		t.Error("an install is reported as an upgrade")
	}
}

// A non-FIM alert has no changed file, and that must be said rather than
// producing a confident verdict about nothing.
func TestANonFimAlertIsNotGivenADriftVerdict(t *testing.T) {
	s, store := triageServer(t)
	enrolHost(t, s, "dev-1", "web-01")
	if err := store.InsertAlert(context.Background(), storepg.Alert{
		ID: "alert-detect", DeviceID: "dev-1", Hostname: "web-01",
		Kind: "detection", Severity: "critical", Status: "open",
		Title: "Reverse shell", Summary: "matched a rule",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	exp, why, err := s.ExplainAlertDrift(context.Background(), "alert-detect")
	if err != nil {
		t.Fatal(err)
	}
	if exp != nil {
		t.Fatalf("a detection alert was given a drift verdict: %+v", exp)
	}
	if !strings.Contains(why, "no changed file") {
		t.Errorf("why = %q", why)
	}
}

func TestAnUnknownAlertIdIsReportedNotGuessed(t *testing.T) {
	s, _ := triageServer(t)
	exp, why, err := s.ExplainAlertDrift(context.Background(), "no-such-alert")
	if err != nil {
		t.Fatal(err)
	}
	if exp != nil {
		t.Error("an unknown alert produced an explanation")
	}
	if !strings.Contains(why, "no-such-alert") {
		t.Errorf("why = %q", why)
	}
}

// Summarisation over real stored alerts.
func TestSummariseGroupsStoredAlerts(t *testing.T) {
	s, store := triageServer(t)
	enrolHost(t, s, "dev-1", "web-01")
	at := time.Now().UTC()
	for i, id := range []string{"s1", "s2", "s3"} {
		insertFimAlert(t, store, id, "dev-1", "/etc/ssh/sshd_config", at.Add(time.Duration(i)*time.Second))
	}

	summary, err := s.SummariseAlerts(context.Background(), storepg.AlertFilters{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 3 {
		t.Errorf("total = %d", summary.Total)
	}
	if len(summary.Clusters) != 1 || summary.Clusters[0].Count != 3 {
		t.Errorf("clusters = %+v", summary.Clusters)
	}
}
