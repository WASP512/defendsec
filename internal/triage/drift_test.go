package triage

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func drift(path string) DriftEvent {
	return DriftEvent{
		Path: path, Previous: "aaa", Current: "bbb", DetectedAt: now, Action: "modified",
	}
}

// The roadmap's own example: "this changed because openssh-server was
// upgraded 4 minutes earlier".
func TestAnOwningPackageUpgradeExplainsTheChange(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "9.6p1-3", NewVersion: "9.6p1-4",
			ObservedAt: now.Add(-4 * time.Minute)},
	})

	if exp.Verdict != VerdictPackageUpgrade {
		t.Fatalf("verdict = %q, want %q", exp.Verdict, VerdictPackageUpgrade)
	}
	for _, want := range []string{"openssh-server", "9.6p1-3", "9.6p1-4", "4 minutes"} {
		if !strings.Contains(exp.Summary, want) {
			t.Errorf("summary does not mention %q: %s", want, exp.Summary)
		}
	}
	if len(exp.Correlated) != 1 {
		t.Errorf("correlated = %v", exp.Correlated)
	}
}

// The property that keeps this honest: a confident verdict is never
// permission to close the alert. A package upgrade is also the most
// convenient cover for a hand edit in the same window.
func TestAnExplainedDriftIsStillNotAutoResolvable(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2",
			ObservedAt: now.Add(-time.Minute)},
	})
	if exp.AutoResolvable {
		t.Error("a correlation was offered as grounds to auto-resolve")
	}
	if exp.Caveat == "" {
		t.Error("an explained drift carries no caveat, so it reads as proof")
	}
	if len(exp.SuggestedChecks) == 0 {
		t.Error("nothing is suggested that would actually settle it")
	}
}

// A package that changed AFTER the file was noticed cannot have caused it.
// This is the correlation mistake the whole design is meant to avoid.
func TestAPackageChangeAfterTheDetectionIsNotAnExplanation(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2",
			ObservedAt: now.Add(10 * time.Minute)},
	})
	if exp.Verdict == VerdictPackageUpgrade {
		t.Fatalf("a later package change explained an earlier file change: %+v", exp)
	}
	if len(exp.Correlated) != 0 {
		t.Errorf("correlated = %v, want none", exp.Correlated)
	}
}

// A change long before the file was touched is not an explanation either.
func TestAPackageChangeOutsideTheWindowIsNotAnExplanation(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2",
			ObservedAt: now.Add(-CorrelationWindow - time.Minute)},
	})
	if exp.Verdict != VerdictUnexplained {
		t.Errorf("verdict = %q, want %q", exp.Verdict, VerdictUnexplained)
	}
}

// The outcome that makes "explained" mean anything.
func TestNoPackageActivityMeansSomebodyEditedTheFile(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), nil)
	if exp.Verdict != VerdictUnexplained {
		t.Fatalf("verdict = %q, want %q", exp.Verdict, VerdictUnexplained)
	}
	if !strings.Contains(exp.Summary, "edited this file directly") {
		t.Errorf("the summary does not say what unexplained means: %s", exp.Summary)
	}
}

// Packages changing nearby is not an explanation unless one of them owns the
// file. A naive "was there an upgrade recently?" check gets this wrong and
// would resolve an intrusion.
func TestUnrelatedPackageActivityDoesNotExplainTheChange(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "nginx", PreviousVersion: "1", NewVersion: "2", ObservedAt: now.Add(-2 * time.Minute)},
		{Package: "curl", PreviousVersion: "3", NewVersion: "4", ObservedAt: now.Add(-3 * time.Minute)},
	})
	if exp.Verdict != VerdictPackageActivity {
		t.Fatalf("verdict = %q, want %q", exp.Verdict, VerdictPackageActivity)
	}
	if len(exp.Correlated) != 0 {
		t.Errorf("unrelated packages were counted as correlated: %v", exp.Correlated)
	}
	if len(exp.OtherActivity) != 2 {
		t.Errorf("otherActivity = %v, want both", exp.OtherActivity)
	}
	if !strings.Contains(exp.Summary, "does not explain") {
		t.Errorf("the summary implies an explanation: %s", exp.Summary)
	}
}

// A path no package owns means a package upgrade cannot be the explanation —
// a stronger statement than merely being unexplained.
func TestAnUnownedPathIsALocalChange(t *testing.T) {
	exp := ExplainDrift(drift("/etc/hosts"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2", ObservedAt: now.Add(-time.Minute)},
	})
	if exp.Verdict != VerdictLocalChange {
		t.Fatalf("verdict = %q, want %q", exp.Verdict, VerdictLocalChange)
	}
	if !exp.Ownership.Unowned {
		t.Error("ownership does not record that nothing owns this path")
	}
}

// An unknown path must not produce a confident "unexplained": the absence of
// a correlation means nothing when ownership was never resolved.
func TestAnUnknownPathSaysSoRatherThanClaimingUnexplained(t *testing.T) {
	exp := ExplainDrift(drift("/opt/vendor/weird.conf"), []PackageEvent{
		{Package: "vendor-thing", PreviousVersion: "1", NewVersion: "2", ObservedAt: now.Add(-time.Minute)},
	})
	if exp.Verdict != VerdictUnknownOwnership {
		t.Fatalf("verdict = %q, want %q", exp.Verdict, VerdictUnknownOwnership)
	}
	if exp.Caveat == "" {
		t.Error("no caveat, so a reader would take the absence of a correlation as meaningful")
	}
}

// A drop-in under a watched directory belongs to whatever owns the directory.
func TestADropInFileInheritsItsDirectorysOwner(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config.d/99-hardening.conf"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2",
			ObservedAt: now.Add(-time.Minute)},
	})
	if exp.Verdict != VerdictPackageUpgrade {
		t.Errorf("verdict = %q: a drop-in should inherit the directory's owner", exp.Verdict)
	}
}

// The same file is owned by differently-named packages across distributions,
// so any candidate owner counts.
func TestAnyCandidateOwnerNameCounts(t *testing.T) {
	for _, pkg := range []string{"openssh-server", "openssh"} {
		exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
			{Package: pkg, PreviousVersion: "1", NewVersion: "2", ObservedAt: now.Add(-time.Minute)},
		})
		if exp.Verdict != VerdictPackageUpgrade {
			t.Errorf("%s: verdict = %q", pkg, exp.Verdict)
		}
	}
}

// Package names differ in case between inventories; ownership matching must
// not be defeated by it.
func TestOwnerMatchingIsCaseInsensitive(t *testing.T) {
	exp := ExplainDrift(drift("/etc/sudoers"), []PackageEvent{
		{Package: "SUDO", PreviousVersion: "1", NewVersion: "2", ObservedAt: now.Add(-time.Minute)},
	})
	if exp.Verdict != VerdictPackageUpgrade {
		t.Errorf("verdict = %q, want a case-insensitive owner match", exp.Verdict)
	}
}

// The nearest change in time is the one an operator wants named.
func TestTheNearestCorrelatedChangeIsReportedFirst(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "openssh-server", PreviousVersion: "1", NewVersion: "2", ObservedAt: now.Add(-20 * time.Minute)},
		{Package: "openssh", PreviousVersion: "3", NewVersion: "4", ObservedAt: now.Add(-2 * time.Minute)},
	})
	if len(exp.Correlated) != 2 {
		t.Fatalf("correlated = %v", exp.Correlated)
	}
	if exp.Correlated[0].Package != "openssh" {
		t.Errorf("first correlated = %q, want the nearest in time", exp.Correlated[0].Package)
	}
}

// An install or removal is distinguished from an upgrade: only an upgrade
// rewrites a config file in place.
func TestAnInstallIsReportedWithItsAbsentPreviousVersion(t *testing.T) {
	exp := ExplainDrift(drift("/etc/ssh/sshd_config"), []PackageEvent{
		{Package: "openssh-server", NewVersion: "9.6p1", ObservedAt: now.Add(-time.Minute)},
	})
	if exp.Verdict != VerdictPackageUpgrade {
		t.Fatalf("verdict = %q", exp.Verdict)
	}
	if !strings.Contains(exp.Summary, "(absent)") {
		t.Errorf("an install is rendered as though it had a previous version: %s", exp.Summary)
	}
	if exp.Correlated[0].Upgrade() {
		t.Error("an install is reported as an upgrade")
	}
}

func TestOwnershipCoverageIsReportable(t *testing.T) {
	paths := KnownOwnedPaths()
	if len(paths) == 0 {
		t.Fatal("no ownership coverage is reported")
	}
	// The paths DefendSec watches by default must be covered, or the default
	// deployment gets "unknown ownership" on every alert.
	for _, want := range []string{
		"/etc/ssh/sshd_config", "/etc/sudoers", "/etc/passwd",
		"/etc/group", "/etc/hosts", "/etc/crypto-policies/config",
	} {
		own := OwnersOf(want)
		if !own.Known {
			t.Errorf("%s is watched by default but has no ownership entry", want)
		}
	}
}
