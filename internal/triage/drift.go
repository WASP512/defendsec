package triage

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// File-integrity drift explanation (roadmap 4.3).

// CorrelationWindow is how far back a package change is looked for.
//
// Inventory arrives on a heartbeat interval, so a package upgrade and the file
// change it caused are observed in the same or adjacent reports rather than at
// the same instant. Wide enough to span a couple of heartbeats and the time an
// upgrade itself takes; narrow enough that "a package changed at some point
// today" is not offered as an explanation for a file edited this minute.
const CorrelationWindow = 30 * time.Minute

// Verdict is how well the drift is explained.
type Verdict string

const (
	// VerdictPackageUpgrade: a package that owns this path was upgraded
	// inside the window. The ordinary explanation, and the one most often
	// correct.
	VerdictPackageUpgrade Verdict = "package-upgrade"
	// VerdictPackageActivity: packages changed inside the window but none of
	// them is a known owner of this path. Weaker, and said to be weaker.
	VerdictPackageActivity Verdict = "package-activity"
	// VerdictLocalChange: nothing changed on this host inside the window, and
	// no package owns the path anyway. Somebody edited the file.
	VerdictLocalChange Verdict = "local-change"
	// VerdictUnexplained: no package activity can account for this. The
	// security-relevant outcome, and the reason this whole mechanism is worth
	// having — it is what lets "explained" mean something.
	VerdictUnexplained Verdict = "unexplained"
	// VerdictUnknownOwnership: the path is not in the ownership map, so
	// correlation could not be attempted properly.
	VerdictUnknownOwnership Verdict = "unknown-ownership"
)

// PackageEvent is one observed package transition, in the form this package
// needs. Defined here rather than taken from the store so the correlation is
// testable without a database.
type PackageEvent struct {
	Package         string
	PreviousVersion string
	NewVersion      string
	ObservedAt      time.Time
}

// Upgrade reports a version change rather than an install or removal.
func (e PackageEvent) Upgrade() bool {
	return e.PreviousVersion != "" && e.NewVersion != "" && e.PreviousVersion != e.NewVersion
}

// DriftEvent is the file change being explained.
type DriftEvent struct {
	Path       string
	Previous   string
	Current    string
	DetectedAt time.Time
	Action     string
}

// Explanation is what DefendSec can say about a drift event.
//
// # It explains; it does not resolve
//
// The roadmap calls a package-upgrade correlation "an excellent auto-resolve
// signal". This deliberately stops short of that, and the reason is worth
// recording: a package upgrade immediately before a security-relevant
// configuration file changes is both the most common innocent explanation and
// exactly the cover an attacker would choose. An upgrade of openssh-server
// does not stop a PermitRootLogin line from having been added by hand in the
// same window.
//
// So there is no auto-resolve. What there is instead is a verdict, the
// timeline it rests on, and — for the strongest case — the specific extra
// check that would turn the correlation into evidence. An operator who reads
// "explained, and here is why that is not proof" is better served than one
// whose alert queue silently emptied.
type Explanation struct {
	Verdict Verdict `json:"verdict"`
	// Summary is one sentence, written for the operator who will read it in
	// the alert rather than for the developer who wrote the rule.
	Summary string `json:"summary"`
	// Ownership records what was known about the path.
	Ownership Ownership `json:"ownership"`
	// Correlated are the package changes that support the verdict, closest in
	// time first.
	Correlated []PackageEvent `json:"correlated,omitempty"`
	// OtherActivity are changes inside the window that are not owners of this
	// path. Shown because "twelve other packages changed at the same moment"
	// is context an operator wants even when it is not the explanation.
	OtherActivity []PackageEvent `json:"otherActivity,omitempty"`
	// Caveat states what this explanation does not establish. Always
	// populated for a correlation-based verdict: an explanation that reads as
	// proof is worse than none.
	Caveat string `json:"caveat,omitempty"`
	// SuggestedChecks are the things that would actually settle it, phrased
	// so an operator or an agent can act on them.
	SuggestedChecks []string `json:"suggestedChecks,omitempty"`
	// AutoResolvable is always false, and is present as a field so that
	// anything consuming this cannot mistake a confident verdict for
	// permission to close the alert.
	AutoResolvable bool `json:"autoResolvable"`
	// WindowMinutes is the correlation window used, so a reader can judge the
	// verdict rather than take it on trust.
	WindowMinutes int `json:"windowMinutes"`
}

// ExplainDrift correlates a file change against package activity on the host.
//
// Pure: everything it needs is passed in, so the correlation can be tested
// against a constructed timeline rather than a live fleet.
func ExplainDrift(event DriftEvent, changes []PackageEvent) Explanation {
	own := OwnersOf(event.Path)
	exp := Explanation{
		Ownership:      own,
		WindowMinutes:  int(CorrelationWindow / time.Minute),
		AutoResolvable: false,
	}

	// Only changes inside the window, and only those at or before the
	// detection. A package that changed after the file was noticed cannot
	// have caused it, and offering it as an explanation would be the
	// correlation mistake this is meant to avoid.
	windowStart := event.DetectedAt.Add(-CorrelationWindow)
	var inWindow []PackageEvent
	for _, c := range changes {
		if c.ObservedAt.Before(windowStart) {
			continue
		}
		if c.ObservedAt.After(event.DetectedAt) {
			continue
		}
		inWindow = append(inWindow, c)
	}
	// Closest in time to the file change first: that is the one an operator
	// wants to see, and the ordering is part of the explanation.
	sort.Slice(inWindow, func(i, j int) bool {
		return inWindow[i].ObservedAt.After(inWindow[j].ObservedAt)
	})

	owners := map[string]bool{}
	for _, p := range own.Packages {
		owners[strings.ToLower(p)] = true
	}
	for _, c := range inWindow {
		if owners[strings.ToLower(c.Package)] {
			exp.Correlated = append(exp.Correlated, c)
		} else {
			exp.OtherActivity = append(exp.OtherActivity, c)
		}
	}

	switch {
	case own.Unowned:
		// No package owns the path, so no upgrade can explain it. This is a
		// stronger statement than "unexplained" and deserves its own verdict.
		exp.Verdict = VerdictLocalChange
		exp.Summary = fmt.Sprintf(
			"%s is not owned by any package, so this change was made locally. %s",
			event.Path, own.Note)
		exp.SuggestedChecks = []string{
			"Check who has recently logged in to this host.",
			"Compare the file against your configuration management's intended content, if it manages this path.",
		}

	case len(exp.Correlated) > 0:
		nearest := exp.Correlated[0]
		gap := event.DetectedAt.Sub(nearest.ObservedAt)
		exp.Verdict = VerdictPackageUpgrade
		exp.Summary = fmt.Sprintf(
			"%s changed %s after %s went from %s to %s, which owns that path. A package upgrade is the ordinary explanation for this.",
			event.Path, describeGap(gap), nearest.Package,
			orNone(nearest.PreviousVersion), orNone(nearest.NewVersion))
		exp.Caveat = "A correlation is not proof. An upgrade of the owning package is also the most convenient cover for a hand edit made in the same window, so this does not establish that the change was benign — only that there is an ordinary explanation available."
		exp.SuggestedChecks = []string{
			fmt.Sprintf("Compare the file against the version %s ships, which settles it either way.", nearest.Package),
			"Check whether the same file changed identically on other hosts that took the same upgrade. A change on one host only is not a package upgrade.",
			"Check who was logged in to this host during the window.",
		}

	case !own.Known:
		exp.Verdict = VerdictUnknownOwnership
		exp.Summary = fmt.Sprintf(
			"%s is not in DefendSec's path-ownership map, so a package upgrade could not be ruled in or out. %d package(s) changed on this host inside the window.",
			event.Path, len(inWindow))
		exp.Caveat = "DefendSec resolves path ownership from a curated map covering the paths it watches by default. This path is not in it, so the absence of a correlation here means nothing."
		exp.SuggestedChecks = []string{
			fmt.Sprintf("On the host, ask the package manager directly which package owns %s.", event.Path),
			"Check who was logged in to this host during the window.",
		}

	case len(exp.OtherActivity) > 0:
		exp.Verdict = VerdictPackageActivity
		exp.Summary = fmt.Sprintf(
			"%d package(s) changed on this host inside the window, but none of them owns %s. The upgrade activity does not explain this change.",
			len(exp.OtherActivity), event.Path)
		exp.Caveat = "Package activity near a file change is not an explanation for it unless the package owns the file."
		exp.SuggestedChecks = []string{
			"Treat this as an unexplained change until something accounts for it.",
			"Check who was logged in to this host during the window.",
		}

	default:
		// The outcome that makes the whole mechanism worth having.
		exp.Verdict = VerdictUnexplained
		exp.Summary = fmt.Sprintf(
			"Nothing on this host accounts for %s changing. No package that owns it was upgraded, and no other package changed inside the window either — so somebody or something edited this file directly.",
			event.Path)
		exp.SuggestedChecks = []string{
			"Check who has recently logged in to this host.",
			"Check the command history and the audit ledger for this host around the detection time.",
			"If this host is managed by configuration management, check whether it made this change.",
		}
	}
	return exp
}

// describeGap renders a duration for an operator rather than for a log.
func describeGap(d time.Duration) string {
	switch {
	case d < 0:
		// The file change was observed before the package change. Reported
		// plainly rather than rendered as a negative number, because the
		// ordering matters and a reader should notice it.
		return "shortly before"
	case d < time.Minute:
		return "less than a minute"
	case d < 2*time.Minute:
		return "about a minute"
	case d < time.Hour:
		return fmt.Sprintf("about %d minutes", int(d.Minutes()))
	default:
		return fmt.Sprintf("about %d hours", int(d.Hours()))
	}
}

func orNone(v string) string {
	if v == "" {
		return "(absent)"
	}
	return v
}
