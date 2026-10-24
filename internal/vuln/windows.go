package vuln

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Windows hosts read through an RMM have no package list the distro matcher can
// compare. What the RMM does know, per device, is the Windows updates it lists
// as not installed. Microsoft's Security Update Guide says which CVEs each
// update fixes, so a missing update is a finding for every CVE it fixes: the
// vendor's own fix, available to install.
//
// The Microsoft feed (internal/feeds/msrc) stores one range per (CVE, update):
// distro "windows", package "KB<digits>", fixed the same KB. This file reads
// those ranges back through the same RangeSource the distro matcher uses.

// WindowsDistro is the range distro of the Microsoft update feed. It names the
// space of KB numbers, not an operating system release: a cumulative update
// that serves Windows 10 1809 and Server 2019 is one KB.
const WindowsDistro = "windows"

// MissingPatch is one update an RMM lists for a device as not installed.
type MissingPatch struct {
	KB    string // "KB5122876"; see NormalizeKB
	Title string
	// Status is how the RMM classes it: "approved_pending" (approved by the
	// site's patch policy, waiting to install) or "not_approved".
	Status string
}

var kbRe = regexp.MustCompile(`(?i)^\s*(?:kb)?\s*([0-9]{5,9})\s*$`)

// NormalizeKB turns "5122876", "kb5122876" or " KB5122876 " into "KB5122876".
// It returns "" for anything that is not a KB number: a driver or definition
// update has none, and a title is not a KB.
func NormalizeKB(s string) string {
	m := kbRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return "KB" + m[1]
}

// MatchWindows maps the missing updates of one device to the CVEs they fix.
//
// Coverage is CoverageFull when the Microsoft feed is loaded and
// CoverageNoFeed when it is not: with no feed, no update can be mapped, and a
// device with no findings is not clean, only unexamined. Updates with no KB
// number, and KBs the feed does not know (not a security update, or older than
// the window the feed keeps), are examined but produce nothing; Stats.Packages
// counts the KBs examined and Stats.DistroMapped the ones the feed knew, so a
// caller can say how many it could not map.
func MatchWindows(ctx context.Context, src RangeSource, missing []MissingPatch) (Result, error) {
	res := Result{Distro: WindowsDistro, Coverage: CoverageNoFeed}
	covered, err := src.DistroCovered(ctx, WindowsDistro, "")
	if err != nil {
		return res, fmt.Errorf("windows feed coverage: %w", err)
	}
	if !covered {
		return res, nil
	}
	res.Coverage = CoverageFull

	byKB := map[string]MissingPatch{}
	for _, m := range missing {
		kb := NormalizeKB(m.KB)
		if kb == "" {
			continue
		}
		if prev, dup := byKB[kb]; !dup || (prev.Status == "not_approved" && m.Status == "approved_pending") {
			m.KB = kb
			byKB[kb] = m
		}
	}
	res.Stats.Packages = len(byKB)
	if len(byKB) == 0 {
		return res, nil
	}
	names := make([]string, 0, len(byKB))
	for kb := range byKB {
		names = append(names, kb)
	}
	sort.Strings(names)
	cands, err := src.DistroRanges(ctx, WindowsDistro, "", names)
	if err != nil {
		return res, fmt.Errorf("windows ranges: %w", err)
	}

	mapped := map[string]bool{}
	advisories := map[string]bool{}
	found := map[string]Finding{}
	for _, c := range cands {
		if c.State != StateFixed {
			continue
		}
		m, ok := byKB[c.Package]
		if !ok {
			continue
		}
		mapped[c.Package] = true
		advisories[c.AdvisoryID] = true
		f := newFinding(c, Package{Name: m.KB}, "not installed", BasisDistro, KindFinding, windowsReason(m))
		addFinding(found, f)
	}
	res.Stats.DistroMapped = len(mapped)
	res.Stats.Advisories = len(advisories)
	for _, f := range found {
		res.Findings = append(res.Findings, f)
	}
	sort.Slice(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		return a.Package < b.Package
	})
	return res, nil
}

func windowsReason(m MissingPatch) string {
	how := "listed by the RMM as not installed"
	switch m.Status {
	case "approved_pending":
		how = "approved in the RMM patch policy and waiting to install"
	case "not_approved":
		how = "not yet approved in the RMM patch policy"
	}
	s := m.KB + " fixes this and is " + how
	if t := strings.TrimSpace(m.Title); t != "" {
		s += " (" + t + ")"
	}
	return s
}
