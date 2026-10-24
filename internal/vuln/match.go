package vuln

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Distro-aware matching.
//
// A Linux distribution fixes vulnerabilities by backporting patches, so the
// version number that matters is the distro's own: Ubuntu fixed CVE-2024-6387
// in openssh 1:8.9p1-3ubuntu0.10 and never shipped 9.8p1. Comparing an installed
// distro build with an upstream floor flags every patched host. This file
// matches instead on (distro, release, source package, CVE) against the ranges
// the distro's own security feed publishes, using that distro's version
// ordering. Upstream floors are consulted only for software the distro does not
// ship.

// FixState values; they are the advisory_ranges.fix_state strings.
const (
	StateAffected           = "affected"
	StateFixed              = "fixed"
	StateWillNotFix         = "will_not_fix"
	StateNotAffected        = "not_affected"
	StateUnderInvestigation = "under_investigation"
)

// Kind separates what the operator must act on from what is only worth knowing.
type Kind string

const (
	// KindFinding: the installed build is vulnerable.
	KindFinding Kind = "finding"
	// KindInformational: the distro has decided not to fix it (will_not_fix) or
	// has not decided yet (under_investigation). Shown, never counted as exposure.
	KindInformational Kind = "informational"
)

// Basis says which kind of range produced a finding.
type Basis string

const (
	BasisDistro   Basis = "distro"
	BasisUpstream Basis = "upstream"
)

// Coverage says whether the feeds could have said anything about this host. A
// host with zero findings and no coverage is not clean, it is unassessed.
type Coverage string

const (
	// CoverageFull: the host's distro and release have a feed loaded.
	CoverageFull Coverage = "covered"
	// CoverageNoFeed: the distro is known but no feed for that release is
	// loaded; only upstream floors could apply.
	CoverageNoFeed Coverage = "no_feed"
	// CoverageNoDistro: the agent did not report a distro (an agent older than
	// this matcher, or a platform without os-release such as Windows).
	CoverageNoDistro Coverage = "no_distro"
)

// Package is one installed package as the agent reports it.
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	SourcePackage string `json:"source_package,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// Host is what the matcher needs to know about a machine. Distro and Release
// are os-release ID and VERSION_ID exactly as reported.
type Host struct {
	Distro         string
	Release        string
	PackageManager string // "dpkg", "rpm" or ""
	Packages       []Package
}

// Candidate is one advisory range with the advisory and feed context a finding
// must record. Storage fills it; the matcher never touches the database.
type Candidate struct {
	RangeID       int64
	AdvisoryID    string
	CVE           string
	Severity      string
	Summary       string
	KEV           bool
	EPSS          *float64
	CVSS          *float64
	Ecosystem     string
	Distro        string
	Release       string
	Package       string
	SourcePackage string
	Introduced    string
	Fixed         string
	State         string
	SnapshotID    *int64
	Feed          string
	FeedDate      *time.Time
}

// RangeSource is the matcher's view of the advisory store.
type RangeSource interface {
	// DistroRanges returns every range for the distro and release (including
	// ranges that apply to all releases of the distro) whose package or source
	// package is one of names.
	DistroRanges(ctx context.Context, distro, release string, names []string) ([]Candidate, error)
	// UpstreamRanges returns distro-less ranges, from the ecosystems that
	// describe software installed outside a distro's package set, for names.
	UpstreamRanges(ctx context.Context, names []string) ([]Candidate, error)
	// DistroCovered reports whether any feed data is loaded for the distro and
	// release.
	DistroCovered(ctx context.Context, distro, release string) (bool, error)
}

// Finding is one advisory that applies to one package on one host.
type Finding struct {
	AdvisoryID    string
	CVE           string
	RangeID       int64
	SnapshotID    *int64
	Feed          string
	FeedDate      *time.Time
	Kind          Kind
	Basis         Basis
	Package       string // installed binary package
	SourcePackage string
	Installed     string
	Fixed         string // version that fixes it; empty when no fix is published
	FixState      string
	Severity      string
	Summary       string
	KEV           bool
	EPSS          *float64
	CVSS          *float64
	Reason        string
}

// Key identifies a finding across runs: one per advisory per package family.
func (f Finding) Key() string {
	return f.AdvisoryID + "\x00" + familyOf(f.Package, f.SourcePackage)
}

// Stats counts what a run saw, so "zero findings" can be read next to what was
// examined.
type Stats struct {
	Packages      int // installed packages examined
	DistroMapped  int // packages the distro feed has an entry for
	Upstream      int // packages assessed against upstream floors
	NotAffected   int // advisories the distro marks not_affected, suppressed
	Undecidable   int // upstream comparisons that cannot be made safely
	Advisories    int // distinct advisories considered
	Informational int
}

// Result is the outcome for one host.
type Result struct {
	Distro   string // normalised (feed vocabulary)
	Release  string
	Coverage Coverage
	Findings []Finding
	Stats    Stats
}

// Open returns the findings of kind KindFinding.
func (r Result) Open() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind == KindFinding {
			out = append(out, f)
		}
	}
	return out
}

func familyOf(name, source string) string {
	if source != "" {
		return source
	}
	return name
}

// NormalizeDistro maps os-release ID and VERSION_ID onto the (distro, release)
// vocabulary advisory feeds use, and chooses the version ordering. RHEL
// rebuilds (Rocky, AlmaLinux, CentOS Stream, Oracle) share RHEL's package
// versions and are matched against RHEL's feed by major release. Rolling
// releases have no release string.
func NormalizeDistro(id, versionID string, manager string) (distro, release string, scheme Scheme) {
	id = strings.ToLower(strings.TrimSpace(id))
	versionID = strings.TrimSpace(versionID)
	scheme = SchemeAuto
	switch manager {
	case "dpkg":
		scheme = SchemeDpkg
	case "rpm":
		scheme = SchemeRPM
	}
	switch id {
	case "":
		return "", "", scheme
	case "rhel", "rocky", "almalinux", "centos", "ol":
		major, _, _ := strings.Cut(versionID, ".")
		if scheme == SchemeAuto {
			scheme = SchemeRPM
		}
		return "rhel", major, scheme
	case "opensuse-tumbleweed", "opensuse-slowroll":
		if scheme == SchemeAuto {
			scheme = SchemeRPM
		}
		return id, "", scheme
	case "debian":
		if scheme == SchemeAuto {
			scheme = SchemeDpkg
		}
		// Debian point releases ("12.5") are not tracked separately.
		major, _, _ := strings.Cut(versionID, ".")
		return "debian", major, scheme
	case "ubuntu":
		if scheme == SchemeAuto {
			scheme = SchemeDpkg
		}
		return "ubuntu", versionID, scheme
	case "opensuse-leap", "sles", "sle-micro", "fedora", "amzn":
		if scheme == SchemeAuto {
			scheme = SchemeRPM
		}
	}
	return id, versionID, scheme
}

// work is the per-package state while matching.
type work struct {
	pkg     Package
	family  string
	mapped  bool
	byAdv   map[string]*group
	advList []string
}

// group collects every range of one advisory that applies to one package.
type group struct {
	cands []Candidate
}

// Match assesses a host. It returns an error only if the range source fails; a
// package it cannot judge is counted, never guessed.
func Match(ctx context.Context, src RangeSource, h Host) (Result, error) {
	distro, release, scheme := NormalizeDistro(h.Distro, h.Release, h.PackageManager)
	res := Result{Distro: distro, Release: release}
	res.Stats.Packages = len(h.Packages)

	switch {
	case distro == "":
		res.Coverage = CoverageNoDistro
	default:
		ok, err := src.DistroCovered(ctx, distro, release)
		if err != nil {
			return res, err
		}
		if ok {
			res.Coverage = CoverageFull
		} else {
			res.Coverage = CoverageNoFeed
		}
	}

	pkgs := make([]*work, 0, len(h.Packages))
	nameSet := map[string]struct{}{}
	for _, p := range h.Packages {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Version) == "" {
			continue
		}
		w := &work{pkg: p, family: familyOf(p.Name, p.SourcePackage), byAdv: map[string]*group{}}
		pkgs = append(pkgs, w)
		nameSet[p.Name] = struct{}{}
		if p.SourcePackage != "" {
			nameSet[p.SourcePackage] = struct{}{}
		}
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)

	advSeen := map[string]struct{}{}
	if res.Coverage == CoverageFull {
		cands, err := src.DistroRanges(ctx, distro, release, names)
		if err != nil {
			return res, err
		}
		bySource := map[string][]int{}
		byName := map[string][]int{}
		for i, c := range cands {
			if c.SourcePackage != "" {
				bySource[c.SourcePackage] = append(bySource[c.SourcePackage], i)
			} else {
				byName[c.Package] = append(byName[c.Package], i)
			}
			// A range naming a binary and a source applies through either.
			if c.SourcePackage != "" && c.Package != "" {
				byName[c.Package] = append(byName[c.Package], i)
			}
		}
		for _, w := range pkgs {
			seen := map[int]struct{}{}
			attach := func(idx []int) {
				for _, i := range idx {
					if _, dup := seen[i]; dup {
						continue
					}
					seen[i] = struct{}{}
					c := cands[i]
					if !rangeAppliesTo(c, w.pkg) {
						continue
					}
					w.mapped = true
					g := w.byAdv[c.AdvisoryID]
					if g == nil {
						g = &group{}
						w.byAdv[c.AdvisoryID] = g
						w.advList = append(w.advList, c.AdvisoryID)
					}
					g.cands = append(g.cands, c)
				}
			}
			if w.pkg.SourcePackage != "" {
				attach(bySource[w.pkg.SourcePackage])
			}
			attach(byName[w.pkg.Name])
			if w.pkg.SourcePackage == "" {
				// Old agent or rpm without SOURCERPM: the binary name is the
				// best guess at the source name, and Debian's tracker keys on it.
				attach(bySource[w.pkg.Name])
			}
		}
	}

	// Findings are merged per (advisory, package family): a source package that
	// builds ten binaries is one finding, not ten.
	merged := map[string]Finding{}
	for _, w := range pkgs {
		if !w.mapped {
			continue
		}
		res.Stats.DistroMapped++
		for _, adv := range w.advList {
			advSeen[adv] = struct{}{}
			f, st := judge(w, w.byAdv[adv].cands, scheme)
			switch st {
			case judgeNotAffected:
				res.Stats.NotAffected++
			case judgeFinding:
				addFinding(merged, f)
			}
		}
	}

	// Upstream floors: only for packages the distro feed does not mention.
	var unmapped []*work
	for _, w := range pkgs {
		if !w.mapped {
			unmapped = append(unmapped, w)
		}
	}
	if len(unmapped) > 0 {
		upNames := make([]string, 0, len(unmapped))
		for _, w := range unmapped {
			upNames = append(upNames, w.pkg.Name)
		}
		sort.Strings(upNames)
		ups, err := src.UpstreamRanges(ctx, upNames)
		if err != nil {
			return res, err
		}
		for _, w := range unmapped {
			var hit bool
			for _, c := range ups {
				if c.State != StateFixed || c.Fixed == "" || !PackageMatches(c.Package, w.pkg.Name) {
					continue
				}
				hit = true
				advSeen[c.AdvisoryID] = struct{}{}
				a := Assess(w.pkg.Version, c.Fixed, scheme)
				switch a.Verdict {
				case VerdictVulnerable:
					addFinding(merged, newFinding(c, w.pkg, w.pkg.Version, BasisUpstream, KindFinding, a.Reason))
				case VerdictUnknown:
					res.Stats.Undecidable++
				}
			}
			if hit {
				res.Stats.Upstream++
			}
		}
	}

	res.Stats.Advisories = len(advSeen)
	for _, f := range merged {
		res.Findings = append(res.Findings, f)
		if f.Kind == KindInformational {
			res.Stats.Informational++
		}
	}
	sort.Slice(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Kind != b.Kind {
			return a.Kind == KindFinding
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		return a.Key() < b.Key()
	})
	return res, nil
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// addFinding keeps one finding per key. A real finding outranks an
// informational one, and between two the one with the lower package name wins
// so a run is deterministic.
func addFinding(m map[string]Finding, f Finding) {
	k := f.Key()
	prev, ok := m[k]
	if !ok {
		m[k] = f
		return
	}
	if prev.Kind != f.Kind {
		if f.Kind == KindFinding {
			m[k] = f
		}
		return
	}
	if f.Package < prev.Package {
		m[k] = f
	}
}

// rangeAppliesTo reports whether the range names this package, directly or
// through its source package.
func rangeAppliesTo(c Candidate, p Package) bool {
	if c.SourcePackage != "" {
		if p.SourcePackage != "" {
			return c.SourcePackage == p.SourcePackage
		}
		return c.SourcePackage == p.Name || c.Package == p.Name
	}
	return c.Package == p.Name || (p.SourcePackage != "" && c.Package == p.SourcePackage)
}

// versionFor picks the installed version to compare against a range: the
// source version when the range is keyed on the source package and the agent
// reported one, otherwise the binary version.
func versionFor(c Candidate, p Package) string {
	if c.SourcePackage != "" && p.SourcePackage != "" && p.SourceVersion != "" && c.SourcePackage == p.SourcePackage {
		return p.SourceVersion
	}
	return p.Version
}

type judgement int

const (
	judgeClean judgement = iota
	judgeNotAffected
	judgeFinding // a finding or an informational entry; see Finding.Kind
)

// judge decides one advisory for one package from all of its applicable ranges.
//
//   - not_affected on the distro's side wins: the distro says the code is not
//     vulnerable (or the vulnerable code was never shipped).
//   - A fixed range the installed version has reached means patched. Several
//     fixed ranges can apply (security pocket and ESM); reaching any of them is
//     enough, because the point of this matcher is never to flag a patched host.
//   - Otherwise the host is vulnerable if a fixed range is above it or the
//     distro lists the package as affected with no fix.
//   - will_not_fix and under_investigation are informational, shown but not
//     counted.
func judge(w *work, cands []Candidate, scheme Scheme) (Finding, judgement) {
	var (
		bestFixed   *Candidate // lowest fixed version above the installed one
		bestVer     string
		affected    *Candidate
		informative *Candidate
		clean       bool
		notAff      bool
	)
	for i := range cands {
		c := cands[i]
		ver := versionFor(c, w.pkg)
		if c.Introduced != "" && Compare(ver, c.Introduced, scheme) < 0 {
			continue // installed predates the vulnerable code
		}
		switch c.State {
		case StateNotAffected:
			notAff = true
		case StateFixed:
			if c.Fixed == "" {
				continue
			}
			if Compare(ver, c.Fixed, scheme) >= 0 {
				clean = true
				continue
			}
			if bestFixed == nil || Compare(c.Fixed, bestFixed.Fixed, scheme) < 0 {
				cc := c
				bestFixed, bestVer = &cc, ver
			}
		case StateAffected:
			if c.Fixed != "" && Compare(ver, c.Fixed, scheme) >= 0 {
				clean = true
				continue
			}
			cc := c
			affected = &cc
		case StateWillNotFix, StateUnderInvestigation:
			cc := c
			informative = &cc
		}
	}
	switch {
	case notAff:
		return Finding{}, judgeNotAffected
	case clean:
		return Finding{}, judgeClean
	case bestFixed != nil:
		return newFinding(*bestFixed, w.pkg, bestVer, BasisDistro, KindFinding,
			"installed version is below the version the distro fixed this in"), judgeFinding
	case affected != nil:
		return newFinding(*affected, w.pkg, w.pkg.Version, BasisDistro, KindFinding,
			"the distro lists this package as affected and has published no fix"), judgeFinding
	case informative != nil:
		reason := "the distro has decided not to fix this"
		if informative.State == StateUnderInvestigation {
			reason = "the distro is still investigating this"
		}
		return newFinding(*informative, w.pkg, w.pkg.Version, BasisDistro, KindInformational, reason), judgeFinding
	}
	return Finding{}, judgeClean
}

func newFinding(c Candidate, p Package, installed string, basis Basis, kind Kind, reason string) Finding {
	return Finding{
		AdvisoryID: c.AdvisoryID, CVE: c.CVE, RangeID: c.RangeID, SnapshotID: c.SnapshotID,
		Feed: c.Feed, FeedDate: c.FeedDate, Kind: kind, Basis: basis,
		Package: p.Name, SourcePackage: p.SourcePackage, Installed: installed,
		Fixed: c.Fixed, FixState: c.State, Severity: c.Severity, Summary: c.Summary,
		KEV: c.KEV, EPSS: c.EPSS, CVSS: c.CVSS, Reason: reason,
	}
}
