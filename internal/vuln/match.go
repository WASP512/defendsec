package vuln

import (
	"context"
	"sort"
	"strings"
	"time"

	"defendsec/internal/lifecycle"
	"defendsec/internal/repohealth"
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
	// KindFinding: the installed build is vulnerable and the distro has a fix
	// to install. This is the "fix these" list.
	KindFinding Kind = "finding"
	// KindUnfixed: the distro lists the package as affected and has published
	// no fix. Real exposure, but nothing to install; a fully patched host can
	// still have these (Debian's tracker lists open CVEs). Counted apart from
	// findings so "patched" means "no fix left to apply".
	KindUnfixed Kind = "unfixed"
	// KindInformational: the distro has decided not to fix it (will_not_fix) or
	// has not decided yet (under_investigation). Shown, never counted as exposure.
	KindInformational Kind = "informational"
	// KindAwaitingVendor: the upstream vendor (Red Hat) has fixed it, but the
	// distribution that rebuilds the vendor's packages (Rocky, AlmaLinux) has
	// not released the rebuild yet, so the host cannot install a fix. It is
	// exposure to watch, not work to schedule: it counts with the no-fix
	// bucket, never as fixable. A KEV entry here is still urgent.
	KindAwaitingVendor Kind = "awaiting_vendor"
	// KindEOL: software from a third-party repository (or installed outside a
	// package manager) whose upstream has stopped issuing security fixes, or
	// has stopped active support. No distro tracker covers it, so nobody is
	// patching it; the remedy is to upgrade to a supported release. It belongs
	// to the fix bucket beside KindFinding. Software from the host's own
	// distribution never gets one: it follows the distribution's lifecycle.
	KindEOL Kind = "eol"
	// KindRepoHealth: an enabled package repository whose signing key has
	// expired or is missing, or whose index has stopped refreshing. Updates from
	// that repository have silently stopped, so the host's pending updates
	// cannot be believed and nothing it publishes is being matched. It belongs
	// to the fix bucket: the remedy is to install the vendor's current key (or
	// refresh the index) and is work for this week. See internal/repohealth.
	KindRepoHealth Kind = "repo_health"
)

// Basis says which kind of range produced a finding.
type Basis string

const (
	BasisDistro   Basis = "distro"
	BasisUpstream Basis = "upstream"
	// BasisLifecycle: the finding comes from a release calendar
	// (endoflife.date), not from an advisory range.
	BasisLifecycle Basis = "lifecycle"
	// BasisHost: the finding comes from what the host reports about its own
	// configuration (its repositories), not from an advisory or a calendar.
	BasisHost Basis = "host"
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
	// Origin is where the package came from, as the agent read it: the apt
	// Origin: of the repository that carries the installed version, or the rpm
	// Vendor. OriginRepo is the repository itself. Both are empty for agents
	// older than origin reporting, and application end-of-life then does not
	// judge the package (see internal/lifecycle).
	Origin     string `json:"origin,omitempty"`
	OriginRepo string `json:"origin_repo,omitempty"`
}

// ecosystemUbuntuPro marks Ubuntu ranges whose fix ships only through Ubuntu
// Pro (ESM): security updates for universe packages and for releases past
// standard support.
const ecosystemUbuntuPro = "Ubuntu:Pro"

// Host is what the matcher needs to know about a machine. Distro and Release
// are os-release ID and VERSION_ID exactly as reported.
type Host struct {
	Distro         string
	Release        string
	PackageManager string // "dpkg", "rpm" or ""
	Packages       []Package
	// AsOf is the calendar day application end-of-life is judged on; the zero
	// value means today. It exists so a run can be reproduced.
	AsOf time.Time
	// RepoHealth is what the agent read about the host's package repositories
	// (nil from an agent that does not report it), and StaleAfter is how old an
	// index may be before it is a finding (0 means the default, 7 days).
	RepoHealth *repohealth.Report
	StaleAfter time.Duration
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
	// Issued is the date (YYYY-MM-DD) the vendor published the erratum behind
	// the range, when the feed says so.
	Issued string
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
	// UpstreamFixedOn is, for an awaiting_vendor finding, the date (YYYY-MM-DD)
	// Red Hat published the fix the host's own distribution has not released.
	UpstreamFixedOn string
	// EOL is set on findings of kind KindEOL.
	EOL *EOLDetail
	// Repo is set on findings of kind KindRepoHealth.
	Repo *RepoDetail
}

// EOLDetail is what an end-of-life finding says beyond the fields every
// finding has.
type EOLDetail struct {
	Product      string   `json:"product"`
	ProductLabel string   `json:"productLabel"`
	Cycle        string   `json:"cycle"`
	Stage        string   `json:"stage"` // "eol" or "eoas"
	StageFrom    string   `json:"stageFrom"`
	EolFrom      string   `json:"eolFrom,omitempty"`
	EoasFrom     string   `json:"eoasFrom,omitempty"`
	EoesFrom     string   `json:"eoesFrom,omitempty"`
	Packages     []string `json:"packages"`
	Origin       string   `json:"origin"`
	OriginRepo   string   `json:"originRepo,omitempty"`
	// UpgradeTo is the release to move to (empty when no newer supported
	// release exists); UpgradeToSupportedUntil is when it stops getting
	// security fixes.
	UpgradeTo               string `json:"upgradeTo,omitempty"`
	UpgradeToSupportedUntil string `json:"upgradeToSupportedUntil,omitempty"`
	Latest                  string `json:"latest,omitempty"`
	Link                    string `json:"link,omitempty"`
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
	Unfixed       int // findings of kind KindUnfixed
	Informational int // findings of kind KindInformational
	// AwaitingVendor counts findings of kind KindAwaitingVendor: fixed by Red
	// Hat, not yet released by the rebuild distribution the host runs.
	AwaitingVendor int
	// Application end-of-life (see internal/lifecycle). Of EOLMapped packages
	// the mapping table knows, EOLDistroOrigin are the distribution's own (not
	// judged: they follow its lifecycle) and EOLOriginUnknown had no readable
	// origin (not assessed, never clean). EOLNoRelease are third-party packages
	// of a release the calendar does not list; EOLSupported are on a supported
	// release.
	EOLMapped        int
	EOLDistroOrigin  int
	EOLOriginUnknown int
	EOLNoRelease     int
	EOLSupported     int
	// RepoHealthChecked is the number of repositories the host reported and
	// RepoHealthFindings how many of them have a problem. Zero checked with no
	// report means "not assessed", never "healthy".
	RepoHealthChecked  int
	RepoHealthFindings int
}

// Result is the outcome for one host.
type Result struct {
	// RepoHealthAssessed is true when the host reported repository evidence and
	// it was judged (even if every repository is healthy). False means the
	// host said nothing, and open repository findings must stay open.
	RepoHealthAssessed bool
	Distro             string // normalised (feed vocabulary)
	Release            string
	Coverage           Coverage
	Findings           []Finding
	Stats              Stats
}

// Open returns the findings of kind KindFinding: what has a fix to install.
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

// rebuildBase names the distribution a rebuild takes its packages from. Rocky
// and AlmaLinux rebuild RHEL: a fix reaches them only after Red Hat has shipped
// it and the rebuild has followed, so a host on one is judged against its own
// errata first and against Red Hat's feed second (see judge). CentOS Stream and
// Oracle Linux are matched against RHEL's feed directly.
func rebuildBase(distro string) string {
	switch distro {
	case "rocky", "almalinux":
		return "rhel"
	}
	return ""
}

// vendorName is how a finding names a rebuild distribution.
func vendorName(distro string) string {
	switch distro {
	case "rocky":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	}
	return distro
}

// NormalizeDistro maps os-release ID and VERSION_ID onto the (distro, release)
// vocabulary advisory feeds use, and chooses the version ordering. Rocky and
// AlmaLinux keep their own name: they publish their own errata, and the matcher
// pairs those with Red Hat's by major release. RHEL, CentOS Stream and Oracle
// Linux are matched against RHEL's feed by major release. Rolling releases have
// no release string.
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
	case "rocky", "almalinux":
		major, _, _ := strings.Cut(versionID, ".")
		if scheme == SchemeAuto {
			scheme = SchemeRPM
		}
		return id, major, scheme
	case "rhel", "centos", "ol":
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
		// A rebuild host is covered by its own errata feed: Red Hat's feed alone
		// cannot say whether the rebuild has shipped a fix, and a list built
		// from it alone is the false "fix this" list this split exists to avoid.
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
	base := rebuildBase(distro)

	pkgs := make([]*work, 0, len(h.Packages))
	onPro := usesUbuntuPro(h)
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
		if base != "" {
			// Red Hat's ranges, to tell "fixed upstream, not yet released by
			// the rebuild" from "no fix at all".
			up, err := src.DistroRanges(ctx, base, release, names)
			if err != nil {
				return res, err
			}
			cands = append(cands, up...)
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
			f, st := judge(w, w.byAdv[adv].cands, scheme, onPro, distro, base)
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

	// Application end-of-life: software from outside the distribution, judged
	// against the upstream release calendar. Only a source that carries the
	// calendar (the Postgres store does) is asked.
	if ls, ok := src.(lifecycle.Source); ok {
		if err := assessEOL(ctx, ls, h, &res); err != nil {
			return res, err
		}
	}

	// Repository health: independent of the distribution's feeds, and judged
	// even for a host no feed covers.
	assessRepoHealth(h, &res)

	res.Stats.Advisories = len(advSeen)
	for _, f := range merged {
		res.Findings = append(res.Findings, f)
		switch f.Kind {
		case KindUnfixed:
			res.Stats.Unfixed++
		case KindInformational:
			res.Stats.Informational++
		case KindAwaitingVendor:
			res.Stats.AwaitingVendor++
		}
	}
	sort.Slice(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Kind != b.Kind {
			return kindRank(a.Kind) < kindRank(b.Kind)
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

// usesUbuntuPro reports whether the host evidently receives Ubuntu Pro
// updates: an ESM build of any installed package ("+esm1", "~esm2"). It is a
// heuristic, because the agent does not yet report `pro status`; a Pro host
// with no ESM package installed is treated as not on Pro and sees ESM-only
// fixes as unfixed rather than as findings.
func usesUbuntuPro(h Host) bool {
	for _, p := range h.Packages {
		v := strings.ToLower(p.Version)
		if strings.Contains(v, "+esm") || strings.Contains(v, "~esm") {
			return true
		}
	}
	return false
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

func kindRank(k Kind) int {
	switch k {
	case KindFinding:
		return 0
	case KindEOL:
		return 1
	case KindRepoHealth:
		return 1
	case KindAwaitingVendor:
		return 2
	case KindUnfixed:
		return 3
	}
	return 4
}

// addFinding keeps one finding per key. A fix to install outranks "fixed
// upstream, not yet released", which outranks "no fix", which outranks
// informational, and between two of the same kind the one with the lower
// package name wins so a run is deterministic.
func addFinding(m map[string]Finding, f Finding) {
	k := f.Key()
	prev, ok := m[k]
	if !ok {
		m[k] = f
		return
	}
	if prev.Kind != f.Kind {
		if kindRank(f.Kind) < kindRank(prev.Kind) {
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
		return inheritEpoch(p.SourceVersion, p.Version)
	}
	return p.Version
}

// inheritEpoch gives a source version the epoch of the binary built from it.
// dpkg's Source: field and an rpm's SOURCERPM file name never carry the epoch,
// yet the epoch belongs to the source version, so every binary of that source
// has the same one. Comparing the bare source version against a feed's
// "1:0.5.0-1ubuntu22.04.1" would read as older and flag a patched host (seen on
// a patched Ubuntu 22.04: libbpf0).
func inheritEpoch(srcVer, binVer string) string {
	if hasEpoch(srcVer) {
		return srcVer
	}
	if i := strings.Index(binVer, ":"); i > 0 && hasEpoch(binVer[:i+1]) {
		return binVer[:i+1] + srcVer
	}
	return srcVer
}

// hasEpoch reports whether v starts with "<digits>:".
func hasEpoch(v string) bool {
	i := strings.Index(v, ":")
	if i <= 0 {
		return false
	}
	for _, r := range v[:i] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
//   - A range from Ubuntu Pro (ESM) counts only on a host that evidently uses
//     Pro. On any other host the fix is not installable, so the package is
//     "affected, no fix you can install", not a finding to act on this week.
//   - On a rebuild host (Rocky, AlmaLinux; base is "rhel") the ranges come from
//     two feeds: the rebuild's own errata and Red Hat's. Reaching either fixed
//     version means patched. A fix above the installed version is a finding to
//     install only if the rebuild has released it. If only Red Hat has, the
//     operator has nothing to install: the finding is awaiting_vendor, and says
//     when Red Hat shipped it.
func judge(w *work, cands []Candidate, scheme Scheme, onPro bool, distro, base string) (Finding, judgement) {
	var (
		bestFixed   *Candidate // lowest fixed version above the installed one
		bestVer     string
		bestUp      *Candidate // same, from the upstream vendor's feed (rebuild hosts only)
		bestUpVer   string
		affected    *Candidate
		informative *Candidate
		proOnly     *Candidate // fixed only by Ubuntu Pro, host not on Pro
		clean       bool
		notAff      bool
	)
	for i := range cands {
		c := cands[i]
		ver := versionFor(c, w.pkg)
		if c.Introduced != "" && Compare(ver, c.Introduced, scheme) < 0 {
			continue // installed predates the vulnerable code
		}
		if c.Ecosystem == ecosystemUbuntuPro && !onPro && c.State == StateFixed {
			if Compare(ver, c.Fixed, scheme) < 0 {
				cc := c
				proOnly = &cc
			} else {
				clean = true
			}
			continue
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
			if base != "" && c.Distro == base {
				if bestUp == nil || Compare(c.Fixed, bestUp.Fixed, scheme) < 0 {
					cc := c
					bestUp, bestUpVer = &cc, ver
				}
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
	case bestUp != nil:
		f := newFinding(*bestUp, w.pkg, bestUpVer, BasisDistro, KindAwaitingVendor, awaitingReason(*bestUp, distro))
		f.UpstreamFixedOn = bestUp.Issued
		return f, judgeFinding
	case proOnly != nil:
		return newFinding(*proOnly, w.pkg, versionFor(*proOnly, w.pkg), BasisDistro, KindUnfixed,
			"the fix ships only through Ubuntu Pro (ESM) and this host does not appear to use it"), judgeFinding
	case affected != nil:
		return newFinding(*affected, w.pkg, w.pkg.Version, BasisDistro, KindUnfixed,
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

// awaitingReason words an awaiting_vendor finding: what Red Hat shipped, when,
// and that the host's own distribution has not.
func awaitingReason(up Candidate, distro string) string {
	r := "fixed upstream by Red Hat in " + up.Fixed
	if up.Issued != "" {
		r += " on " + up.Issued
	}
	return r + "; not yet released by " + vendorName(distro)
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
