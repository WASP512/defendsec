package lifecycle

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Release is one release cycle of one product, as endoflife.date lists it.
// Dates are calendar dates, "YYYY-MM-DD", or "" when the feed gives none.
type Release struct {
	Product     string
	Label       string // "PHP"
	Cycle       string // "8.0"
	ReleaseDate string
	// EoasFrom is the day active support ended (bug fixes); security fixes may
	// continue after it. EolFrom is the day security support ended: the
	// product is end-of-life from then on. EoesFrom is the end of paid
	// extended security support, where a vendor sells it.
	EoasFrom string
	EolFrom  string
	EoesFrom string
	// IsEol is the feed's own flag, used only where it gives no EolFrom date.
	IsEol  bool
	IsLTS  bool
	Latest string
	Link   string

	// SnapshotID and FeedDate say which feed fetch the row came from. Storage
	// fills them; the judgement never reads them.
	SnapshotID *int64
	FeedDate   *time.Time
}

// Source is the matcher's view of the loaded endoflife.date data.
type Source interface {
	// EOLReleases returns every release cycle of the given products.
	EOLReleases(ctx context.Context, products []string) ([]Release, error)
}

// Stage is how far past support a release is.
type Stage string

const (
	// StageEOL: security support has ended. Nobody issues fixes any more.
	StageEOL Stage = "eol"
	// StageEOAS: active support has ended; security fixes continue until the
	// release's end of life.
	StageEOAS Stage = "eoas"
)

// StageOf reports where a release stands on the calendar day asOf
// ("YYYY-MM-DD"): StageEOL, StageEOAS, or "" when it is fully supported or the
// feed gives no end date.
func StageOf(r Release, asOf string) Stage {
	switch {
	case r.EolFrom != "" && r.EolFrom <= asOf:
		return StageEOL
	case r.EolFrom == "" && r.IsEol:
		return StageEOL
	case r.EoasFrom != "" && r.EoasFrom <= asOf:
		return StageEOAS
	}
	return ""
}

// Package is one installed package as the agent reports it.
type Package struct {
	Name    string
	Version string
	// Origin and OriginRepo are what the agent read about where the package
	// came from: the apt Origin: (or rpm Vendor) and the repository.
	Origin     string
	OriginRepo string
}

// Host is what the judgement needs to know about a machine.
type Host struct {
	Distro   string // os-release ID
	Manager  string // "dpkg", "rpm" or ""
	Packages []Package
	// AsOf is the calendar day to judge on; zero means today (UTC).
	AsOf time.Time
}

// Finding is one product release on one host that is past upstream support,
// installed from a source that is not the distribution's.
type Finding struct {
	Product      string
	ProductLabel string
	Cycle        string
	Stage        Stage
	// StageFrom is the date the stage began (the end-of-life date for
	// StageEOL, the end of active support for StageEOAS).
	StageFrom string
	EolFrom   string
	EoasFrom  string
	EoesFrom  string

	// Package is the representative package (the first by name), Installed its
	// version, Packages every package of the release found on the host.
	Package   string
	Installed string
	Packages  []string

	Origin      Origin
	OriginLabel string
	OriginRepo  string

	// UpgradeTo is the oldest newer release that still has active support, or
	// failing that security support: the fix is an upgrade when it is set.
	// UpgradeToSupportedUntil is when that release's security support ends.
	UpgradeTo               string
	UpgradeToSupportedUntil string
	// Fixed is the oldest newer release that still receives security fixes;
	// moving to it ends the finding.
	Fixed  string
	Latest string
	Link   string

	SnapshotID *int64
	FeedDate   *time.Time
	Reason     string
}

// AdvisoryID is the stable identifier of a lifecycle finding: it plays the part
// an advisory id plays for a vulnerability, so the same release on many hosts
// is one row in the exposure list.
func (f Finding) AdvisoryID() string { return "EOL:" + f.Product + ":" + f.Cycle }

// Stats counts what a run saw, so "no end-of-life findings" can be read next
// to what was examined: a package the table does not know, or whose origin is
// not known, was not assessed.
type Stats struct {
	Mapped        int // packages the mapping table knows
	DistroOrigin  int // mapped, but the host's distribution ships them: not judged
	OriginUnknown int // mapped, but where they came from could not be read: not assessed
	NoRelease     int // mapped third-party packages whose release the feed does not list: not assessed
	Supported     int // mapped third-party packages on a supported release
	Findings      int
}

// Assess judges the host's third-party software against the loaded release
// data. It returns an error only if the data source fails.
func Assess(ctx context.Context, src Source, h Host) ([]Finding, Stats, error) {
	var st Stats
	asOf := h.AsOf
	if asOf.IsZero() {
		asOf = time.Now()
	}
	day := asOf.UTC().Format("2006-01-02")

	type cand struct {
		pkg   Package
		match Match
		class Origin
		label string
	}
	var cands []cand
	products := map[string]struct{}{}
	for _, p := range h.Packages {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Version) == "" {
			continue
		}
		m, ok := Map(h.Manager, p.Name, p.Version)
		if !ok {
			continue
		}
		st.Mapped++
		class, label := ClassifyOrigin(h.Distro, h.Manager, p.Version, p.Origin, p.OriginRepo)
		switch class {
		case OriginDistro:
			st.DistroOrigin++
			continue
		case OriginUnknown:
			st.OriginUnknown++
			continue
		}
		products[m.Product] = struct{}{}
		cands = append(cands, cand{pkg: p, match: m, class: class, label: label})
	}
	if len(cands) == 0 {
		return nil, st, nil
	}
	names := make([]string, 0, len(products))
	for p := range products {
		names = append(names, p)
	}
	sort.Strings(names)
	rels, err := src.EOLReleases(ctx, names)
	if err != nil {
		return nil, st, err
	}
	byProduct := map[string]map[string]Release{}
	for _, r := range rels {
		if byProduct[r.Product] == nil {
			byProduct[r.Product] = map[string]Release{}
		}
		byProduct[r.Product][r.Cycle] = r
	}

	groups := map[string]*Finding{}
	var order []string
	for _, c := range cands {
		cycles := byProduct[c.match.Product]
		var rel Release
		var found bool
		for _, cy := range c.match.Cycles {
			if r, ok := cycles[cy]; ok {
				rel, found = r, true
				break
			}
		}
		if !found {
			st.NoRelease++
			continue
		}
		stage := StageOf(rel, day)
		if stage == "" {
			st.Supported++
			continue
		}
		key := rel.Product + "\x00" + rel.Cycle
		g, ok := groups[key]
		if !ok {
			g = &Finding{
				Product: rel.Product, ProductLabel: rel.Label, Cycle: rel.Cycle, Stage: stage,
				EolFrom: rel.EolFrom, EoasFrom: rel.EoasFrom, EoesFrom: rel.EoesFrom,
				Origin: c.class, OriginLabel: c.label, OriginRepo: c.pkg.OriginRepo,
				Latest: rel.Latest, Link: rel.Link, SnapshotID: rel.SnapshotID, FeedDate: rel.FeedDate,
			}
			if g.ProductLabel == "" {
				g.ProductLabel = rel.Product
			}
			if stage == StageEOL {
				g.StageFrom = rel.EolFrom
			} else {
				g.StageFrom = rel.EoasFrom
			}
			groups[key] = g
			order = append(order, key)
			g.Package, g.Installed = c.pkg.Name, c.pkg.Version
		}
		g.Packages = append(g.Packages, c.pkg.Name)
		// The representative is the first package by name, so a run is
		// deterministic whatever order the agent listed them in.
		if c.pkg.Name < g.Package {
			g.Package, g.Installed = c.pkg.Name, c.pkg.Version
			g.OriginLabel, g.OriginRepo = c.label, c.pkg.OriginRepo
		}
	}

	out := make([]Finding, 0, len(groups))
	for _, key := range order {
		g := groups[key]
		sort.Strings(g.Packages)
		g.Packages = dedupe(g.Packages)
		g.UpgradeTo, g.UpgradeToSupportedUntil, g.Fixed = upgradePath(byProduct[g.Product], g.Cycle, day)
		g.Reason = reason(*g)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Stage != b.Stage {
			return a.Stage == StageEOL // past security support ranks above past active support
		}
		return a.AdvisoryID() < b.AdvisoryID()
	})
	st.Findings = len(out)
	return out, st, nil
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func reason(f Finding) string {
	name := f.ProductLabel + " " + f.Cycle
	var r string
	switch f.Stage {
	case StageEOL:
		if f.EolFrom != "" {
			r = name + " reached end of life on " + f.EolFrom + ": upstream no longer issues security fixes for it"
		} else {
			r = name + " is end of life: upstream no longer issues security fixes for it"
		}
	default:
		r = name + " left active support on " + f.EoasFrom
		if f.EolFrom != "" {
			r += "; security fixes continue until " + f.EolFrom
		}
	}
	r += ". It came from a repository that is not the distribution's"
	if f.OriginLabel != "" {
		r += " (" + f.OriginLabel + ")"
	}
	r += ", so nobody else is patching it"
	if f.UpgradeTo != "" {
		r += "; upgrading to " + f.ProductLabel + " " + f.UpgradeTo + " fixes it"
		if f.UpgradeToSupportedUntil != "" {
			r += " (security support until " + f.UpgradeToSupportedUntil + ")"
		}
	}
	return r + "."
}

// upgradePath finds the release to move to. Candidates are releases newer than
// the installed cycle that are not past security support; the recommended one
// is the oldest with active support left (the smallest jump that does not
// land on a release already winding down), else the oldest still receiving
// security fixes. fixed is the oldest newer release still receiving security
// fixes. All are "" when no newer supported release exists, which means the
// fix is more than an upgrade.
func upgradePath(rels map[string]Release, cycle, day string) (to, until, fixed string) {
	var newer []Release
	for _, r := range rels {
		if cmpCycle(r.Cycle, cycle) <= 0 || !numericCycle(r.Cycle) {
			continue
		}
		if StageOf(r, day) == StageEOL {
			continue
		}
		newer = append(newer, r)
	}
	if len(newer) == 0 {
		return "", "", ""
	}
	sort.Slice(newer, func(i, j int) bool { return cmpCycle(newer[i].Cycle, newer[j].Cycle) < 0 })
	fixed = newer[0].Cycle
	pick := newer[0]
	for _, r := range newer {
		if StageOf(r, day) == "" {
			pick = r
			break
		}
	}
	return pick.Cycle, pick.EolFrom, fixed
}

func numericCycle(c string) bool {
	if c == "" {
		return false
	}
	for _, p := range strings.Split(c, ".") {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// cmpCycle orders dotted numeric cycles ("9.6" < "10" < "10.11").
func cmpCycle(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// String is for logs and tests.
func (f Finding) String() string {
	return fmt.Sprintf("%s %s %s (%s) origin=%s", f.ProductLabel, f.Cycle, f.Stage, f.Package, f.OriginLabel)
}
