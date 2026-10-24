package vuln

import (
	"context"
	"strings"

	"defendsec/internal/lifecycle"
)

// Severities of lifecycle findings. A release past security support gets no
// fixes for anything found in it from now on, which is a high exposure by
// construction; one past active support only still gets security fixes.
// Neither has a CVSS or EPSS score, so they rank among the unscored findings
// by this label (see docs/EXPOSURE.md).
const (
	SeverityEOL  = "high"
	SeverityEOAS = "low"
)

// assessEOL adds the application end-of-life findings of host h to res. The
// package list the agent reports already says where each package came from;
// lifecycle.Assess judges only what did not come from the host's own
// distribution.
func assessEOL(ctx context.Context, src lifecycle.Source, h Host, res *Result) error {
	lh := lifecycle.Host{Distro: strings.ToLower(strings.TrimSpace(h.Distro)), Manager: h.PackageManager, AsOf: h.AsOf}
	lh.Packages = make([]lifecycle.Package, 0, len(h.Packages))
	for _, p := range h.Packages {
		lh.Packages = append(lh.Packages, lifecycle.Package{Name: p.Name, Version: p.Version, Origin: p.Origin, OriginRepo: p.OriginRepo})
	}
	found, st, err := lifecycle.Assess(ctx, src, lh)
	if err != nil {
		return err
	}
	res.Stats.EOLMapped = st.Mapped
	res.Stats.EOLDistroOrigin = st.DistroOrigin
	res.Stats.EOLOriginUnknown = st.OriginUnknown
	res.Stats.EOLNoRelease = st.NoRelease
	res.Stats.EOLSupported = st.Supported
	for _, lf := range found {
		res.Findings = append(res.Findings, eolFinding(lf))
	}
	return nil
}

func eolFinding(lf lifecycle.Finding) Finding {
	sev, state, summary := SeverityEOL, "end_of_life", lf.ProductLabel+" "+lf.Cycle+" is end of life"
	if lf.EolFrom != "" && lf.Stage == lifecycle.StageEOL {
		summary = lf.ProductLabel + " " + lf.Cycle + " reached end of life on " + lf.EolFrom
	}
	if lf.Stage == lifecycle.StageEOAS {
		sev, state = SeverityEOAS, "end_of_active_support"
		summary = lf.ProductLabel + " " + lf.Cycle + " left active support on " + lf.EoasFrom
	}
	return Finding{
		AdvisoryID: lf.AdvisoryID(), SnapshotID: lf.SnapshotID, Feed: "endoflife", FeedDate: lf.FeedDate,
		Kind: KindEOL, Basis: BasisLifecycle,
		// The product is the family: one release of one product is one finding
		// per host, however many of its packages are installed or which one is
		// listed first.
		Package: lf.Package, SourcePackage: lf.Product, Installed: lf.Installed,
		FixState: state, Severity: sev, Summary: summary, Reason: lf.Reason,
		EOL: &EOLDetail{
			Product: lf.Product, ProductLabel: lf.ProductLabel, Cycle: lf.Cycle, Stage: string(lf.Stage),
			StageFrom: lf.StageFrom, EolFrom: lf.EolFrom, EoasFrom: lf.EoasFrom, EoesFrom: lf.EoesFrom,
			Packages: lf.Packages, Origin: lf.OriginLabel, OriginRepo: lf.OriginRepo,
			UpgradeTo: lf.UpgradeTo, UpgradeToSupportedUntil: lf.UpgradeToSupportedUntil,
			Latest: lf.Latest, Link: lf.Link,
		},
	}
}
