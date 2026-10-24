// Package rhel turns Red Hat's OVAL v2 patch feed into advisory ranges.
//
// Source: https://security.access.redhat.com/data/oval/v2/RHEL<N>/rhel-<N>.oval.xml.bz2
//
// Each "patch" definition is one erratum (RHSA/RHBA/RHEA): the CVEs it fixes
// and, per binary RPM, "installed EVR is earlier than <fixed>". Ranges carry
// distro "rhel" and the major release ("9"). AlmaLinux and Rocky rebuild RHEL
// with the same package versions, so a matcher maps them onto distro "rhel"
// rather than DefendSec duplicating every row.
//
// Not covered, and counted as skipped instead of guessed:
//   - definitions that apply only when an AppStream module stream is enabled
//     ("Module nodejs:18 is enabled"). The ranges would be false positives for a
//     host that has the package from another stream, and DefendSec does not yet
//     collect enabled streams.
//   - the "including-unpatched" feed's vulnerability-class definitions
//     (affected / will-not-fix); only fixed errata are read.
//   - kernel running-version tests.
package rhel

import (
	"fmt"
	"strings"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/oval"
)

// Parse reads one major release's patch OVAL document (decompressed) and emits
// one advisory per CVE per erratum. release is the major version, e.g. "9".
func Parse(open oval.Opener, release string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	doc, err := oval.Read(open, "patch")
	if err != nil {
		return st, fmt.Errorf("rhel: %w", err)
	}
	for _, def := range doc.Defs {
		if len(def.CVEs) == 0 {
			if len(def.RefCVEs) == 0 {
				st.Skip("erratum without CVE")
				continue
			}
			for _, id := range def.RefCVEs {
				def.CVEs = append(def.CVEs, oval.CVE{ID: id})
			}
		}
		modular := false
		for _, c := range def.Criteria {
			if strings.HasPrefix(c.Comment, "Module ") && strings.HasSuffix(c.Comment, " is enabled") {
				modular = true
				break
			}
		}
		ranges := rangesFor(doc, def, release)
		if len(ranges) == 0 {
			continue
		}
		if modular {
			for range ranges {
				st.Skip("module-stream range")
			}
			continue
		}
		for _, c := range def.CVEs {
			if !feeds.IsCVE(c.ID) {
				st.Skip("malformed CVE id")
				continue
			}
			sev := c.Impact
			if sev == "" {
				sev = def.Severity
			}
			adv := feeds.Advisory{
				ID: c.ID, CVE: c.ID, Summary: def.Title,
				Severity: feeds.NormalizeSeverity(sev), Ranges: ranges,
			}
			if score, vec, ok := feeds.SplitCVSS(c.CVSS3); ok {
				adv.CVSSScore, adv.CVSSVector = &score, vec
			}
			if c.CWE != "" {
				for _, w := range strings.FieldsFunc(c.CWE, func(r rune) bool { return r == '|' || r == ',' || r == ' ' }) {
					adv.CWE = append(adv.CWE, w)
				}
			}
			if err := emit(adv); err != nil {
				return st, err
			}
			st.Advisories++
			st.Ranges += len(ranges)
		}
	}
	return st, nil
}

func rangesFor(doc *oval.Doc, def oval.Definition, release string) []feeds.Range {
	var out []feeds.Range
	seen := map[string]bool{}
	for _, crit := range def.Criteria {
		test, ok := doc.Tests[crit.TestRef]
		if !ok || test.Kind != "rpminfo_test" {
			continue
		}
		state, ok := doc.States[test.State]
		if !ok || state.EVR == "" || state.EVROp != "less than" {
			continue // signature checks, "is installed" and the like
		}
		for _, name := range doc.Names(test) {
			key := name + "\x00" + state.EVR
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, feeds.Range{
				Ecosystem: "Red Hat", Distro: "rhel", Release: release,
				Package: name, Fixed: state.EVR, State: feeds.Fixed,
			})
		}
	}
	return out
}
