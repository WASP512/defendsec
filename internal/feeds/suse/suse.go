// Package suse turns SUSE's per-CVE OVAL feed into advisory ranges.
//
// Source: https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.16.0-affected.xml.bz2
// (and opensuse.tumbleweed-affected.xml.bz2). The "-affected" variant is a
// superset of the plain file: fixed packages, packages SUSE says are not
// affected, and packages that are affected with no fix yet.
//
// Each definition is one CVE. Its criteria carry, per package, one of:
//
//	"<pkg> is not affected"  → not_affected
//	"<pkg> is affected"      → affected (no fixed version published)
//	a test "<pkg> is <EVR"   → fixed in EVR (installed older than EVR is vulnerable)
//
// Distro is the os-release ID ("opensuse-leap", "opensuse-tumbleweed"); Leap
// has a release ("16.0"), Tumbleweed is rolling and has none.
package suse

import (
	"fmt"
	"strings"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/oval"
)

// Parse reads one SUSE OVAL document (decompressed). distro is the os-release
// ID and release the VERSION_ID ("" for a rolling release).
func Parse(open oval.Opener, distro, release string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	doc, err := oval.Read(open, "vulnerability")
	if err != nil {
		return st, fmt.Errorf("suse: %w", err)
	}
	for _, def := range doc.Defs {
		if !feeds.IsCVE(def.Title) {
			st.Skip("definition without CVE title")
			continue
		}
		ranges := rangesFor(doc, def, distro, release)
		if len(ranges) == 0 {
			st.Skip("CVE without package ranges")
			continue
		}
		adv := feeds.Advisory{
			ID: def.Title, CVE: def.Title, Summary: def.Title,
			Severity: feeds.NormalizeSeverity(def.Severity), Ranges: ranges,
		}
		if len(def.CVEs) > 0 {
			c := def.CVEs[0]
			if c.Impact != "" {
				adv.Severity = feeds.NormalizeSeverity(c.Impact)
			}
			if score, vec, ok := feeds.SplitCVSS(c.CVSS3); ok {
				adv.CVSSScore, adv.CVSSVector = &score, vec
			}
		}
		if err := emit(adv); err != nil {
			return st, err
		}
		st.Advisories++
		st.Ranges += len(ranges)
	}
	return st, nil
}

func rangesFor(doc *oval.Doc, def oval.Definition, distro, release string) []feeds.Range {
	var out []feeds.Range
	seen := map[string]bool{}
	add := func(name string, state feeds.FixState, fixed string) {
		key := name + "\x00" + string(state) + "\x00" + fixed
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, feeds.Range{
			Ecosystem: "openSUSE", Distro: distro, Release: release,
			Package: name, Fixed: fixed, State: state,
		})
	}
	for _, crit := range def.Criteria {
		test, ok := doc.Tests[crit.TestRef]
		if !ok || test.Kind != "rpminfo_test" {
			continue
		}
		names := doc.Names(test)
		switch {
		case strings.HasSuffix(crit.Comment, " is not affected"):
			for _, n := range names {
				add(n, feeds.NotAffected, "")
			}
		case strings.HasSuffix(crit.Comment, " is affected"):
			for _, n := range names {
				add(n, feeds.Affected, "")
			}
		default:
			state, ok := doc.States[test.State]
			if !ok || state.EVR == "" || state.EVROp != "less than" {
				continue // release check, signature check
			}
			for _, n := range names {
				add(n, feeds.Fixed, state.EVR)
			}
		}
	}
	return out
}
