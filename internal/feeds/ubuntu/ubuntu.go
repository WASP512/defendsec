// Package ubuntu turns Canonical's USN OVAL feed into advisory ranges.
//
// Source: https://security-metadata.canonical.com/oval/com.ubuntu.<codename>.usn.oval.xml.bz2
//
// Each "patch" definition is one USN: the CVEs it fixes, and for every source
// package a test "binary version is less than <fixed>" over the binary package
// names built from it. One range is emitted per binary package, with the source
// package recorded alongside, so a matcher can key on either.
//
// Fixes shipped only through Ubuntu Pro (ESM) use the ecosystem "Ubuntu:Pro".
// A host without a Pro subscription cannot install them, so a matcher must not
// present them as available fixes for an unsubscribed host.
//
// Kernel definitions test the running kernel (uname), not an installed
// package, and are skipped and counted; kernel exposure needs its own handling.
package ubuntu

import (
	"fmt"
	"regexp"
	"strings"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/oval"
)

// Releases maps an Ubuntu codename to its os-release VERSION_ID.
var Releases = map[string]string{
	"focal":    "20.04",
	"jammy":    "22.04",
	"noble":    "24.04",
	"plucky":   "25.04",
	"questing": "25.10",
}

var commentRe = regexp.MustCompile(`^(\S+) source package in ([^,\s]+),`)

// Parse reads one release's USN OVAL document (already decompressed) and emits
// one advisory per CVE per USN. release is the VERSION_ID, e.g. "22.04".
func Parse(open oval.Opener, release string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	doc, err := oval.Read(open, "patch")
	if err != nil {
		return st, fmt.Errorf("ubuntu: %w", err)
	}
	for _, def := range doc.Defs {
		ranges := rangesFor(doc, def, release, &st)
		cves := def.CVEs
		if len(cves) == 0 {
			for _, id := range def.RefCVEs {
				cves = append(cves, oval.CVE{ID: id})
			}
		}
		if len(ranges) == 0 {
			continue
		}
		if len(cves) == 0 {
			st.Skip("definition without CVE")
			continue
		}
		for _, c := range cves {
			if !feeds.IsCVE(c.ID) {
				st.Skip("malformed CVE id")
				continue
			}
			sev := c.Priority
			if sev == "" {
				sev = def.Severity
			}
			adv := feeds.Advisory{
				ID: c.ID, CVE: c.ID, Summary: def.Title,
				Severity: feeds.NormalizeSeverity(sev), CVSSScore: c.CVSSScore, CVSSVector: c.CVSSVector,
				Ranges: ranges,
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

func rangesFor(doc *oval.Doc, def oval.Definition, release string, st *feeds.Stats) []feeds.Range {
	var out []feeds.Range
	seen := map[string]bool{}
	for _, crit := range def.Criteria {
		test, ok := doc.Tests[crit.TestRef]
		if !ok {
			st.Skip("criterion without test")
			continue
		}
		if test.Kind == "uname_test" {
			st.Skip("kernel running-version test")
			continue
		}
		if test.Kind != "dpkginfo_test" {
			continue
		}
		state, ok := doc.States[test.State]
		if !ok || state.EVR == "" || state.EVROp != "less than" {
			st.Skip("unsupported package state")
			continue
		}
		names := doc.Names(test)
		if len(names) == 0 {
			st.Skip("test without package names")
			continue
		}
		source, pocket := "", ""
		if m := commentRe.FindStringSubmatch(crit.Comment); m != nil {
			source, pocket = m[1], m[2]
		}
		eco := "Ubuntu"
		if strings.Contains(pocket, "esm") || strings.Contains(state.EVR, "~esm") {
			eco = "Ubuntu:Pro"
		}
		for _, name := range names {
			key := eco + "\x00" + name + "\x00" + state.EVR
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, feeds.Range{
				Ecosystem: eco, Distro: "ubuntu", Release: release,
				Package: name, SourcePackage: source,
				Fixed: state.EVR, State: feeds.Fixed,
			})
		}
	}
	return out
}
