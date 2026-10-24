// Package debian parses the Debian Security Tracker JSON.
//
// Source: https://security-tracker.debian.org/tracker/data/json
//
// The document is {source-package: {CVE: {description, releases: {codename:
// {status, fixed_version, urgency, nodsa, nodsa_reason}}}}}. It is about 86 MB,
// so it is decoded one source package at a time.
//
// The tracker is keyed by SOURCE package and does not list binary package
// names. Ranges therefore carry the source name in both Package and
// SourcePackage; a matcher has to map an installed binary package to its source
// (dpkg's Source field) before it can use them. That is a limitation of this
// feed, not something the parser can paper over.
//
// Status mapping (per release):
//
//	resolved, fixed_version "0"            → not_affected (never vulnerable)
//	resolved, fixed_version V              → fixed in V
//	open, urgency unimportant|end-of-life  → will_not_fix
//	open, nodsa_reason "ignored"           → will_not_fix
//	open (anything else)                   → affected
//	undetermined                           → under_investigation
package debian

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"defendsec/internal/feeds"
)

// Releases maps a Debian codename to its os-release VERSION_ID.
var Releases = map[string]string{
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
}

type release struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
	NoDSA        string `json:"nodsa"`
	NoDSAReason  string `json:"nodsa_reason"`
}

type cveRecord struct {
	Description string             `json:"description"`
	Releases    map[string]release `json:"releases"`
}

// Parse streams the document and emits one advisory per (source package, CVE)
// that has an entry for at least one of the wanted releases. wanted maps codename
// to VERSION_ID (use Releases, or a subset).
func Parse(r io.Reader, wanted map[string]string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return st, err
	}
	pkgs := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return st, fmt.Errorf("debian: %w", err)
		}
		pkg, ok := tok.(string)
		if !ok {
			return st, fmt.Errorf("debian: package key is %T", tok)
		}
		var cves map[string]cveRecord
		if err := dec.Decode(&cves); err != nil {
			return st, fmt.Errorf("debian: package %q: %w", pkg, err)
		}
		pkgs++
		for id, rec := range cves {
			if !feeds.IsCVE(id) {
				st.Skip("non-CVE identifier")
				continue
			}
			adv, ok := convert(pkg, id, rec, wanted, &st)
			if !ok {
				continue
			}
			if err := emit(adv); err != nil {
				return st, err
			}
			st.Advisories++
			st.Ranges += len(adv.Ranges)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return st, err
	}
	if pkgs == 0 {
		return st, errors.New("debian: document has no packages")
	}
	return st, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("debian: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("debian: expected %q, got %v", want, tok)
	}
	return nil
}

func convert(pkg, id string, rec cveRecord, wanted map[string]string, st *feeds.Stats) (feeds.Advisory, bool) {
	adv := feeds.Advisory{ID: id, CVE: id, Summary: summarize(rec.Description), Severity: "unknown"}
	for codename, ver := range wanted {
		rel, ok := rec.Releases[codename]
		if !ok {
			continue
		}
		rg, ok := rangeFor(pkg, ver, rel)
		if !ok {
			st.Skip("unrecognised status " + rel.Status)
			continue
		}
		adv.Ranges = append(adv.Ranges, rg)
		if sev := feeds.NormalizeSeverity(rel.Urgency); feeds.SeverityRank(sev) > feeds.SeverityRank(adv.Severity) {
			adv.Severity = sev
		}
	}
	if len(adv.Ranges) == 0 {
		return adv, false
	}
	// Map iteration order is random; keep output stable.
	sortRanges(adv.Ranges)
	return adv, true
}

func rangeFor(pkg, ver string, rel release) (feeds.Range, bool) {
	rg := feeds.Range{Ecosystem: "Debian", Distro: "debian", Release: ver, Package: pkg, SourcePackage: pkg}
	switch rel.Status {
	case "resolved":
		if rel.FixedVersion == "0" {
			rg.State = feeds.NotAffected
		} else if rel.FixedVersion != "" {
			rg.State, rg.Fixed = feeds.Fixed, rel.FixedVersion
		} else {
			return rg, false
		}
	case "open":
		if rel.Urgency == "unimportant" || rel.Urgency == "end-of-life" || rel.NoDSAReason == "ignored" {
			rg.State = feeds.WillNotFix
		} else {
			rg.State = feeds.Affected
		}
	case "undetermined":
		rg.State = feeds.UnderInvestigation
	default:
		return rg, false
	}
	return rg, true
}

func sortRanges(rs []feeds.Range) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Release < rs[j].Release })
}

func summarize(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[:400]
		for !utf8.ValidString(s) { // do not cut a multibyte rune in half
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return s
}
