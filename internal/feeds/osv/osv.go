// Package osv parses an OSV bulk export for one ecosystem.
//
// Source: https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip
//
// This is for software the fleet runs outside the system package manager
// (PyPI, npm, Go, Maven, crates.io, ...). It is off unless configured: the
// distro feeds are the authority for OS packages, and OSV's Debian/Ubuntu
// ecosystems are not used.
//
// The zip holds one JSON record per advisory. Each is read independently.
package osv

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"defendsec/internal/feeds"
)

// maxRecordBytes bounds one record; real ones are a few KB. A larger entry is a
// corrupt or hostile archive.
const maxRecordBytes = 16 << 20

type record struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Parse reads an all.zip for ecosystem (as spelled in OSV, e.g. "PyPI") and
// emits one advisory per record that has at least one usable range. The
// advisory ID is the record's first CVE alias if it has one, otherwise the OSV
// ID, so the same vulnerability reported by several OSV sources merges.
func Parse(ra io.ReaderAt, size int64, ecosystem string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return st, fmt.Errorf("osv: %w", err)
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if f.UncompressedSize64 > maxRecordBytes {
			return st, fmt.Errorf("osv: %s is %d bytes, over the %d limit", f.Name, f.UncompressedSize64, maxRecordBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return st, fmt.Errorf("osv: %s: %w", f.Name, err)
		}
		var rec record
		err = json.NewDecoder(io.LimitReader(rc, maxRecordBytes)).Decode(&rec)
		rc.Close()
		if err != nil {
			return st, fmt.Errorf("osv: %s: %w", f.Name, err)
		}
		adv, ok := convert(rec, ecosystem, &st)
		if !ok {
			continue
		}
		if err := emit(adv); err != nil {
			return st, err
		}
		st.Advisories++
		st.Ranges += len(adv.Ranges)
	}
	return st, nil
}

func convert(rec record, ecosystem string, st *feeds.Stats) (feeds.Advisory, bool) {
	if rec.ID == "" {
		st.Skip("record without id")
		return feeds.Advisory{}, false
	}
	if rec.Withdrawn != "" {
		st.Skip("withdrawn")
		return feeds.Advisory{}, false
	}
	adv := feeds.Advisory{ID: rec.ID, Severity: feeds.NormalizeSeverity(rec.DatabaseSpecific.Severity)}
	for _, a := range rec.Aliases {
		if feeds.IsCVE(a) {
			adv.ID, adv.CVE = a, a
			break
		}
	}
	adv.Summary = rec.Summary
	if adv.Summary == "" {
		adv.Summary = strings.Join(strings.Fields(rec.Details), " ")
		if len(adv.Summary) > 300 {
			adv.Summary = adv.Summary[:300]
		}
	}
	adv.CWE = rec.DatabaseSpecific.CWEIDs
	for _, s := range rec.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") && strings.HasPrefix(s.Score, "CVSS:3") {
			adv.CVSSVector = s.Score
		}
	}

	seen := map[string]bool{}
	add := func(r feeds.Range) {
		k := r.Package + "\x00" + r.Introduced + "\x00" + r.Fixed
		if !seen[k] {
			seen[k] = true
			adv.Ranges = append(adv.Ranges, r)
		}
	}
	for _, aff := range rec.Affected {
		if aff.Package.Ecosystem != ecosystem || aff.Package.Name == "" {
			continue
		}
		for _, rg := range aff.Ranges {
			if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
				st.Skip("range type " + rg.Type)
				continue
			}
			introduced, open := "", false
			base := feeds.Range{Ecosystem: ecosystem, Package: aff.Package.Name}
			for _, ev := range rg.Events {
				switch {
				case ev.Introduced != "":
					if ev.Introduced != "0" {
						introduced = ev.Introduced
					}
					open = true
				case ev.Fixed != "":
					r := base
					r.Introduced, r.Fixed, r.State = introduced, ev.Fixed, feeds.Fixed
					add(r)
					introduced, open = "", false
				case ev.LastAffected != "":
					// "affected up to and including X" cannot be expressed as a
					// fixed-below range without inventing the next version.
					st.Skip("last_affected event")
					introduced, open = "", false
				}
			}
			if open {
				r := base
				r.Introduced, r.State = introduced, feeds.Affected
				add(r)
			}
		}
	}
	return adv, len(adv.Ranges) > 0
}
