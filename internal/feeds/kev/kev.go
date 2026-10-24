// Package kev parses the CISA Known Exploited Vulnerabilities catalog.
//
// Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"defendsec/internal/feeds"
)

// Entry is one catalog row, reduced to what DefendSec stores.
type Entry struct {
	CVE        string
	DateAdded  time.Time // calendar date, UTC midnight
	Name       string    // vulnerabilityName
	Vendor     string
	Product    string
	Ransomware bool // knownRansomwareCampaignUse == "Known"
}

// Catalog is a parsed feed.
type Catalog struct {
	Version  string
	Released string
	Entries  []Entry // sorted by CVE
	Stats    feeds.Stats
}

type document struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           *int   `json:"count"`
	Vulnerabilities []struct {
		CVE        string `json:"cveID"`
		Vendor     string `json:"vendorProject"`
		Product    string `json:"product"`
		Name       string `json:"vulnerabilityName"`
		DateAdded  string `json:"dateAdded"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// Parse reads a KEV JSON document. It fails on malformed JSON, on a document
// with no vulnerabilities array, and when the catalog's own "count" disagrees
// with the number of rows (a truncated download), rather than loading a partial
// catalog and clearing KEV flags on everything missing from it.
func Parse(r io.Reader) (*Catalog, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	if doc.Vulnerabilities == nil {
		return nil, fmt.Errorf("kev: no vulnerabilities array")
	}
	if doc.Count != nil && *doc.Count != len(doc.Vulnerabilities) {
		return nil, fmt.Errorf("kev: catalog says count=%d but has %d rows (truncated download?)", *doc.Count, len(doc.Vulnerabilities))
	}
	cat := &Catalog{Version: doc.CatalogVersion, Released: doc.DateReleased}
	seen := map[string]bool{}
	for i, v := range doc.Vulnerabilities {
		if !feeds.IsCVE(v.CVE) {
			cat.Stats.Skip("malformed cveID")
			continue
		}
		if seen[v.CVE] {
			cat.Stats.Skip("duplicate cveID")
			continue
		}
		added, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil {
			return nil, fmt.Errorf("kev: row %d (%s): dateAdded %q: %w", i, v.CVE, v.DateAdded, err)
		}
		seen[v.CVE] = true
		cat.Entries = append(cat.Entries, Entry{
			CVE: v.CVE, DateAdded: added, Name: v.Name, Vendor: v.Vendor, Product: v.Product,
			Ransomware: v.Ransomware == "Known",
		})
	}
	sort.Slice(cat.Entries, func(i, j int) bool { return cat.Entries[i].CVE < cat.Entries[j].CVE })
	cat.Stats.Advisories = len(cat.Entries)
	return cat, nil
}
