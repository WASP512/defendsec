// Package endoflife parses endoflife.date's bulk product list.
//
// Source: https://endoflife.date/api/v1/products/full (API v1, schema 1.x): one
// JSON document with every product and every release cycle. DefendSec keeps
// only the products its mapping table can produce (see internal/lifecycle).
package endoflife

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"defendsec/internal/feeds"
)

// Release is one release cycle of one product. Dates are "YYYY-MM-DD" or "".
type Release struct {
	Cycle       string
	ReleaseDate string
	EoasFrom    string // active support ends
	EolFrom     string // security support ends: end of life
	EoesFrom    string // paid extended security support ends
	// IsEol is the feed's flag. It matters only for releases that are end of
	// life with no date on record (an old Node.js 3, say).
	IsEol  bool
	IsLTS  bool
	Latest string
	Link   string
}

// Product is one product with its releases, newest first as the feed lists them.
type Product struct {
	Name     string
	Label    string
	Releases []Release
}

// Catalog is a parsed feed.
type Catalog struct {
	SchemaVersion string
	GeneratedAt   string
	// Products are the wanted products the feed carries, sorted by name.
	Products []Product
	Stats    feeds.Stats
}

// Releases counts the release cycles in the catalog.
func (c *Catalog) Releases() int {
	n := 0
	for _, p := range c.Products {
		n += len(p.Releases)
	}
	return n
}

// date reads a feed date. v1 gives "YYYY-MM-DD" or null; older schemas gave
// true/false, which carries no date and reads as empty (the isEol flag holds
// the information).
type date struct {
	s     string
	valid bool // false when the value was present but not a date
	set   bool
}

func (d *date) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" || string(b) == "true" || string(b) == "false" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		d.set = true
		return nil
	}
	d.set = true
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return nil
	}
	d.s, d.valid = s, true
	return nil
}

type document struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Total         *int   `json:"total"`
	Result        []struct {
		Name     string `json:"name"`
		Label    string `json:"label"`
		Releases []struct {
			Name        string `json:"name"`
			ReleaseDate date   `json:"releaseDate"`
			IsLTS       bool   `json:"isLts"`
			IsEol       bool   `json:"isEol"`
			EolFrom     date   `json:"eolFrom"`
			EoasFrom    date   `json:"eoasFrom"`
			EoesFrom    date   `json:"eoesFrom"`
			Latest      *struct {
				Name string `json:"name"`
				Link string `json:"link"`
			} `json:"latest"`
		} `json:"releases"`
	} `json:"result"`
}

// Parse reads the bulk document and keeps the products named in want. It fails
// on malformed JSON, on a schema other than 1.x, on a "total" that disagrees
// with the number of products (a truncated download), and when none of the
// wanted products is present, rather than loading an empty set that would
// clear every lifecycle verdict.
func Parse(r io.Reader, want []string) (*Catalog, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("endoflife: decode: %w", err)
	}
	if !strings.HasPrefix(doc.SchemaVersion, "1.") {
		return nil, fmt.Errorf("endoflife: schema_version %q is not 1.x; this build reads API v1 only", doc.SchemaVersion)
	}
	if doc.Result == nil {
		return nil, fmt.Errorf("endoflife: no result array")
	}
	if doc.Total != nil && *doc.Total != len(doc.Result) {
		return nil, fmt.Errorf("endoflife: document says total=%d but has %d products (truncated download?)", *doc.Total, len(doc.Result))
	}
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
	}
	cat := &Catalog{SchemaVersion: doc.SchemaVersion, GeneratedAt: doc.GeneratedAt}
	found := map[string]bool{}
	for _, p := range doc.Result {
		if !wanted[p.Name] {
			continue
		}
		if found[p.Name] {
			cat.Stats.Skip("duplicate product")
			continue
		}
		found[p.Name] = true
		prod := Product{Name: p.Name, Label: p.Label}
		seen := map[string]bool{}
		for _, r := range p.Releases {
			if strings.TrimSpace(r.Name) == "" || seen[r.Name] {
				cat.Stats.Skip("release without a unique name")
				continue
			}
			seen[r.Name] = true
			rel := Release{Cycle: r.Name, IsEol: r.IsEol, IsLTS: r.IsLTS,
				ReleaseDate: r.ReleaseDate.s, EolFrom: r.EolFrom.s, EoasFrom: r.EoasFrom.s, EoesFrom: r.EoesFrom.s}
			for _, d := range []date{r.ReleaseDate, r.EolFrom, r.EoasFrom, r.EoesFrom} {
				if d.set && !d.valid {
					cat.Stats.Skip("unreadable date (left empty)")
				}
			}
			if r.Latest != nil {
				rel.Latest, rel.Link = r.Latest.Name, r.Latest.Link
			}
			prod.Releases = append(prod.Releases, rel)
		}
		cat.Products = append(cat.Products, prod)
	}
	for _, w := range want {
		if !found[w] {
			cat.Stats.Skip("wanted product not in the feed")
		}
	}
	if len(cat.Products) == 0 {
		return nil, fmt.Errorf("endoflife: none of the %d wanted products is in the feed", len(want))
	}
	sort.Slice(cat.Products, func(i, j int) bool { return cat.Products[i].Name < cat.Products[j].Name })
	cat.Stats.Advisories = cat.Releases()
	cat.Stats.Ranges = cat.Releases()
	return cat, nil
}
