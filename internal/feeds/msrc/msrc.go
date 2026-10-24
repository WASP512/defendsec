// Package msrc turns Microsoft's Security Update Guide (the CVRF API) into
// advisory ranges that map a Windows update (KB number) to the CVEs it fixes.
//
// Source: https://api.msrc.microsoft.com/cvrf/v3.0 (public, no key), checked
// against the live service on 2026-10-24:
//
//   - GET /updates lists the monthly documents ({"value":[{ID, DocumentTitle,
//     InitialReleaseDate, CurrentReleaseDate, CvrfUrl}]}), including the
//     "Mariner Release Notes" documents, which are not Windows and are skipped.
//   - GET /cvrf/<ID> (for example 2026-Sep) is one month, about 20 MB of JSON:
//     ProductTree.FullProductName maps ProductID to a product name, and each
//     Vulnerability carries its CVE, Title, Threats (Type 3 is the severity),
//     CVSSScoreSets and Remediations. A Remediation of Type 2 (Vendor Fix) whose
//     Description is a number is a KB, with the ProductIDs it applies to and the
//     KB it supersedes.
//
// The feed keeps the most recent months (12 by default). Every month is reduced
// to the few fields DefendSec reads when it is downloaded, and the reduced month
// is cached under the feed's own directory keyed by its CurrentReleaseDate, so a
// sync downloads only the months Microsoft revised: the first sync is a few
// hundred megabytes, the next ones are a listing and, after Patch Tuesday, one
// month. The assembled file is small and ordered, so an unchanged upstream has
// an unchanged digest.
//
// What it does not know: an update older than the window, a driver or
// definition update (no CVE), and which CVEs a KB fixes on a product other than
// the one the Remediation names (a cumulative update that serves two products is
// one KB). Counted, not guessed.
package msrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/fetch"
)

const (
	// BaseURL is the CVRF API.
	BaseURL = "https://api.msrc.microsoft.com/cvrf/v3.0"
	// DefaultMonths is how many monthly documents the feed keeps.
	DefaultMonths = 12
	// Ecosystem and Distro label the ranges. Distro "windows" is the space of
	// KB numbers, not an operating system release.
	Ecosystem = "MSRC"
	Distro    = "windows"
)

// Update is one month of the Security Update Guide, reduced.
type Update struct {
	ID       string `json:"id"`       // "2026-Sep"
	Released string `json:"released"` // YYYY-MM-DD, the month's initial release
	CVEs     []CVE  `json:"cves"`
}

// CVE is one vulnerability that has at least one KB fix.
type CVE struct {
	CVE      string   `json:"cve"`
	Title    string   `json:"title,omitempty"`
	Severity string   `json:"severity,omitempty"` // Microsoft's own word: Critical, Important, Moderate, Low
	CVSS     *float64 `json:"cvss,omitempty"`
	Vector   string   `json:"vector,omitempty"`
	KBs      []KB     `json:"kbs"`
}

// KB is one update that fixes a CVE.
type KB struct {
	KB         string   `json:"kb"` // "KB5122876"
	Supersedes string   `json:"supersedes,omitempty"`
	Products   []string `json:"products,omitempty"`
}

// File is what the feed stores: {"updates":[...]}.
type File struct {
	Updates []Update `json:"updates"`
}

// cvrfWire is the part of a CVRF document the reducer reads.
type cvrfWire struct {
	DocumentTracking struct {
		Identification struct {
			ID struct{ Value string } `json:"ID"`
		} `json:"Identification"`
		InitialReleaseDate string `json:"InitialReleaseDate"`
	} `json:"DocumentTracking"`
	ProductTree struct {
		FullProductName []struct {
			ProductID string `json:"ProductID"`
			Value     string `json:"Value"`
		} `json:"FullProductName"`
	} `json:"ProductTree"`
	Vulnerability []struct {
		CVE     string                 `json:"CVE"`
		Title   struct{ Value string } `json:"Title"`
		Threats []struct {
			Type        int                    `json:"Type"`
			Description struct{ Value string } `json:"Description"`
		} `json:"Threats"`
		CVSSScoreSets []struct {
			BaseScore float64 `json:"BaseScore"`
			Vector    string  `json:"Vector"`
		} `json:"CVSSScoreSets"`
		Remediations []struct {
			Type         int                    `json:"Type"`
			Description  struct{ Value string } `json:"Description"`
			ProductID    []string               `json:"ProductID"`
			Supercedence string                 `json:"Supercedence"`
		} `json:"Remediations"`
	} `json:"Vulnerability"`
}

var (
	cveRe   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	kbRe    = regexp.MustCompile(`(?i)^(?:KB)?([0-9]{5,9})$`)
	monthRe = regexp.MustCompile(`^[0-9]{4}-[A-Z][a-z]{2}$`)
)

// maxProducts bounds the product names kept per KB.
const maxProducts = 6

func normKB(s string) string {
	m := kbRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	return "KB" + m[1]
}

var severityOrder = map[string]int{"critical": 4, "important": 3, "moderate": 2, "low": 1}

// Reduce reads one CVRF document and keeps, for every CVE with at least one KB
// fix, the CVE, its title, severity and best CVSS score, and its KBs. Entries
// that are not CVEs, and remediations that are not a numeric KB (Azure Linux
// release notes, for instance), are dropped.
func Reduce(r io.Reader) (Update, error) {
	var doc cvrfWire
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return Update{}, fmt.Errorf("not a CVRF document: %w", err)
	}
	id := strings.TrimSpace(doc.DocumentTracking.Identification.ID.Value)
	if !monthRe.MatchString(id) {
		return Update{}, fmt.Errorf("CVRF document id %q is not a month", id)
	}
	out := Update{ID: id}
	if t := doc.DocumentTracking.InitialReleaseDate; len(t) >= 10 {
		out.Released = t[:10]
	}
	if out.Released == "" {
		return Update{}, fmt.Errorf("CVRF %s has no initial release date", id)
	}
	names := make(map[string]string, len(doc.ProductTree.FullProductName))
	for _, p := range doc.ProductTree.FullProductName {
		names[p.ProductID] = strings.TrimSpace(p.Value)
	}
	for _, v := range doc.Vulnerability {
		cve := strings.TrimSpace(v.CVE)
		if !cveRe.MatchString(cve) {
			continue
		}
		byKB := map[string]*KB{}
		for _, rem := range v.Remediations {
			if rem.Type != 2 {
				continue
			}
			kb := normKB(rem.Description.Value)
			if kb == "" {
				continue
			}
			e := byKB[kb]
			if e == nil {
				e = &KB{KB: kb}
				byKB[kb] = e
			}
			if s := normKB(rem.Supercedence); s != "" && e.Supersedes == "" {
				e.Supersedes = s
			}
			for _, pid := range rem.ProductID {
				if n := names[pid]; n != "" {
					e.Products = append(e.Products, n)
				}
			}
		}
		if len(byKB) == 0 {
			continue
		}
		c := CVE{CVE: cve, Title: strings.TrimSpace(v.Title.Value)}
		best := 0
		for _, t := range v.Threats {
			if t.Type != 3 {
				continue
			}
			if n := severityOrder[strings.ToLower(strings.TrimSpace(t.Description.Value))]; n > best {
				best, c.Severity = n, strings.TrimSpace(t.Description.Value)
			}
		}
		for _, s := range v.CVSSScoreSets {
			if s.BaseScore > 0 && (c.CVSS == nil || s.BaseScore > *c.CVSS) {
				score := s.BaseScore
				c.CVSS, c.Vector = &score, s.Vector
			}
		}
		for _, e := range byKB {
			e.Products = uniqSorted(e.Products)
			if len(e.Products) > maxProducts {
				e.Products = e.Products[:maxProducts]
			}
			c.KBs = append(c.KBs, *e)
		}
		sort.Slice(c.KBs, func(i, j int) bool { return c.KBs[i].KB < c.KBs[j].KB })
		out.CVEs = append(out.CVEs, c)
	}
	sort.Slice(out.CVEs, func(i, j int) bool { return out.CVEs[i].CVE < out.CVEs[j].CVE })
	return out, nil
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// listing is GET /updates.
type listing struct {
	Value []struct {
		ID                 string `json:"ID"`
		DocumentTitle      string `json:"DocumentTitle"`
		InitialReleaseDate string `json:"InitialReleaseDate"`
		CurrentReleaseDate string `json:"CurrentReleaseDate"`
	} `json:"value"`
}

// Month is one document the listing offers.
type Month struct {
	ID      string
	Initial time.Time
	Current string // CurrentReleaseDate, as sent: changes when Microsoft revises the month
}

// SelectMonths picks the most recent monthly security-update documents that
// were released by now. Release notes for other products (Mariner) are skipped.
func SelectMonths(body []byte, months int, now time.Time) ([]Month, error) {
	var l listing
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, fmt.Errorf("not an MSRC update listing: %w", err)
	}
	var all []Month
	for _, e := range l.Value {
		if !monthRe.MatchString(e.ID) || !strings.Contains(strings.ToLower(e.DocumentTitle), "security update") ||
			strings.Contains(strings.ToLower(e.DocumentTitle), "mariner") {
			continue
		}
		t, err := time.Parse(time.RFC3339, e.InitialReleaseDate)
		if err != nil || t.After(now) {
			continue
		}
		all = append(all, Month{ID: e.ID, Initial: t.UTC(), Current: e.CurrentReleaseDate})
	}
	if len(all) == 0 {
		return nil, errors.New("the MSRC listing has no security update documents")
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].Initial.Equal(all[j].Initial) {
			return all[i].Initial.After(all[j].Initial)
		}
		return all[i].ID > all[j].ID
	})
	if months <= 0 {
		months = DefaultMonths
	}
	if len(all) > months {
		all = all[:months]
	}
	return all, nil
}

type monthCache struct {
	Current string `json:"current"`
	Update  Update `json:"update"`
}

// Fetch brings the feed up to date: it reads the listing, downloads the months
// it does not hold at their current revision, and stores the assembled file as
// the feed's data. base is the API root (BaseURL or a mirror). A month that
// cannot be downloaded fails the whole fetch, so a short window never reads as
// "Microsoft fixed fewer things".
func Fetch(ctx context.Context, f *fetch.Fetcher, name, base string, months int) (fetch.Result, error) {
	base = strings.TrimRight(base, "/")
	if err := fetch.CheckURL(base); err != nil {
		return fetch.Result{}, err
	}
	body, err := f.GetBody(ctx, name, base+"/updates")
	if err != nil {
		return fetch.Result{}, err
	}
	picked, err := SelectMonths(body, months, f.Clock())
	if err != nil {
		return fetch.Result{}, fmt.Errorf("fetch %s: %w", name, err)
	}
	dir := filepath.Join(f.Cache.Dir, name, "months")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fetch.Result{}, err
	}
	var file File
	keep := map[string]bool{}
	for _, m := range picked {
		path := filepath.Join(dir, m.ID+".json")
		keep[m.ID+".json"] = true
		if mc, ok := readMonth(path); ok && mc.Current == m.Current && mc.Current != "" {
			file.Updates = append(file.Updates, mc.Update)
			continue
		}
		raw, err := f.GetBody(ctx, name, base+"/cvrf/"+m.ID)
		if err != nil {
			return fetch.Result{}, err
		}
		up, err := Reduce(strings.NewReader(string(raw)))
		if err != nil {
			return fetch.Result{}, fmt.Errorf("fetch %s: %s: %w", name, m.ID, err)
		}
		if up.ID != m.ID {
			return fetch.Result{}, fmt.Errorf("fetch %s: asked for %s, got %s", name, m.ID, up.ID)
		}
		if err := writeMonth(path, monthCache{Current: m.Current, Update: up}); err != nil {
			return fetch.Result{}, err
		}
		file.Updates = append(file.Updates, up)
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !keep[e.Name()] {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	sort.Slice(file.Updates, func(i, j int) bool {
		return file.Updates[i].Released+file.Updates[i].ID < file.Updates[j].Released+file.Updates[j].ID
	})
	data, err := json.Marshal(file)
	if err != nil {
		return fetch.Result{}, err
	}
	return f.StoreNormalised(name, base, append(data, '\n'))
}

func readMonth(path string) (monthCache, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return monthCache{}, false
	}
	var mc monthCache
	if json.Unmarshal(b, &mc) != nil || mc.Update.ID == "" {
		return monthCache{}, false
	}
	return mc, true
}

func writeMonth(path string, mc monthCache) error {
	b, err := json.Marshal(mc)
	if err != nil {
		return err
	}
	part := path + ".part"
	if err := os.WriteFile(part, b, 0o600); err != nil {
		return err
	}
	return os.Rename(part, path)
}

// Parse reads the stored file and emits one advisory per CVE, with one range per
// KB that fixes it: distro "windows", package and fixed both the KB, issued the
// month's release date. Several months may mention the same CVE and KB (a
// revision); the loader keeps one range per identity.
func Parse(r io.Reader, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	var file File
	if err := json.NewDecoder(r).Decode(&file); err != nil {
		return st, fmt.Errorf("not an MSRC feed file: %w", err)
	}
	if len(file.Updates) == 0 {
		return st, errors.New("the MSRC feed file has no months")
	}
	for _, up := range file.Updates {
		for _, c := range up.CVEs {
			if !feeds.IsCVE(c.CVE) {
				st.Skip("not a CVE id")
				continue
			}
			adv := feeds.Advisory{
				ID: c.CVE, CVE: c.CVE, Summary: c.Title,
				Severity:  feeds.NormalizeSeverity(c.Severity),
				CVSSScore: c.CVSS, CVSSVector: c.Vector,
			}
			for _, kb := range c.KBs {
				if normKB(kb.KB) == "" {
					st.Skip("not a KB number")
					continue
				}
				adv.Ranges = append(adv.Ranges, feeds.Range{
					Ecosystem: Ecosystem, Distro: Distro, Package: kb.KB,
					Fixed: kb.KB, State: feeds.Fixed, Issued: up.Released,
				})
				st.Ranges++
			}
			if len(adv.Ranges) == 0 {
				st.Skip("CVE without a KB")
				continue
			}
			st.Advisories++
			if err := emit(adv); err != nil {
				return st, err
			}
		}
	}
	return st, nil
}
