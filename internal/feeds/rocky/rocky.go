// Package rocky turns Rocky Linux's errata service (Apollo) into advisory
// ranges.
//
// Source: https://apollo.build.resf.org/v2/advisories
//
// Rocky rebuilds Red Hat Enterprise Linux and publishes its own errata (RLSA)
// once it has rebuilt Red Hat's fix, which can be days later. Matching a Rocky
// host against Red Hat's feed alone reports fixes the Rocky user cannot install
// yet. This feed says which fixes Rocky has actually shipped. Ranges carry
// distro "rocky" and the major release; the matcher pairs them with the RHEL
// ones (see internal/vuln).
//
// The API is paged, so the runner walks it (fetch.FetchPaged) and stores one
// file, {"advisories":[...]}, which Parse reads. API facts that were checked
// against the live service rather than assumed:
//
//   - /v2/advisories honours filters.product, filters.type and filters.cve, and
//     takes limit (at most 100) and a zero-based page.
//   - /api/v3/advisories/ ignores every filter (a filters.cve query returned an
//     unrelated advisory, as did product, kind and cve without the prefix), so
//     it cannot be narrowed to a release, and at 2.7 MB per page of 100 it is
//     five times larger. This package does not use it.
//   - rpms is keyed by product name ("Rocky Linux 9"); an advisory that fixes
//     both releases lists both. nvras are "name-epoch:version-release.arch.rpm".
//
// Not covered, and counted as skipped instead of guessed: module-stream
// packages (see package rhel), source RPMs, advisories without a CVE.
package rocky

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/fetch"
	"defendsec/internal/feeds/nevra"
)

// PageSize is the largest page the API serves.
const PageSize = 100

// product is how Apollo names a release: "Rocky Linux 9".
func product(release string) string { return "Rocky Linux " + release }

// Pager walks the security advisories for one release. base is the service URL
// (https://apollo.build.resf.org/v2/advisories, or a mirror).
func Pager(base, release string) fetch.Pager {
	return fetch.Pager{
		URL: func(n int) string {
			u, err := url.Parse(base)
			if err != nil {
				return base
			}
			q := u.Query()
			q.Set("filters.product", product(release))
			q.Set("filters.type", "TYPE_SECURITY")
			q.Set("limit", strconv.Itoa(PageSize))
			q.Set("page", strconv.Itoa(n))
			u.RawQuery = q.Encode()
			return u.String()
		},
		Records: func(body []byte) ([]json.RawMessage, int, error) {
			var page struct {
				Advisories []json.RawMessage `json:"advisories"`
				Total      int               `json:"total"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				return nil, 0, fmt.Errorf("not an Apollo advisory page: %w", err)
			}
			return page.Advisories, page.Total, nil
		},
		Key: func(rec json.RawMessage) (string, error) {
			var a struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(rec, &a); err != nil || a.Name == "" {
				return "", errors.New("advisory without a name")
			}
			return a.Name, nil
		},
		Normalize: normalize,
		Wrap:      "advisories",
	}
}

// normalize reduces an advisory to the fields Parse reads, with its CVEs and
// packages sorted. Apollo returns the members of those lists in a different
// order from one request to the next, and the descriptions, topics and
// references it also sends are not used; the stored file is therefore the same
// bytes for the same set of advisories, and a fraction of the size.
func normalize(rec json.RawMessage) (json.RawMessage, error) {
	var a advisory
	if err := json.Unmarshal(rec, &a); err != nil {
		return nil, fmt.Errorf("advisory: %w", err)
	}
	sort.Slice(a.CVEs, func(i, j int) bool { return a.CVEs[i].Name < a.CVEs[j].Name })
	for k, v := range a.RPMs {
		sort.Strings(v.NVRAs)
		a.RPMs[k] = v
	}
	return json.Marshal(a)
}

// advisory is the part of an Apollo advisory this package uses; it is also the
// stored form (see normalize).
type advisory struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Synopsis    string `json:"synopsis"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"publishedAt"`
	CVEs        []struct {
		Name string `json:"name"`
		// Apollo sends the base score as a string.
		CVSS3Vector string `json:"cvss3ScoringVector"`
		CVSS3Score  string `json:"cvss3BaseScore"`
		CWE         string `json:"cwe"`
	} `json:"cves"`
	RPMs map[string]struct {
		NVRAs []string `json:"nvras"`
	} `json:"rpms"`
}

// Parse reads the stored {"advisories":[...]} file for one release ("9") and
// emits one advisory per CVE per erratum. A document that is not an Apollo
// advisory file, or that has no advisories, is an error: an empty page must not
// look like "Rocky has fixed nothing".
func Parse(raw []byte, release string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	var doc struct {
		Advisories []advisory `json:"advisories"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return st, fmt.Errorf("rocky: %w", err)
	}
	if len(doc.Advisories) == 0 {
		return st, errors.New("rocky: the file has no advisories")
	}
	prod := product(release)
	for _, a := range doc.Advisories {
		if a.Type != "TYPE_SECURITY" {
			st.Skip("not a security advisory")
			continue
		}
		var ranges []feeds.Range
		seen := map[string]bool{}
		issued := ""
		if t, err := time.Parse(time.RFC3339, a.PublishedAt); err == nil {
			issued = t.UTC().Format("2006-01-02")
		}
		for _, s := range a.RPMs[prod].NVRAs {
			n, err := nevra.Parse(s)
			if err != nil {
				st.Skip("unparseable package name")
				continue
			}
			switch {
			case n.IsSource():
				continue
			case n.IsModular():
				st.Skip("module-stream range")
				continue
			}
			key := n.Name + "\x00" + n.EVR()
			if seen[key] {
				continue // the same build for every architecture
			}
			seen[key] = true
			ranges = append(ranges, feeds.Range{
				Ecosystem: "Rocky Linux", Distro: "rocky", Release: release,
				Package: n.Name, Fixed: n.EVR(), State: feeds.Fixed, Issued: issued,
			})
		}
		if len(ranges) == 0 {
			st.Skip("advisory without packages for this release")
			continue
		}
		cves := 0
		sev := strings.TrimPrefix(a.Severity, "SEVERITY_")
		summary := strings.TrimSpace(a.Name + ": " + a.Synopsis)
		for _, c := range a.CVEs {
			if !feeds.IsCVE(c.Name) {
				st.Skip("malformed CVE id")
				continue
			}
			cves++
			adv := feeds.Advisory{
				ID: c.Name, CVE: c.Name, Summary: summary,
				Severity: feeds.NormalizeSeverity(sev), Ranges: ranges,
			}
			if score, err := strconv.ParseFloat(c.CVSS3Score, 64); err == nil && score >= 0 && score <= 10 && c.CVSS3Vector != "" {
				adv.CVSSScore, adv.CVSSVector = &score, c.CVSS3Vector
			}
			if c.CWE != "" {
				adv.CWE = []string{c.CWE}
			}
			if err := emit(adv); err != nil {
				return st, err
			}
			st.Advisories++
			st.Ranges += len(ranges)
		}
		if cves == 0 {
			st.Skip("advisory without CVE")
		}
	}
	return st, nil
}
