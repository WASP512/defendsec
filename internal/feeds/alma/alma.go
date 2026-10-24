// Package alma turns AlmaLinux's errata feed into advisory ranges.
//
// Source: https://errata.almalinux.org/<N>/errata.full.json
//
// AlmaLinux rebuilds Red Hat Enterprise Linux and publishes its own errata
// (ALSA/ALBA/ALEA) after it has rebuilt Red Hat's fix, so the fix reaches an
// Alma host later than it reaches RHEL, sometimes by days. Matching an Alma host
// against Red Hat's feed alone reports fixes that Alma users cannot install yet.
// This feed says which fixes Alma has actually shipped. Ranges carry distro
// "almalinux" and the major release; the matcher pairs them with the RHEL ones
// (see internal/vuln).
//
// The file is one JSON document, {"schema_version","data":[erratum...]}, about
// 30 MB for release 9. Each erratum lists its CVEs (as references of type
// "cve") and every fixed package with epoch, version, release and architecture.
//
// Not covered, and counted as skipped instead of guessed:
//   - packages built for an AppStream module stream, for the reason given in
//     package rhel;
//   - errata without a CVE (bug fix and enhancement updates).
package alma

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/nevra"
)

type pkg struct {
	Name    string          `json:"name"`
	Epoch   string          `json:"epoch"`
	Version string          `json:"version"`
	Release string          `json:"release"`
	Arch    string          `json:"arch"`
	Module  json.RawMessage `json:"module"`
}

type reference struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type erratum struct {
	ID         string      `json:"id"`
	IssuedDate int64       `json:"issued_date"`
	Severity   string      `json:"severity"`
	Title      string      `json:"title"`
	Type       string      `json:"type"`
	Packages   []pkg       `json:"packages"`
	References []reference `json:"references"`
}

// Parse streams one release's errata.full.json and emits one advisory per CVE
// per erratum. release is the major version, e.g. "9". It fails on a document
// that is not the errata format, or has no errata at all: an empty or error
// page must not look like "Alma has fixed nothing".
func Parse(r io.Reader, release string, emit func(feeds.Advisory) error) (feeds.Stats, error) {
	var st feeds.Stats
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return st, fmt.Errorf("alma: %w", err)
	}
	sawData := false
	total := 0
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return st, fmt.Errorf("alma: %w", err)
		}
		key, _ := keyTok.(string)
		if key != "data" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return st, fmt.Errorf("alma: %w", err)
			}
			continue
		}
		sawData = true
		if err := expectDelim(dec, '['); err != nil {
			return st, fmt.Errorf("alma: data: %w", err)
		}
		for dec.More() {
			var e erratum
			if err := dec.Decode(&e); err != nil {
				return st, fmt.Errorf("alma: erratum %d: %w", total+1, err)
			}
			total++
			if err := emitErratum(e, release, &st, emit); err != nil {
				return st, err
			}
		}
		if err := expectDelim(dec, ']'); err != nil {
			return st, fmt.Errorf("alma: data: %w", err)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return st, fmt.Errorf("alma: %w", err)
	}
	if !sawData {
		return st, errors.New("alma: no \"data\" array; not an AlmaLinux errata file")
	}
	if total == 0 {
		return st, errors.New("alma: the errata file has no errata")
	}
	return st, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("unexpected %v, want %q", tok, string(want))
	}
	return nil
}

func emitErratum(e erratum, release string, st *feeds.Stats, emit func(feeds.Advisory) error) error {
	var cves []string
	for _, ref := range e.References {
		if ref.Type == "cve" && feeds.IsCVE(ref.ID) {
			cves = append(cves, ref.ID)
		}
	}
	if len(cves) == 0 {
		st.Skip("erratum without CVE")
		return nil
	}
	issued := ""
	if e.IssuedDate > 0 {
		issued = time.Unix(e.IssuedDate, 0).UTC().Format("2006-01-02")
	}
	var ranges []feeds.Range
	seen := map[string]bool{}
	for _, p := range e.Packages {
		n := nevra.Join(p.Name, p.Epoch, p.Version, p.Release, p.Arch)
		if n.Name == "" || n.Version == "" || n.Release == "" {
			st.Skip("package without name or version")
			continue
		}
		if len(p.Module) > 0 && string(p.Module) != "null" || n.IsModular() {
			st.Skip("module-stream range")
			continue
		}
		key := n.Name + "\x00" + n.EVR()
		if seen[key] {
			continue // the same build for every architecture
		}
		seen[key] = true
		ranges = append(ranges, feeds.Range{
			Ecosystem: "AlmaLinux", Distro: "almalinux", Release: release,
			Package: n.Name, Fixed: n.EVR(), State: feeds.Fixed, Issued: issued,
		})
	}
	if len(ranges) == 0 {
		st.Skip("erratum without installable packages")
		return nil
	}
	sev := e.Severity
	summary := strings.TrimSpace(e.ID + ": " + e.Title)
	for _, c := range cves {
		adv := feeds.Advisory{
			ID: c, CVE: c, Summary: summary,
			Severity: feeds.NormalizeSeverity(sev), Ranges: ranges,
		}
		if err := emit(adv); err != nil {
			return err
		}
		st.Advisories++
		st.Ranges += len(ranges)
	}
	return nil
}
