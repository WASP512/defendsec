package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"defendsec/internal/hostinv"
	"defendsec/internal/repohealth"
	"defendsec/internal/vuln"
)

// exitError makes main exit with a specific status, so a script can tell "has
// findings" from "could not assess" from "broke".
type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

const (
	exitFindings   = 2 // at least one open finding
	exitUnassessed = 3 // no feed could speak for this host
)

// matchReport is the --json output: the matcher's result plus what was matched.
type matchReport struct {
	Inventory string         `json:"inventory"`
	Distro    string         `json:"distro"`
	Release   string         `json:"release"`
	Coverage  string         `json:"coverage"`
	Snapshot  *int64         `json:"latestSnapshotId"`
	Stats     vuln.Stats     `json:"stats"`
	Open      int            `json:"openFindings"` // fixable: same number as Counts.Fixable
	Counts    matchCounts    `json:"counts"`
	Findings  []matchFinding `json:"findings"`
	// PendingUpdates says whether the host's pending-updates list can be
	// believed, with the reasons when it cannot; "unassessed" when the
	// inventory carries no repository evidence.
	PendingUpdates pendingVerdict `json:"pendingUpdates"`
}

type pendingVerdict struct {
	Reliability string   `json:"reliability"`
	Reasons     []string `json:"reasons"`
	Repos       int      `json:"repositories"`
}

// kindCounts is one tally of findings by what the operator can do about them.
type kindCounts struct {
	// Fixable: a fix is released for this host's distribution and can be
	// installed. The only bucket that is "fix this week".
	Fixable int `json:"fixable"`
	// AwaitingVendor: fixed upstream by Red Hat, not yet released by the rebuild
	// (Rocky, AlmaLinux) the host runs. Nothing to install yet.
	AwaitingVendor int `json:"awaitingVendor"`
	// NoFix: affected, and no fix is published anywhere.
	NoFix int `json:"noFix"`
	// Informational: will not fix, or under investigation.
	Informational int `json:"informational"`
	// EOL: software from outside the distribution that is past upstream
	// support. The fix is an upgrade; it counts with "fix this week" but is
	// not a patch, so it is not in Fixable.
	EOL int `json:"eol"`
	// RepoHealth: package repositories with an expired or missing signing key
	// or a stale index. The fix is work for this week; it is not a patch.
	RepoHealth int `json:"repoHealth"`
}

// matchCounts tallies all findings, and again only those on the CISA KEV list.
type matchCounts struct {
	kindCounts
	KEV kindCounts `json:"kev"`
}

func countFindings(fs []vuln.Finding) matchCounts {
	var c matchCounts
	for _, f := range fs {
		tallies := []*kindCounts{&c.kindCounts}
		if f.KEV {
			tallies = append(tallies, &c.KEV)
		}
		for _, t := range tallies {
			switch f.Kind {
			case vuln.KindFinding:
				t.Fixable++
			case vuln.KindAwaitingVendor:
				t.AwaitingVendor++
			case vuln.KindUnfixed:
				t.NoFix++
			case vuln.KindInformational:
				t.Informational++
			case vuln.KindEOL:
				t.EOL++
			case vuln.KindRepoHealth:
				t.RepoHealth++
			}
		}
	}
	return c
}

func (k kindCounts) line() string {
	return fmt.Sprintf("%d fixable, %d awaiting_vendor, %d no_fix, %d informational, %d eol, %d repo_health", k.Fixable, k.AwaitingVendor, k.NoFix, k.Informational, k.EOL, k.RepoHealth)
}

type matchFinding struct {
	AdvisoryID    string     `json:"advisoryId"`
	CVE           string     `json:"cve"`
	RangeID       int64      `json:"rangeId"`
	SnapshotID    *int64     `json:"snapshotId"`
	Feed          string     `json:"feed"`
	FeedDate      *time.Time `json:"feedDate"`
	Kind          string     `json:"kind"`
	Basis         string     `json:"basis"`
	Package       string     `json:"package"`
	SourcePackage string     `json:"sourcePackage"`
	Installed     string     `json:"installed"`
	Fixed         string     `json:"fixed"`
	FixState      string     `json:"fixState"`
	Severity      string     `json:"severity"`
	KEV           bool       `json:"kev"`
	EPSS          *float64   `json:"epss"`
	Reason        string     `json:"reason"`
	// EOL is set on end-of-life findings: the release, its end date, where the
	// packages came from and what to upgrade to.
	EOL *vuln.EOLDetail `json:"eol,omitempty"`
	// Repo is set on repository-health findings.
	Repo *vuln.RepoDetail `json:"repo,omitempty"`
}

// cmdMatch runs the matcher over a package inventory against the advisory
// tables and prints what it finds. It reads the database and writes nothing:
// no findings are stored, no alert is raised.
//
// The inventory is the JSON `defendsec-agentd -print-inventory` writes: distro,
// release, package manager and packages, nothing else about the host.
func cmdMatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbURL := fs.String("db-url", "", "Postgres URL (default: DEFENDSEC_DATABASE_URL or DATABASE_URL)")
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	all := fs.Bool("all", false, "also list entries with no fix at all (no_fix, will_not_fix, under_investigation); awaiting_vendor and eol are always listed")
	asOf := fs.String("as-of", "", "judge application end-of-life and repository freshness on this day, YYYY-MM-DD (default: today), to reproduce a run")
	staleDays := fs.Int("stale-days", 7, "a repository index older than this many days without a refresh is a finding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: defendsec-feeds match [--db-url URL] [--json] [--all] [--as-of YYYY-MM-DD] <inventory.json>")
	}
	var asOfDay time.Time
	if *asOf != "" {
		d, err := time.Parse("2006-01-02", *asOf)
		if err != nil {
			return fmt.Errorf("--as-of %q: want YYYY-MM-DD", *asOf)
		}
		asOfDay = d
	}
	path := fs.Arg(0)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var inv hostinv.PackageInventory
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	store, closeDB, err := openStore(ctx, *dbURL)
	if err != nil {
		return err
	}
	defer closeDB()

	host := vuln.Host{Distro: inv.Distro, Release: inv.DistroRelease, PackageManager: inv.PackageManager, AsOf: asOfDay,
		RepoHealth: inv.RepoHealth, StaleAfter: time.Duration(*staleDays) * 24 * time.Hour}
	for _, sw := range inv.Software {
		host.Packages = append(host.Packages, vuln.Package{
			Name: sw.Name, Version: sw.Version, SourcePackage: sw.SourcePackage, SourceVersion: sw.SourceVersion,
			Origin: sw.Origin, OriginRepo: sw.OriginRepo,
		})
	}
	res, err := vuln.Match(ctx, store, host)
	if err != nil {
		return err
	}
	var snapID *int64
	if snap, ok, err := store.LatestFeedSnapshot(ctx); err == nil && ok {
		snapID = &snap.ID
	}
	verdict := pendingVerdict{Reliability: string(repohealth.Unassessed), Reasons: []string{}}
	if inv.RepoHealth != nil && !inv.RepoHealth.Empty() {
		asm := repohealth.Assess(*inv.RepoHealth, repoAsOf(asOfDay), host.StaleAfter)
		verdict = pendingVerdict{Reliability: string(asm.Reliability), Reasons: asm.Reasons, Repos: asm.Checked}
	}
	return printMatch(stdout, path, res, snapID, *asJSON, *all, verdict)
}

func repoAsOf(day time.Time) time.Time {
	if day.IsZero() {
		return time.Now()
	}
	return day
}

func printMatch(w io.Writer, path string, res vuln.Result, snapID *int64, asJSON, all bool, verdict pendingVerdict) error {
	open := res.Open()
	if asJSON {
		rep := matchReport{
			Inventory: path, Distro: res.Distro, Release: res.Release, Coverage: string(res.Coverage),
			Snapshot: snapID, Stats: res.Stats, Open: len(open), Counts: countFindings(res.Findings), Findings: []matchFinding{},
			PendingUpdates: verdict,
		}
		for _, f := range res.Findings {
			rep.Findings = append(rep.Findings, matchFinding{
				AdvisoryID: f.AdvisoryID, CVE: f.CVE, RangeID: f.RangeID, SnapshotID: f.SnapshotID, Feed: f.Feed,
				FeedDate: f.FeedDate, Kind: string(f.Kind), Basis: string(f.Basis), Package: f.Package,
				SourcePackage: f.SourcePackage, Installed: f.Installed, Fixed: f.Fixed, FixState: f.FixState,
				Severity: f.Severity, KEV: f.KEV, EPSS: f.EPSS, Reason: f.Reason, EOL: f.EOL, Repo: f.Repo,
			})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		snap := "none"
		if snapID != nil {
			snap = fmt.Sprint(*snapID)
		}
		fmt.Fprintf(w, "inventory:  %s\n", path)
		fmt.Fprintf(w, "host:       %s %s (matched as %s %s), %d packages\n", orDash(res.Distro), orDash(res.Release),
			orDash(res.Distro), orDash(res.Release), res.Stats.Packages)
		fmt.Fprintf(w, "coverage:   %s (latest feed snapshot %s)\n", res.Coverage, snap)
		fmt.Fprintf(w, "examined:   %d distro-mapped, %d against upstream floors, %d undecidable, %d advisories, %d marked not-affected\n",
			res.Stats.DistroMapped, res.Stats.Upstream, res.Stats.Undecidable, res.Stats.Advisories, res.Stats.NotAffected)
		fmt.Fprintf(w, "app eol:    %d mapped to a product: %d the distribution's own (not judged), %d origin unknown (not assessed), %d no release data (not assessed), %d supported\n",
			res.Stats.EOLMapped, res.Stats.EOLDistroOrigin, res.Stats.EOLOriginUnknown, res.Stats.EOLNoRelease, res.Stats.EOLSupported)
		fmt.Fprintf(w, "repos:      %d checked, %d with a problem; pending updates: %s\n", res.Stats.RepoHealthChecked, res.Stats.RepoHealthFindings, verdict.Reliability)
		for _, r := range verdict.Reasons {
			fmt.Fprintf(w, "            - %s\n", r)
		}
		counts := countFindings(res.Findings)
		fmt.Fprintf(w, "result:     %s\n", counts.line())
		fmt.Fprintf(w, "kev:        %s\n", counts.KEV.line())
		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		shown := 0
		for _, f := range res.Findings {
			if f.Kind != vuln.KindFinding && f.Kind != vuln.KindAwaitingVendor && f.Kind != vuln.KindEOL && f.Kind != vuln.KindRepoHealth && !all {
				continue
			}
			if shown == 0 {
				fmt.Fprintln(tw, "\nSEVERITY\tKEV\tCVE\tPACKAGE\tINSTALLED\tFIXED IN\tKIND\tFEED\tNOTE")
			}
			shown++
			kev := ""
			if f.KEV {
				kev = "KEV"
			}
			note, fixed := "", orDash(f.Fixed)
			if f.Kind == vuln.KindAwaitingVendor {
				note = f.Reason
			}
			if f.Kind == vuln.KindEOL && f.EOL != nil {
				note = f.Summary + "; origin " + orDash(f.EOL.Origin)
				if f.EOL.UpgradeTo != "" {
					fixed = "upgrade to " + f.EOL.UpgradeTo
				}
			}
			if f.Kind == vuln.KindRepoHealth {
				note, fixed = f.Summary, "see fix text"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, kev, firstNonEmpty(f.CVE, f.AdvisoryID),
				f.Package, f.Installed, fixed, kindLabel(f.Kind), f.Feed, note)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	switch {
	case res.Coverage != vuln.CoverageFull:
		return exitError{exitUnassessed, fmt.Sprintf("not assessed: no advisory feed covers this host (coverage %s)", res.Coverage)}
	case len(open) > 0 || countFindings(res.Findings).EOL > 0 || countFindings(res.Findings).RepoHealth > 0:
		c := countFindings(res.Findings)
		return exitError{exitFindings, fmt.Sprintf("%d open findings, %d end-of-life, %d repository problems", len(open), c.EOL, c.RepoHealth)}
	}
	return nil
}

// kindLabel names a finding kind the way the operator reads it: "finding" is
// what can be fixed.
func kindLabel(k vuln.Kind) string {
	switch k {
	case vuln.KindFinding:
		return "fixable"
	case vuln.KindUnfixed:
		return "no_fix"
	}
	return string(k)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
