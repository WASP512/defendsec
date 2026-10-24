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
	Open      int            `json:"openFindings"`
	Findings  []matchFinding `json:"findings"`
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
	all := fs.Bool("all", false, "also list entries with no fix to install (unfixed, will_not_fix, under_investigation)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: defendsec-feeds match [--db-url URL] [--json] [--all] <inventory.json>")
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

	host := vuln.Host{Distro: inv.Distro, Release: inv.DistroRelease, PackageManager: inv.PackageManager}
	for _, sw := range inv.Software {
		host.Packages = append(host.Packages, vuln.Package{
			Name: sw.Name, Version: sw.Version, SourcePackage: sw.SourcePackage, SourceVersion: sw.SourceVersion,
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
	return printMatch(stdout, path, res, snapID, *asJSON, *all)
}

func printMatch(w io.Writer, path string, res vuln.Result, snapID *int64, asJSON, all bool) error {
	open := res.Open()
	if asJSON {
		rep := matchReport{
			Inventory: path, Distro: res.Distro, Release: res.Release, Coverage: string(res.Coverage),
			Snapshot: snapID, Stats: res.Stats, Open: len(open), Findings: []matchFinding{},
		}
		for _, f := range res.Findings {
			rep.Findings = append(rep.Findings, matchFinding{
				AdvisoryID: f.AdvisoryID, CVE: f.CVE, RangeID: f.RangeID, SnapshotID: f.SnapshotID, Feed: f.Feed,
				FeedDate: f.FeedDate, Kind: string(f.Kind), Basis: string(f.Basis), Package: f.Package,
				SourcePackage: f.SourcePackage, Installed: f.Installed, Fixed: f.Fixed, FixState: f.FixState,
				Severity: f.Severity, KEV: f.KEV, EPSS: f.EPSS,
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
		fmt.Fprintf(w, "result:     %d findings (fix available), %d unfixed (no fix published), %d informational (will not fix / investigating)\n",
			len(open), res.Stats.Unfixed, res.Stats.Informational)
		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		shown := 0
		for _, f := range res.Findings {
			if f.Kind != vuln.KindFinding && !all {
				continue
			}
			if shown == 0 {
				fmt.Fprintln(tw, "\nSEVERITY\tKEV\tCVE\tPACKAGE\tINSTALLED\tFIXED IN\tSTATE\tFEED")
			}
			shown++
			kev := ""
			if f.KEV {
				kev = "KEV"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, kev, firstNonEmpty(f.CVE, f.AdvisoryID),
				f.Package, f.Installed, orDash(f.Fixed), f.FixState, f.Feed)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	switch {
	case res.Coverage != vuln.CoverageFull:
		return exitError{exitUnassessed, fmt.Sprintf("not assessed: no advisory feed covers this host (coverage %s)", res.Coverage)}
	case len(open) > 0:
		return exitError{exitFindings, fmt.Sprintf("%d open findings", len(open))}
	}
	return nil
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
