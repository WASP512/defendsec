// Command defendsec-verify checks a DefendSec evidence bundle offline.
//
// It needs no server, no database, no network and no credentials — only the
// bundle. That independence is the point: a verifier that has to ask the
// system it is checking cannot tell you anything about that system's honesty.
//
//	defendsec-verify evidence.json
//	defendsec-verify --json evidence.json
//
// Exits 0 when every check passes, 1 when any check fails, and 2 when the
// bundle cannot be read at all.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"defendsec/internal/evidence"
)

func main() {
	asJSON := flag.Bool("json", false, "emit the report as JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: defendsec-verify [--json] <bundle.json>\n\n")
		fmt.Fprintf(os.Stderr, "Verifies a DefendSec evidence bundle using only its own contents.\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "defendsec-verify: %v\n", err)
		os.Exit(2)
	}
	defer f.Close() //nolint:errcheck

	bundle, err := evidence.Read(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "defendsec-verify: %v\n", err)
		os.Exit(2)
	}

	report := evidence.Verify(bundle)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "defendsec-verify: %v\n", err)
			os.Exit(2)
		}
	} else {
		printReport(bundle, report)
	}

	if !report.OK() {
		os.Exit(1)
	}
}

func printReport(b *evidence.Bundle, r evidence.Report) {
	m := b.Manifest
	fmt.Printf("bundle    %s\n", m.FormatVersion)
	fmt.Printf("generated %s\n", m.GeneratedAt.UTC().Format("2006-01-02 15:04:05 MST"))
	if m.Server != "" {
		fmt.Printf("server    %s\n", m.Server)
	}
	if m.Scope != "" {
		fmt.Printf("scope     %s\n", m.Scope)
	}
	fmt.Println()

	for _, c := range r.Checks {
		mark := "FAIL"
		if c.OK {
			mark = "ok"
		}
		fmt.Printf("  %-4s  %-20s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Println()

	if r.OK() {
		fmt.Println("VERIFIED — every check passed.")
		if r.CommandsUnsigned > 0 {
			fmt.Printf("Note: %d command(s) carry no retained signature and are outside what this bundle can attest.\n", r.CommandsUnsigned)
		}
		if r.AcksUnattested > 0 {
			fmt.Printf("Note: %d acknowledgement(s) are unattested, so what was authorised is proven but not what was carried out.\n", r.AcksUnattested)
		}
		return
	}
	fmt.Println("FAILED — this bundle does not verify. See the failing check above.")
}
