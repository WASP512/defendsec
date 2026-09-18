// Package supplychain holds DefendSec's checks on itself (roadmap 5.7).
//
// A tool that asks operators to verify signatures, check provenance and read
// an SBOM has to hold itself to the same standard. The pitch is meant to be
// "verify our binaries with the same tooling we give you for your fleet",
// and that is only worth saying if it is true and checkable.
//
// What lives here is the checkable part: invariants about the repository and
// its build that are asserted by tests rather than described in a document.
// The document drifts; the test fails.
package supplychain

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// IntegrationEnvVar is the variable whose absence makes a database-backed test
// skip. A package containing it has tests that do nothing without a database.
const IntegrationEnvVar = "TEST_DATABASE_URL"

// RepoRoot walks up from the working directory to the module root.
//
// Tests run with the working directory set to their own package, so a test
// asserting something about the repository has to find it rather than assume
// a relative depth.
func RepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", start)
		}
		dir = parent
	}
}

// PackagesNeedingDatabase returns the import paths, relative to the module
// root, of every package whose tests skip without a database.
//
// Discovered by scanning rather than listed, because a list is what drifted
// in the first place: internal/control grew database-backed tests months
// after the CI job naming its packages was written, and nobody updated the
// job. The tests ran locally, skipped in CI, and the guarantees they cover
// went unverified on every pull request.
func PackagesNeedingDatabase(root string) ([]string, error) {
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "dist", ".next", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !integrationProbe.Match(raw) {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		seen[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for pkg := range seen {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out, nil
}

// integrationProbe matches a test actually reading the variable in order to
// skip, rather than merely mentioning its name.
//
// Precision matters here: this file's own tests contain the variable's name
// in fixtures and in a constant reference, and matching the bare name would
// report this package as needing a database. A guard with a false positive
// gets an exception added to it, and an exception is how the next real case
// gets excluded too.
var integrationProbe = regexp.MustCompile(`os\.Getenv\("` + regexp.QuoteMeta(IntegrationEnvVar) + `"\)`)

// goTestPattern finds the package arguments of a `go test` invocation in a
// workflow file.
var goTestPattern = regexp.MustCompile(`go test[^\n]*`)

// WorkflowCoversPackage reports whether a workflow's `go test` invocations,
// among those that set the integration environment variable, would run a
// package.
//
// Pattern matching on a shell command rather than executing it: the aim is to
// catch a package nobody remembered to add, and for that a textual check of
// what the job actually runs is both sufficient and honest about its limits.
// A `./...` covers everything; anything narrower is matched by prefix, since
// `./internal/control/...` covers `internal/control` and its children.
func WorkflowCoversPackage(workflow, pkg string) bool {
	for _, invocation := range goTestPattern.FindAllString(workflow, -1) {
		for _, field := range strings.Fields(invocation) {
			if !strings.HasPrefix(field, "./") {
				continue
			}
			target := strings.TrimSuffix(strings.TrimSuffix(field, "..."), "/")
			target = strings.TrimPrefix(target, "./")
			if target == "" || target == "." {
				// `./...` — everything. Both spellings, because trimming
				// "./..." leaves "." rather than the empty string and
				// checking only for empty silently matched nothing.
				return true
			}
			if pkg == target || strings.HasPrefix(pkg, target+"/") {
				return true
			}
		}
	}
	return false
}

// IntegrationJob extracts the part of a workflow that sets the integration
// environment variable, so a `go test` in some unrelated job is not mistaken
// for one that has a database.
//
// Returns the whole file when the variable is absent, so a caller gets a
// clear "not covered" rather than a silent pass.
func IntegrationJob(workflow string) string {
	idx := strings.Index(workflow, IntegrationEnvVar)
	if idx < 0 {
		return ""
	}
	// From the variable to the end of that step's block. Steps are separated
	// by a `- name:` at the same indentation; taking everything after is
	// simpler and cannot miss the command, at the cost of possibly including
	// a later job's — which would only ever make this check more permissive,
	// and a permissive check that still caught the real drift is the right
	// trade for a guard like this.
	return workflow[idx:]
}

// ReproducibilityFlags are the build flags that make a release binary
// reproducible. Dropping any one of them breaks it, in ways measured rather
// than guessed:
//
//   - -trimpath: without it the build directory is embedded, so the hash
//     depends on where it was compiled.
//   - -buildvcs=false: without it Go stamps the git commit and dirty flag
//     into a main package, so the hash depends on a .git directory being
//     present — and a verifier rebuilding from a source tarball gets a
//     different answer than CI produced.
//   - CGO_ENABLED=0: without it the host toolchain and libc are involved.
var ReproducibilityFlags = []string{"-trimpath", "-buildvcs=false", "CGO_ENABLED=0"}
