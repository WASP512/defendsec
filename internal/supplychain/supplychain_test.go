package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guard that would have caught the drift it was written for.
//
// internal/control grew database-backed tests long after the CI job naming
// its packages was written, and nobody updated the job. Those tests ran
// locally and skipped in CI, so the guarantees they cover — per-user
// attribution, an agent being unable to sign its own authority, autonomy
// staying inside its blast-radius ceiling — went unverified on every pull
// request while appearing to be tested.
//
// This asserts the CI job covers every package that needs a database, so the
// next package to grow one fails here rather than skipping quietly.
func TestEveryIntegrationPackageRunsInCI(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := PackagesNeedingDatabase(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no packages with database-backed tests were found; the scan is broken, which would make this guard pass vacuously")
	}

	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	job := IntegrationJob(string(raw))
	if job == "" {
		t.Fatalf("no CI step sets %s, so every database-backed test skips in CI", IntegrationEnvVar)
	}

	for _, pkg := range pkgs {
		if !WorkflowCoversPackage(job, pkg) {
			t.Errorf("package %s has tests that skip without a database, and no CI step with %s runs it. Its tests pass locally and do nothing in CI. Add it to the postgres-integration job.",
				pkg, IntegrationEnvVar)
		}
	}
}

// The scan has to find the packages that actually exist today, or the guard
// above is asserting nothing.
func TestTheScanFindsTheKnownIntegrationPackages(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := PackagesNeedingDatabase(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(pkgs, " ")
	for _, want := range []string{"internal/storepg", "db/migrations", "internal/control"} {
		if !strings.Contains(got, want) {
			t.Errorf("the scan missed %s; found %v", want, pkgs)
		}
	}
}

func TestWorkflowCoverageMatching(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		pkg      string
		expected bool
	}{
		{"exact package", "go test -p 1 ./internal/control/...", "internal/control", true},
		{"child of a covered tree", "go test ./internal/...", "internal/control", true},
		{"everything", "go test ./...", "internal/control", true},
		{"not named", "go test ./internal/storepg/...", "internal/control", false},
		{
			// The specific trap: a prefix that is not a path boundary.
			// ./internal/cont would not cover internal/control, and a naive
			// strings.HasPrefix would say it did.
			name: "prefix that is not a path boundary", command: "go test ./internal/cont/...",
			pkg: "internal/control", expected: false,
		},
		{"no package arguments at all", "go test", "internal/control", false},
		{"several targets", "go test -p 1 ./a/... ./internal/control/... ./b/...", "internal/control", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WorkflowCoversPackage(tc.command, tc.pkg); got != tc.expected {
				t.Errorf("WorkflowCoversPackage(%q, %q) = %v, want %v",
					tc.command, tc.pkg, got, tc.expected)
			}
		})
	}
}

// A workflow that sets the variable nowhere must report no coverage rather
// than matching some unrelated job's `go test ./...`, which would make the
// guard pass while every integration test skipped.
func TestAWorkflowWithNoDatabaseStepCoversNothing(t *testing.T) {
	const workflow = `
jobs:
  go:
    steps:
      - run: go test ./...
`
	if job := IntegrationJob(workflow); job != "" {
		t.Errorf("a workflow with no %s was treated as having an integration step", IntegrationEnvVar)
	}
}

// The unit test job must NOT be mistaken for the integration job. It runs
// `go test ./...`, which textually covers everything — but without a
// database, so the tests skip.
func TestTheUnitJobIsNotMistakenForTheIntegrationJob(t *testing.T) {
	const workflow = `
jobs:
  go:
    steps:
      - run: go test ./...
  postgres-integration:
    steps:
      - env:
          TEST_DATABASE_URL: postgres://localhost/db
        run: go test ./internal/storepg/...
`
	job := IntegrationJob(workflow)
	if job == "" {
		t.Fatal("the integration step was not found")
	}
	if WorkflowCoversPackage(job, "internal/control") {
		t.Error("the unit job's ./... was counted as integration coverage; that is exactly how the original gap hid")
	}
	if !WorkflowCoversPackage(job, "internal/storepg") {
		t.Error("the integration step's own package was not matched")
	}
}

func TestRepoRootIsFound(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("RepoRoot returned %q, which has no go.mod", root)
	}
}

// The release build and the reproducibility check must use the same flags.
//
// If they drift, the check verifies something the release does not do — which
// is worse than having no check, because it reports success for a property
// nobody has actually tested.
func TestReproducibleFlagsMatchTheReleaseScript(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		"scripts/build-release.sh",
		"scripts/check-reproducible.sh",
	} {
		raw, err := os.ReadFile(filepath.Join(root, script))
		if err != nil {
			t.Fatalf("%s: %v", script, err)
		}
		body := string(raw)
		for _, flag := range ReproducibilityFlags {
			// Skip the explanatory comments: a flag named only in prose
			// would satisfy a naive check while the build did not use it.
			if !containsOutsideComments(body, flag) {
				t.Errorf("%s does not use %s outside its comments; a release built without it is not reproducible",
					script, flag)
			}
		}
	}
}

// containsOutsideComments reports whether a shell script uses a token in a
// command rather than only mentioning it in a comment.
func containsOutsideComments(script, token string) bool {
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		if strings.Contains(line, token) {
			return true
		}
	}
	return false
}

// The release script must stamp the commit, because release builds switch off
// Go's automatic VCS stamping. Without the explicit stamp the information is
// simply lost and a binary cannot say what it was built from.
func TestTheReleaseScriptStampsTheCommit(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "build-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsOutsideComments(string(raw), "main.buildCommit=") {
		t.Error("the release script switches off VCS stamping without stamping the commit itself, so released binaries cannot report what they were built from")
	}
}

// Every release binary must declare the variable the release script stamps.
// -X against a symbol that does not exist is silently ignored, so a main
// package missing it would report "unknown" forever with no error anywhere.
func TestEveryMainPackageDeclaresBuildCommit(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		main := filepath.Join(root, "cmd", e.Name(), "main.go")
		raw, err := os.ReadFile(main)
		if err != nil {
			continue
		}
		checked++
		if !strings.Contains(string(raw), "buildCommit") {
			t.Errorf("cmd/%s does not declare buildCommit; the release script's -X flag against it is silently ignored, so the binary reports no commit and nothing warns",
				e.Name())
		}
	}
	if checked == 0 {
		t.Fatal("no cmd/*/main.go files were found; this guard is asserting nothing")
	}
}
