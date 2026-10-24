package vuln

import (
	"context"
	"testing"
	"time"

	"defendsec/internal/lifecycle"
)

// eolSource is the in-memory advisory store plus a release calendar, the shape
// the Postgres store has.
type eolSource struct {
	*fakeSource
	rels []lifecycle.Release
}

func (e eolSource) EOLReleases(_ context.Context, products []string) ([]lifecycle.Release, error) {
	want := map[string]bool{}
	for _, p := range products {
		want[p] = true
	}
	var out []lifecycle.Release
	for _, r := range e.rels {
		if want[r.Product] {
			out = append(out, r)
		}
	}
	return out, nil
}

var eolRels = []lifecycle.Release{
	{Product: "php", Label: "PHP", Cycle: "8.4", EoasFrom: "2026-12-31", EolFrom: "2028-12-31"},
	{Product: "php", Label: "PHP", Cycle: "8.0", EoasFrom: "2022-11-26", EolFrom: "2023-11-26", Latest: "8.0.30", Link: "https://www.php.net/ChangeLog-8.php#8.0.30"},
	{Product: "python", Label: "Python", Cycle: "3.10", EoasFrom: "2023-04-05", EolFrom: "2026-10-01"},
}

var eolDay = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

func TestMatchRaisesEOLForThirdPartyOnly(t *testing.T) {
	src := eolSource{&fakeSource{}, eolRels}
	h := Host{Distro: "debian", Release: "11", PackageManager: "dpkg", AsOf: eolDay, Packages: []Package{
		{Name: "php8.0-cli", Version: "8.0.30-3+0~2023", Origin: "deb.sury.org", OriginRepo: "https://packages.sury.org/php"},
		{Name: "php8.0-common", Version: "8.0.30-3+0~2023", Origin: "deb.sury.org", OriginRepo: "https://packages.sury.org/php"},
		{Name: "python3.10", Version: "3.10.12-1", Origin: "Debian"},
		{Name: "bash", Version: "5.1-2+deb11u1", Origin: "Debian"},
	}}
	res, err := Match(context.Background(), src, h)
	if err != nil {
		t.Fatal(err)
	}
	var eol []Finding
	for _, f := range res.Findings {
		if f.Kind == KindEOL {
			eol = append(eol, f)
		}
	}
	if len(eol) != 1 {
		t.Fatalf("findings = %+v, want exactly one eol", res.Findings)
	}
	f := eol[0]
	if f.AdvisoryID != "EOL:php:8.0" || f.Basis != BasisLifecycle || f.Severity != "high" || f.Package != "php8.0-cli" || f.SourcePackage != "php" ||
		f.Fixed != "" || f.FixState != "end_of_life" || f.Feed != "endoflife" || f.KEV || f.CVE != "" {
		t.Errorf("finding = %+v", f)
	}
	if f.Summary != "PHP 8.0 reached end of life on 2023-11-26" {
		t.Errorf("summary = %q", f.Summary)
	}
	if d := f.EOL; d == nil || d.Stage != "eol" || d.StageFrom != "2023-11-26" || d.Origin != "deb.sury.org" || d.OriginRepo != "https://packages.sury.org/php" ||
		d.UpgradeTo != "8.4" || d.UpgradeToSupportedUntil != "2028-12-31" || len(d.Packages) != 2 || d.Latest != "8.0.30" {
		t.Errorf("detail = %+v", f.EOL)
	}
	// php8.0 x2 from Sury, python3.10 from Debian (mapped, not judged), bash unmapped
	if res.Stats.EOLMapped != 3 || res.Stats.EOLDistroOrigin != 1 || res.Stats.EOLOriginUnknown != 0 {
		t.Errorf("stats = %+v", res.Stats)
	}
	// An eol finding is not a patch: it is not in the "fixable" list the CLI and
	// the old tests read.
	if len(res.Open()) != 0 {
		t.Errorf("Open() = %+v", res.Open())
	}
}

func TestMatchOldAgentWithoutOriginIsNotAssessed(t *testing.T) {
	src := eolSource{&fakeSource{}, eolRels}
	h := Host{Distro: "debian", Release: "11", PackageManager: "dpkg", AsOf: eolDay,
		Packages: []Package{{Name: "php8.0-cli", Version: "8.0.30-3+0~2023"}}}
	res, err := Match(context.Background(), src, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.Stats.EOLOriginUnknown != 1 {
		t.Fatalf("findings = %+v, stats = %+v; want none and one not assessed", res.Findings, res.Stats)
	}
}

// A source with no release calendar (the matcher's older tests, a store before
// the migration) matches exactly as before.
func TestMatchWithoutCalendarSourceIsUnchanged(t *testing.T) {
	h := Host{Distro: "debian", Release: "11", PackageManager: "dpkg", AsOf: eolDay,
		Packages: []Package{{Name: "php8.0-cli", Version: "8.0.30-3", Origin: "deb.sury.org"}}}
	res, err := Match(context.Background(), &fakeSource{}, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.Stats.EOLMapped != 0 {
		t.Fatalf("findings = %+v, stats = %+v", res.Findings, res.Stats)
	}
}

// Patch findings come first, then end-of-life, then the watch kinds.
func TestMatchOrdersEOLAfterPatches(t *testing.T) {
	fs := &fakeSource{ranges: []Candidate{{
		AdvisoryID: "USN-1", CVE: "CVE-2099-1", Severity: "low", Distro: "ubuntu", Release: "22.04", Package: "bash",
		Fixed: "5.1-6ubuntu1.2", State: StateFixed,
	}}}
	src := eolSource{fs, eolRels}
	h := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", AsOf: eolDay, Packages: []Package{
		{Name: "bash", Version: "5.1-6ubuntu1.1", Origin: "Ubuntu"},
		{Name: "php8.0-cli", Version: "8.0.30-3", Origin: "LP-PPA-ondrej-php"},
	}}
	res, err := Match(context.Background(), src, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 || res.Findings[0].Kind != KindFinding || res.Findings[1].Kind != KindEOL {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestMatchCalendarErrorSurfaces(t *testing.T) {
	src := errEOL{eolSource{&fakeSource{}, nil}}
	h := Host{Distro: "debian", PackageManager: "dpkg", AsOf: eolDay,
		Packages: []Package{{Name: "php8.0-cli", Version: "8.0.30-3", Origin: "deb.sury.org"}}}
	if _, err := Match(context.Background(), src, h); err == nil {
		t.Fatal("a calendar that cannot be read must not look like a clean host")
	}
}

type errEOL struct{ eolSource }

func (errEOL) EOLReleases(context.Context, []string) ([]lifecycle.Release, error) {
	return nil, context.DeadlineExceeded
}
