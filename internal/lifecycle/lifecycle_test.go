package lifecycle

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMapTable(t *testing.T) {
	cases := []struct {
		manager, name, version string
		product                string
		cycles                 []string // nil: not mapped
	}{
		// PHP: the release is in the package name.
		{"dpkg", "php8.0-cli", "8.0.30-3+0~20231014.67+debian11~1.gbpf0b1c1", "php", []string{"8.0", "8"}},
		{"dpkg", "php8.0", "8.0.30-3+0~20231014.67+debian11~1.gbpf0b1c1", "php", []string{"8.0", "8"}},
		{"dpkg", "libapache2-mod-php8.2", "8.2.12-1+ubuntu22.04.1+deb.sury.org+1", "php", []string{"8.2", "8"}},
		{"dpkg", "libphp8.1-embed", "8.1.1-1", "php", []string{"8.1", "8"}},
		// Debian's metapackages carry their own version, not PHP's: not mapped.
		{"dpkg", "php-fpm", "2:8.2+93", "", nil},
		{"dpkg", "php-pear", "1:1.10.43+submodules+notgz+2022032202-2", "", nil},
		{"rpm", "php80-php-cli", "8.0.30-1.el9.remi", "php", []string{"8.0", "8"}},
		{"rpm", "php-cli", "8.0.30-1.el9", "php", []string{"8.0", "8"}},
		{"rpm", "php-fpm", "1:8.2.12-1.el9", "php", []string{"8.2", "8"}},
		// Node.js: the version is the product's.
		{"dpkg", "nodejs", "20.11.0-1nodesource1", "nodejs", []string{"20"}},
		{"rpm", "nodejs", "2:18.19.1-1.el9", "nodejs", []string{"18"}},
		{"dpkg", "nodejs-doc", "20.11.0-1nodesource1", "", nil},
		{"dpkg", "npm", "9.2.0~ds1-1", "", nil},
		// Python: release in the name; the python3 metapackage is not mapped.
		{"dpkg", "python3.9", "3.9.18-1+jammy1", "python", []string{"3.9", "3"}},
		{"dpkg", "libpython3.10-stdlib", "3.10.12-1~22.04.12", "python", []string{"3.10", "3"}},
		{"dpkg", "python3", "3.10.6-1~22.04.1", "", nil},
		{"dpkg", "python3-pip", "22.0.2+dfsg-1", "", nil},
		{"rpm", "python3.11", "3.11.9-1.el9", "python", []string{"3.11", "3"}},
		{"rpm", "python311", "3.11.9-1.el9", "python", []string{"3.11", "3"}},
		{"rpm", "python3", "3.9.18-3.el9", "", nil},
		// PostgreSQL.
		{"dpkg", "postgresql-16", "16.4-1.pgdg22.04+1", "postgresql", []string{"16"}},
		{"dpkg", "postgresql-9.6", "9.6.24-1.pgdg90+1", "postgresql", []string{"9.6", "9"}},
		{"dpkg", "postgresql-client-16", "16.4-1.pgdg22.04+1", "", nil},
		{"rpm", "postgresql15-server", "15.8-1PGDG.rhel9", "postgresql", []string{"15"}},
		{"rpm", "postgresql96-server", "9.6.24-1PGDG.rhel7", "postgresql", []string{"9.6", "9"}},
		// MySQL and MariaDB; an epoch is not part of the release.
		{"dpkg", "mysql-community-server", "8.0.35-1debian12", "mysql", []string{"8.0", "8"}},
		{"dpkg", "mysql-server-8.0", "8.0.36-0ubuntu0.22.04.1", "mysql", []string{"8.0", "8"}},
		{"rpm", "mysql-community-server", "5.7.44-1.el7", "mysql", []string{"5.7", "5"}},
		{"dpkg", "mariadb-server", "1:10.11.6+maria~ubu2204", "mariadb", []string{"10.11", "10"}},
		{"rpm", "MariaDB-server", "10.6.16-1.el9", "mariadb", []string{"10.6", "10"}},
		{"dpkg", "mariadb-client", "1:10.11.6+maria~ubu2204", "", nil},
		// Web servers, caches, document stores.
		{"dpkg", "nginx", "1.24.0-1~jammy", "nginx", []string{"1.24", "1"}},
		{"dpkg", "nginx-common", "1.24.0-1~jammy", "", nil},
		{"dpkg", "apache2", "2.4.57-2", "apache-http-server", []string{"2.4", "2"}},
		{"rpm", "httpd", "2.4.57-5.el9", "apache-http-server", []string{"2.4", "2"}},
		{"dpkg", "redis-server", "6:7.2.4-1rl1~jammy1", "redis", []string{"7.2", "7"}},
		{"dpkg", "redis-tools", "6:7.2.4-1rl1~jammy1", "", nil},
		{"dpkg", "mongodb-org-server", "6.0.14", "mongodb", []string{"6.0", "6"}},
		// .NET and Java.
		{"dpkg", "dotnet-sdk-6.0", "6.0.428-1", "dotnet", []string{"6.0", "6"}},
		{"rpm", "aspnetcore-runtime-8.0", "8.0.4-1", "dotnet", []string{"8.0", "8"}},
		{"dpkg", "dotnet-host", "8.0.4-1", "", nil},
		{"dpkg", "temurin-17-jdk", "17.0.10.0.0+7", "eclipse-temurin", []string{"17"}},
		{"rpm", "java-17-amazon-corretto-devel", "17.0.10.7-1", "amazon-corretto", []string{"17"}},
		{"dpkg", "msopenjdk-21", "21.0.2", "microsoft-build-of-openjdk", []string{"21"}},
		{"dpkg", "openjdk-17-jre", "17.0.10+7-1", "", nil},
		// Windows: no package manager, the display name carries the release.
		{"", "Microsoft .NET Runtime - 6.0.25 (x64)", "48.100.31948", "dotnet", []string{"6.0", "6"}},
		{"", "Microsoft SQL Server 2016 (64-bit)", "13.0.7000.253", "mssqlserver", []string{"13.0", "13"}},
		{"", "Microsoft SQL Server 2008 R2 Setup", "10.50.1600.1", "mssqlserver", []string{"10.50", "10"}},
		{"", "Eclipse Temurin JDK with Hotspot 17.0.8+7 (x64)", "17.0.8.7", "eclipse-temurin", []string{"17"}},
		{"", "Mozilla Firefox", "125.0", "", nil},
		// A rule for packages with a manager does not fire on a host without one, and the reverse.
		{"", "nodejs", "20.1.0", "", nil},
		{"dpkg", "Microsoft SQL Server 2016 (64-bit)", "13.0", "", nil},
	}
	for _, c := range cases {
		m, ok := Map(c.manager, c.name, c.version)
		if c.cycles == nil {
			if ok {
				t.Errorf("Map(%q, %q, %q) = %+v, want not mapped", c.manager, c.name, c.version, m)
			}
			continue
		}
		if !ok {
			t.Errorf("Map(%q, %q, %q) not mapped, want %s %v", c.manager, c.name, c.version, c.product, c.cycles)
			continue
		}
		if m.Product != c.product || !reflect.DeepEqual(m.Cycles, c.cycles) {
			t.Errorf("Map(%q, %q, %q) = %s %v, want %s %v", c.manager, c.name, c.version, m.Product, m.Cycles, c.product, c.cycles)
		}
	}
}

func TestProductsAreSortedAndCoverTheCard(t *testing.T) {
	got := Products()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not sorted/unique: %v", got)
		}
	}
	for _, want := range []string{"php", "nodejs", "python", "postgresql", "mysql", "mariadb", "nginx", "apache-http-server",
		"eclipse-temurin", "redis", "mongodb", "dotnet", "mssqlserver"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("product %s missing from the mapping table", want)
		}
	}
}

func TestClassifyOrigin(t *testing.T) {
	cases := []struct {
		name                     string
		distro, manager, version string
		label, repo              string
		want                     Origin
		wantLabel                string
	}{
		{"debian own archive", "debian", "dpkg", "7.4.33-1+deb11u5", "Debian", "http://deb.debian.org/debian", OriginDistro, "Debian"},
		{"ubuntu own archive", "ubuntu", "dpkg", "3.10.12-1~22.04.12", "Ubuntu", "", OriginDistro, "Ubuntu"},
		{"ubuntu pro", "ubuntu", "dpkg", "3.5.2+esm1", "UbuntuESM", "", OriginDistro, "UbuntuESM"},
		{"sury on debian", "debian", "dpkg", "8.0.30-3+0~20231014.67+debian11~1.gbpf0b1c1", "deb.sury.org", "https://packages.sury.org/php", OriginThirdParty, "deb.sury.org"},
		{"ppa on ubuntu", "ubuntu", "dpkg", "8.0.30-1+ubuntu22.04.1+deb.sury.org+1", "LP-PPA-ondrej-php", "", OriginThirdParty, "LP-PPA-ondrej-php"},
		{"label case does not matter", "debian", "dpkg", "1", "DEBIAN", "", OriginDistro, "DEBIAN"},
		{"rocky own vendor", "rocky", "rpm", "3.9.18-3.el9", "Rocky Enterprise Software Foundation", "", OriginDistro, "Rocky Enterprise Software Foundation"},
		{"remi on rocky", "rocky", "rpm", "8.0.30-1.el9.remi", "Remi Collet", "", OriginThirdParty, "Remi Collet"},
		{"epel on rocky", "rocky", "rpm", "1", "Fedora Project", "", OriginThirdParty, "Fedora Project"},
		{"fedora own", "fedora", "rpm", "1", "Fedora Project", "", OriginDistro, "Fedora Project"},
		// A distribution whose labels are not known cannot be told from its repositories.
		{"unknown distro", "gentoo", "rpm", "1", "Whoever", "", OriginUnknown, "Whoever"},
		// No label: only a third-party signature in the version can say anything.
		{"suffix only, sury", "debian", "dpkg", "8.0.30-1+0~20231014+debian11~1.deb.sury.org", "", "", OriginThirdParty, "Sury"},
		{"suffix only, nodesource", "ubuntu", "dpkg", "20.11.0-1nodesource1", "", "", OriginThirdParty, "NodeSource"},
		{"suffix only, pgdg", "debian", "dpkg", "16.4-1.pgdg120+1", "", "", OriginThirdParty, "PostgreSQL (PGDG)"},
		{"no label and no signature stays unknown", "ubuntu", "dpkg", "3.10.12-1~22.04.12", "", "", OriginUnknown, ""},
		{"old agent, distro version stays unknown", "debian", "dpkg", "7.4.33-1+deb11u5", "", "", OriginUnknown, ""},
		// Windows: nothing is the distribution's.
		{"windows", "", "", "6.0.25", "", "", OriginThirdParty, "installed outside a package manager"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, label := ClassifyOrigin(c.distro, c.manager, c.version, c.label, c.repo)
			if got != c.want || label != c.wantLabel {
				t.Errorf("ClassifyOrigin = %s %q, want %s %q", got, label, c.want, c.wantLabel)
			}
		})
	}
}

// fakeSource serves release rows copied from endoflife.date (schema 1.2.1) on
// the day this slice was built.
type fakeSource struct{ rows []Release }

func (f fakeSource) EOLReleases(_ context.Context, products []string) ([]Release, error) {
	want := map[string]bool{}
	for _, p := range products {
		want[p] = true
	}
	var out []Release
	for _, r := range f.rows {
		if want[r.Product] {
			out = append(out, r)
		}
	}
	return out, nil
}

func rel(product, label, cycle, eoas, eol string) Release {
	return Release{Product: product, Label: label, Cycle: cycle, EoasFrom: eoas, EolFrom: eol, Latest: cycle + ".0"}
}

var fixtureRows = []Release{
	rel("php", "PHP", "8.5", "2027-12-31", "2029-12-31"),
	rel("php", "PHP", "8.4", "2026-12-31", "2028-12-31"),
	rel("php", "PHP", "8.3", "2025-12-31", "2027-12-31"),
	rel("php", "PHP", "8.2", "2024-12-31", "2026-12-31"),
	rel("php", "PHP", "8.1", "2023-11-25", "2025-12-31"),
	rel("php", "PHP", "8.0", "2022-11-26", "2023-11-26"),
	rel("php", "PHP", "7.4", "2021-11-28", "2022-11-28"),
	rel("python", "Python", "3.10", "2023-04-05", "2026-10-01"),
	rel("python", "Python", "3.12", "2025-04-02", "2028-10-31"),
	rel("nodejs", "Node.js", "20", "2024-10-22", "2026-04-30"),
	rel("nodejs", "Node.js", "22", "2025-10-21", "2027-04-30"),
	rel("nodejs", "Node.js", "24", "2026-10-20", "2028-04-30"),
	rel("dotnet", ".NET", "6", "", "2024-11-12"),
	rel("dotnet", ".NET", "8", "", "2026-11-10"),
	rel("dotnet", ".NET", "10", "", "2028-11-14"),
}

var asOf = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func pkgs(manager, origin string, nv ...string) []Package {
	var out []Package
	for i := 0; i+1 < len(nv); i += 2 {
		out = append(out, Package{Name: nv[i], Version: nv[i+1], Origin: origin})
	}
	return out
}

// The motivating case: PHP 8.0 from Sury on Debian 11. Three packages of one
// release are one finding, naming PHP 8.0, its end-of-life date and the origin.
func TestAssessSuryPHP80(t *testing.T) {
	h := Host{Distro: "debian", Manager: "dpkg", AsOf: asOf, Packages: append(
		pkgs("dpkg", "deb.sury.org", "php8.0-fpm", "8.0.30-3+0~2023", "php8.0-cli", "8.0.30-3+0~2023", "php8.0-common", "8.0.30-3+0~2023"),
		pkgs("dpkg", "Debian", "openssl", "1.1.1w-0+deb11u1", "python3.9", "3.9.2-1")...)}
	got, st, err := Assess(context.Background(), fakeSource{fixtureRows}, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %d (%v), want exactly 1", len(got), got)
	}
	f := got[0]
	if f.Product != "php" || f.Cycle != "8.0" || f.Stage != StageEOL || f.EolFrom != "2023-11-26" || f.StageFrom != "2023-11-26" {
		t.Errorf("finding = %+v", f)
	}
	if f.OriginLabel != "deb.sury.org" || f.Origin != OriginThirdParty {
		t.Errorf("origin = %s %q", f.Origin, f.OriginLabel)
	}
	if f.Package != "php8.0-cli" || !reflect.DeepEqual(f.Packages, []string{"php8.0-cli", "php8.0-common", "php8.0-fpm"}) {
		t.Errorf("package = %s, packages = %v", f.Package, f.Packages)
	}
	if f.AdvisoryID() != "EOL:php:8.0" {
		t.Errorf("id = %s", f.AdvisoryID())
	}
	// 8.2 and 8.3 are past active support; 8.4 is the oldest with active support left.
	if f.UpgradeTo != "8.4" || f.UpgradeToSupportedUntil != "2028-12-31" || f.Fixed != "8.2" {
		t.Errorf("upgrade = %q until %q fixed %q", f.UpgradeTo, f.UpgradeToSupportedUntil, f.Fixed)
	}
	for _, want := range []string{"PHP 8.0 reached end of life on 2023-11-26", "(deb.sury.org)", "upgrading to PHP 8.4"} {
		if !strings.Contains(f.Reason, want) {
			t.Errorf("reason %q lacks %q", f.Reason, want)
		}
	}
	// openssl and python3.9 are from Debian: python3.9 maps to a product but is not judged.
	if st.Mapped != 4 || st.DistroOrigin != 1 || st.Findings != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// Origin decides: Ubuntu 22.04's own python3.10 is upstream end-of-life and
// supported by Canonical, so it is no finding.
func TestAssessDistroOriginIsNeverAFinding(t *testing.T) {
	h := Host{Distro: "ubuntu", Manager: "dpkg", AsOf: asOf,
		Packages: pkgs("dpkg", "Ubuntu", "python3.10", "3.10.12-1~22.04.12", "libpython3.10-stdlib", "3.10.12-1~22.04.12", "nodejs", "12.22.9~dfsg-1ubuntu3.6")}
	got, st, err := Assess(context.Background(), fakeSource{fixtureRows}, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || st.DistroOrigin != 3 || st.Mapped != 3 {
		t.Fatalf("findings = %v, stats = %+v; want none, 3 mapped and 3 distro-origin", got, st)
	}
}

// Unknown origin is not assessed: never a finding, never counted clean.
func TestAssessUnknownOriginIsNotAssessed(t *testing.T) {
	h := Host{Distro: "debian", Manager: "dpkg", AsOf: asOf,
		Packages: []Package{{Name: "php8.0-cli", Version: "8.0.30-3+0~2023"}}}
	got, st, err := Assess(context.Background(), fakeSource{fixtureRows}, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || st.OriginUnknown != 1 || st.Supported != 0 {
		t.Fatalf("findings = %v, stats = %+v", got, st)
	}
}

func TestAssessSupportedAndMissingReleases(t *testing.T) {
	h := Host{Distro: "debian", Manager: "dpkg", AsOf: asOf,
		Packages: pkgs("dpkg", "deb.sury.org", "php8.4-cli", "8.4.1-1", "php9.9-cli", "9.9.0-1")}
	got, st, err := Assess(context.Background(), fakeSource{fixtureRows}, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || st.Supported != 1 || st.NoRelease != 1 {
		t.Fatalf("findings = %v, stats = %+v", got, st)
	}
}

// Past security support ranks above past active support.
func TestAssessStagesAndOrder(t *testing.T) {
	h := Host{Distro: "debian", Manager: "dpkg", AsOf: asOf, Packages: pkgs("dpkg", "NodeSource",
		"nodejs", "22.1.0-1nodesource1")} // nodejs 22: active support ended 2025-10-21, security until 2027-04-30
	h.Packages = append(h.Packages, pkgs("dpkg", "deb.sury.org", "php8.1-cli", "8.1.30-1", "php8.2-cli", "8.2.20-1")...)
	got, _, err := Assess(context.Background(), fakeSource{fixtureRows}, h)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range got {
		ids = append(ids, f.AdvisoryID()+"/"+string(f.Stage))
	}
	want := []string{"EOL:php:8.1/eol", "EOL:nodejs:22/eoas", "EOL:php:8.2/eoas"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("order = %v, want %v", ids, want)
	}
	for _, f := range got {
		if f.Stage == StageEOAS && !strings.Contains(f.Reason, "security fixes continue until") {
			t.Errorf("eoas reason %q", f.Reason)
		}
	}
}

func TestAssessWindowsHasNoDistro(t *testing.T) {
	h := Host{AsOf: asOf, Packages: []Package{
		{Name: "Microsoft .NET Runtime - 6.0.25 (x64)", Version: "48.100.31948"},
		{Name: "Microsoft .NET Runtime - 8.0.4 (x64)", Version: "64.16.1234"},
		{Name: "7-Zip", Version: "23.01"},
	}}
	got, st, err := Assess(context.Background(), fakeSource{fixtureRows}, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Product != "dotnet" || got[0].Cycle != "6" || got[0].OriginLabel != "installed outside a package manager" {
		t.Fatalf("findings = %v", got)
	}
	if got[0].UpgradeTo != "8" || st.Supported != 1 {
		t.Errorf("upgrade = %q, stats = %+v", got[0].UpgradeTo, st)
	}
}

func TestAssessNoUpgradeWhenNothingNewerIsSupported(t *testing.T) {
	rows := []Release{rel("php", "PHP", "8.0", "2022-11-26", "2023-11-26"), rel("php", "PHP", "7.4", "", "2022-11-28")}
	h := Host{Distro: "debian", Manager: "dpkg", AsOf: asOf, Packages: pkgs("dpkg", "deb.sury.org", "php8.0-cli", "8.0.30-1")}
	got, _, err := Assess(context.Background(), fakeSource{rows}, h)
	if err != nil || len(got) != 1 {
		t.Fatalf("err = %v, findings = %v", err, got)
	}
	if got[0].UpgradeTo != "" || got[0].Fixed != "" || strings.Contains(got[0].Reason, "upgrading") {
		t.Errorf("finding offers an upgrade it cannot name: %+v", got[0])
	}
}

func TestAssessIsDeterministic(t *testing.T) {
	ps := pkgs("dpkg", "deb.sury.org", "php8.0-fpm", "8.0.30-3", "php8.0-cli", "8.0.30-3", "php8.0-common", "8.0.30-3", "php8.1-cli", "8.1.1-1")
	h := Host{Distro: "debian", Manager: "dpkg", AsOf: asOf, Packages: ps}
	first, _, _ := Assess(context.Background(), fakeSource{fixtureRows}, h)
	for i := 0; i < 20; i++ {
		rev := append([]Package(nil), ps...)
		for a, b := 0, len(rev)-1; a < b; a, b = a+1, b-1 {
			rev[a], rev[b] = rev[b], rev[a]
		}
		if i%2 == 0 {
			rev = ps
		}
		again, _, _ := Assess(context.Background(), fakeSource{fixtureRows}, Host{Distro: "debian", Manager: "dpkg", AsOf: asOf, Packages: rev})
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\n%v\n%v", i, first, again)
		}
	}
}

func TestStageOf(t *testing.T) {
	cases := []struct {
		r    Release
		day  string
		want Stage
	}{
		{Release{EoasFrom: "2022-11-26", EolFrom: "2023-11-26"}, "2023-11-26", StageEOL}, // the day itself
		{Release{EoasFrom: "2022-11-26", EolFrom: "2023-11-26"}, "2023-11-25", StageEOAS},
		{Release{EoasFrom: "2022-11-26", EolFrom: "2023-11-26"}, "2022-11-25", ""},
		{Release{EolFrom: "2023-11-26"}, "2023-11-25", ""}, // no active-support date: supported until EOL
		{Release{IsEol: true}, "2026-01-01", StageEOL},     // end of life with no date on record
		{Release{}, "2026-01-01", ""},                      // nothing known: not flagged
	}
	for _, c := range cases {
		if got := StageOf(c.r, c.day); got != c.want {
			t.Errorf("StageOf(%+v, %s) = %q, want %q", c.r, c.day, got, c.want)
		}
	}
}

func TestCmpCycle(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"9.6", "10", -1}, {"10", "9.6", 1}, {"8.0", "8.0", 0}, {"8", "8.0", 0}, {"10.11", "10.6", 1}, {"3.9", "3.10", -1}} {
		if got := cmpCycle(c.a, c.b); got != c.want {
			t.Errorf("cmpCycle(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
