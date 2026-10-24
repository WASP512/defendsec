package lifecycle

import (
	"regexp"
	"sort"
	"strings"
)

// Match is what the mapping table says an installed package is.
type Match struct {
	// Product is the endoflife.date product slug ("php").
	Product string
	// Cycles are the release cycles to look for, most specific first ("8.0",
	// then "8"): products name their cycles differently ("8.0" for PHP, "8" for
	// .NET and Node.js), so the first one the feed has wins. A package whose
	// cycle the feed does not list is not assessed.
	Cycles []string
}

// A rule maps package names to a product. Exactly one of fromName and
// fromVersion says where the release cycle is read from:
//
//   - fromName: capture groups of the name pattern ("php8.0-cli" is PHP 8.0;
//     "postgresql-15" is PostgreSQL 15).
//   - fromVersion: the upstream version of the package ("nodejs 20.11.0-1nodesource1"
//     is Node.js 20), for packages that are not named after their release
//     and whose version is the product's own version.
//
// Rules are deliberately narrow. A pattern that also matched a plugin or a
// library with its own version numbers would assign it somebody else's
// lifecycle, so metapackages whose version is not the product's (Debian's
// "php-fpm" is 2:8.2+93) are left out rather than guessed at.
type rule struct {
	product string
	manager string // "dpkg", "rpm", "none" (host without a package manager), "" for any with one
	name    *regexp.Regexp
	// fromName builds the cycle from the name's capture groups.
	fromName func(m []string) string
	// maxParts bounds the version components a version-derived cycle may use.
	maxParts int
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

func fromGroup(m []string) string { return m[1] }

// pgCycle turns the digits of an RPM name ("postgresql96-server") into a
// cycle: PostgreSQL 10 and later are numbered "10", "15"; before that "9.6".
func pgCycle(m []string) string {
	d := m[1]
	if len(d) == 2 && d[0] == '9' {
		return "9." + d[1:]
	}
	return d
}

func joinGroups(sep string) func(m []string) string {
	return func(m []string) string { return m[1] + sep + m[2] }
}

// sqlServerCycles maps the year in "Microsoft SQL Server 2016" to the
// release cycle endoflife.date names it by (its internal major version).
var sqlServerCycles = map[string]string{
	"2008": "10.0", "2008 r2": "10.50", "2012": "11.0", "2014": "12.0", "2016": "13.0",
	"2017": "14.0", "2019": "15.0", "2022": "16.0", "2025": "17.0",
}

var rules = []rule{
	// PHP. Debian and Ubuntu name every PHP package after its release
	// (php8.0-cli, libapache2-mod-php8.0), the third-party builds (Sury, the
	// ondrej PPA) as well. RPM builds from Remi are php80-php-cli; the
	// unversioned php, php-cli, php-fpm of a RPM host carry PHP's own version.
	{product: "php", manager: ManagerDPKG, name: re(`^(?:libapache2-mod-|lib)?php(\d+\.\d+)(?:-.+)?$`), fromName: fromGroup},
	{product: "php", manager: ManagerRPM, name: re(`^php(\d)(\d)-php(?:-.+)?$`), fromName: joinGroups(".")},
	{product: "php", manager: ManagerRPM, name: re(`^php(?:-cli|-fpm|-cgi|-common)?$`), maxParts: 2},

	{product: "nodejs", manager: "", name: re(`^nodejs$`), maxParts: 1},

	// Python. Third-party builds (deadsnakes, a vendor repo) are named after
	// their release; the distro's own python3 metapackage is left alone.
	{product: "python", manager: ManagerDPKG, name: re(`^(?:lib)?python(3\.\d+)(?:-(?:minimal|stdlib|venv|dev|dbg|full|distutils|lib2to3|tk|gdbm|doc|examples|nopie))?$`), fromName: fromGroup},
	{product: "python", manager: ManagerRPM, name: re(`^python(3\.\d+)(?:-.+)?$`), fromName: fromGroup},
	{product: "python", manager: ManagerRPM, name: re(`^python3(\d{1,2})(?:-.+)?$`), fromName: func(m []string) string { return "3." + m[1] }},

	// PostgreSQL. PGDG names packages after the release (postgresql-16 on
	// Debian and Ubuntu, postgresql16-server on RPM).
	{product: "postgresql", manager: ManagerDPKG, name: re(`^postgresql-(\d+(?:\.\d+)?)$`), fromName: fromGroup},
	{product: "postgresql", manager: ManagerRPM, name: re(`^postgresql(\d{2,3})(?:-server)?$`), fromName: pgCycle},

	// MySQL and MariaDB.
	{product: "mysql", manager: "", name: re(`^mysql-community-server$`), maxParts: 2},
	{product: "mysql", manager: "", name: re(`^mysql-server$`), maxParts: 2},
	{product: "mysql", manager: ManagerDPKG, name: re(`^mysql-server(?:-core)?-(\d+\.\d+)$`), fromName: fromGroup},
	{product: "mariadb", manager: "", name: re(`^(?i:mariadb)-server$`), maxParts: 2},
	{product: "mariadb", manager: ManagerDPKG, name: re(`^mariadb-server(?:-core)?-(\d+\.\d+)$`), fromName: fromGroup},

	// Web servers: nginx.org and Apache builds.
	{product: "nginx", manager: "", name: re(`^nginx$`), maxParts: 2},
	{product: "apache-http-server", manager: ManagerDPKG, name: re(`^apache2$`), maxParts: 2},
	{product: "apache-http-server", manager: ManagerRPM, name: re(`^httpd$`), maxParts: 2},

	// Redis and MongoDB.
	{product: "redis", manager: "", name: re(`^redis(?:-server)?$`), maxParts: 2},
	{product: "mongodb", manager: "", name: re(`^mongodb-(?:org|org-server|org-mongos|enterprise-server)$`), maxParts: 2},

	// .NET, from Microsoft's repository and from the distro.
	{product: "dotnet", manager: "", name: re(`^(?:dotnet-sdk|dotnet-runtime|aspnetcore-runtime|dotnet-hostfxr)-(\d+\.\d+)$`), fromName: fromGroup},

	// Java. Eclipse Temurin, Amazon Corretto and the Microsoft build name
	// the major release in the package name.
	{product: "eclipse-temurin", manager: "", name: re(`^temurin-(\d+)-(?:jdk|jre)(?:-headless)?$`), fromName: fromGroup},
	{product: "amazon-corretto", manager: "", name: re(`^java-(\d+)-amazon-corretto(?:-.+)?$`), fromName: fromGroup},
	{product: "amazon-corretto", manager: "", name: re(`^amazon-corretto-(\d+)(?:-.+)?$`), fromName: fromGroup},
	{product: "microsoft-build-of-openjdk", manager: "", name: re(`^msopenjdk-(\d+)$`), fromName: fromGroup},

	// Windows. No package manager: the program's display name carries the
	// release. These rows are unit-tested on names only; no Windows host has
	// reported through them yet.
	{product: "dotnet", manager: "none", name: re(`^Microsoft (?:\.NET (?:Runtime|SDK|Host FX Resolver|Windows Desktop Runtime|AspNetCore[^-]*Runtime)|Windows Desktop Runtime|ASP\.NET Core) ?-? ?(\d+\.\d+)\.\d+`), fromName: fromGroup},
	{product: "mssqlserver", manager: "none", name: re(`^Microsoft SQL Server (2008 R2|20\d\d)\b`), fromName: func(m []string) string { return sqlServerCycles[strings.ToLower(m[1])] }},
	{product: "eclipse-temurin", manager: "none", name: re(`^Eclipse Temurin JDK with Hotspot (\d+)\.`), fromName: fromGroup},
}

// Products lists every endoflife.date product the mapping table can produce,
// sorted; it is the set of products the feed keeps.
func Products() []string {
	seen := map[string]struct{}{}
	for _, r := range rules {
		seen[r.product] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// OSProducts are the operating-system calendars the console's Supported OS
// policy reads. They are kept in the same feed and the same table as the
// application products but are never produced by the package mapping, so
// Products() does not list them.
var OSProducts = []string{"windows", "windows-server"}

// FeedProducts is every product the endoflife feed keeps.
func FeedProducts() []string {
	return append(Products(), OSProducts...)
}

// managerOf folds a host's package manager onto the rules' vocabulary.
func managerKey(manager string) string {
	if manager == "" {
		return "none"
	}
	return manager
}

// Map says which product and release cycle an installed package is, if the
// table knows it. A package the table does not know is not assessed.
func Map(manager, name, version string) (Match, bool) {
	key := managerKey(manager)
	for _, r := range rules {
		if r.manager != "" && r.manager != key {
			continue
		}
		if r.manager == "" && key == "none" {
			continue // "any package manager" does not include none
		}
		m := r.name.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		var base string
		parts := 0
		if r.fromName != nil {
			base = r.fromName(m)
		} else {
			base, parts = upstreamVersion(version), r.maxParts
		}
		if base == "" {
			continue
		}
		cycles := cycleCandidates(base, parts)
		if len(cycles) == 0 {
			continue
		}
		return Match{Product: r.product, Cycles: cycles}, true
	}
	return Match{}, false
}

var leadingVersion = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)

// upstreamVersion strips a dpkg or rpm epoch ("5:7.2.4-1" -> "7.2.4-1") and
// returns the leading dotted number of the upstream version ("7.2.4"); "" when
// the version does not start with one.
func upstreamVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i > 0 && isDigits(v[:i]) {
		v = v[i+1:]
	}
	if m := leadingVersion.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cycleCandidates lists the dotted prefixes of base, longest first, using at
// most maxParts components when it is positive: "8.0.30" gives 8.0.30, 8.0, 8.
func cycleCandidates(base string, maxParts int) []string {
	parts := strings.Split(base, ".")
	if maxParts > 0 && len(parts) > maxParts {
		parts = parts[:maxParts]
	}
	var out []string
	for n := len(parts); n >= 1; n-- {
		out = append(out, strings.Join(parts[:n], "."))
	}
	return out
}
