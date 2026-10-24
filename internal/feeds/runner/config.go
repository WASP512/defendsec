// Package runner turns configuration into feeds, fetches them into the cache,
// parses them and loads them into Postgres (or, for a dry run, just counts).
package runner

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/feeds/debian"
	"defendsec/internal/feeds/fetch"
	"defendsec/internal/feeds/ubuntu"
	"defendsec/internal/storepg"
)

// Kind selects the parser for a feed.
type Kind string

const (
	KindKEV    Kind = "kev"
	KindEPSS   Kind = "epss"
	KindUbuntu Kind = "ubuntu"
	KindDebian Kind = "debian"
	KindRHEL   Kind = "rhel"
	KindSUSE   Kind = "suse"
	KindOSV    Kind = "osv"
)

// Spec is one feed: where it comes from and what part of the advisory data it
// owns.
type Spec struct {
	Name string
	Kind Kind
	URL  string

	// Distro/Release (os-release ID and VERSION_ID) for the distro feeds;
	// Release is "" for a rolling release.
	Distro  string
	Release string
	// Ecosystem for OSV (as OSV spells it, e.g. "PyPI").
	Ecosystem string
	// Debian: codename -> VERSION_ID for the releases to keep.
	Releases map[string]string
}

// Scopes lists the advisory_ranges sets this feed owns. KEV and EPSS own none:
// they only annotate advisories.
func (s Spec) Scopes() []storepg.RangeScope {
	switch s.Kind {
	case KindUbuntu, KindRHEL, KindSUSE:
		return []storepg.RangeScope{{Distro: s.Distro, Release: s.Release}}
	case KindDebian:
		var out []storepg.RangeScope
		for _, v := range sortedValues(s.Releases) {
			out = append(out, storepg.RangeScope{Distro: "debian", Release: v})
		}
		return out
	case KindOSV:
		return []storepg.RangeScope{{Ecosystem: s.Ecosystem}}
	}
	return nil
}

// HasRanges reports whether the feed produces ranges (as opposed to annotating).
func (s Spec) HasRanges() bool { return s.Kind != KindKEV && s.Kind != KindEPSS }

func sortedValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// DefaultEnabled is the feed set used when DEFENDSEC_FEEDS_ENABLED is unset.
// OSV is never in it: it is opt-in per ecosystem.
var DefaultEnabled = []string{
	"kev", "epss",
	"ubuntu-jammy", "ubuntu-noble",
	"debian",
	"rhel-8", "rhel-9",
	"suse-leap-16.0", "suse-tumbleweed",
}

// Config is the runner's configuration, normally read from the environment
// (/etc/defendsec/feeds.env).
type Config struct {
	CacheDir       string
	DataDir        string // holds pki/control-ed25519.key for export
	Enabled        []string
	OSVEcosystems  []string
	DebianReleases []string // codenames
	URLOverrides   map[string]string
	MaxBytes       int64
	FetchTimeout   time.Duration
	TrustedKeys    []string // PEM file paths accepted for imported bundles
}

// ConfigFromEnv reads the DEFENDSEC_FEEDS_* variables:
//
//	DEFENDSEC_FEEDS_CACHE_DIR        default /var/lib/defendsec/feeds
//	DEFENDSEC_DATA_DIR               default /var/lib/defendsec (control key at pki/)
//	DEFENDSEC_FEEDS_ENABLED          comma list of feed names (default: DefaultEnabled)
//	DEFENDSEC_FEEDS_OSV_ECOSYSTEMS   comma list, e.g. PyPI,npm (default none)
//	DEFENDSEC_FEEDS_DEBIAN_RELEASES  comma list of codenames (default bookworm,trixie)
//	DEFENDSEC_FEEDS_URL_<NAME>       override one feed's URL (mirror), NAME upper-cased, non-alphanumerics as _
//	DEFENDSEC_FEEDS_MAX_BYTES        per-file download limit (default 4 GiB)
//	DEFENDSEC_FEEDS_TIMEOUT          per-feed fetch timeout, a Go duration (default 30m)
//	DEFENDSEC_FEEDS_TRUSTED_KEYS     comma list of PEM public key files for `import`
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		CacheDir:       or(getenv("DEFENDSEC_FEEDS_CACHE_DIR"), "/var/lib/defendsec/feeds"),
		DataDir:        or(getenv("DEFENDSEC_DATA_DIR"), "/var/lib/defendsec"),
		Enabled:        splitList(getenv("DEFENDSEC_FEEDS_ENABLED")),
		OSVEcosystems:  splitList(getenv("DEFENDSEC_FEEDS_OSV_ECOSYSTEMS")),
		DebianReleases: splitList(or(getenv("DEFENDSEC_FEEDS_DEBIAN_RELEASES"), "bookworm,trixie")),
		TrustedKeys:    splitList(getenv("DEFENDSEC_FEEDS_TRUSTED_KEYS")),
		FetchTimeout:   30 * time.Minute,
		URLOverrides:   map[string]string{},
	}
	if len(c.Enabled) == 0 {
		c.Enabled = append([]string(nil), DefaultEnabled...)
	}
	if v := getenv("DEFENDSEC_FEEDS_MAX_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return c, fmt.Errorf("DEFENDSEC_FEEDS_MAX_BYTES %q: want a positive integer", v)
		}
		c.MaxBytes = n
	}
	if v := getenv("DEFENDSEC_FEEDS_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("DEFENDSEC_FEEDS_TIMEOUT %q: want a positive Go duration such as 45m", v)
		}
		c.FetchTimeout = d
	}
	for _, name := range allNames(c) {
		if v := getenv(urlEnvName(name)); v != "" {
			if err := fetch.CheckURL(v); err != nil {
				return c, fmt.Errorf("%s: %w", urlEnvName(name), err)
			}
			c.URLOverrides[name] = v
		}
	}
	return c, nil
}

func or(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

func urlEnvName(feed string) string {
	return "DEFENDSEC_FEEDS_URL_" + strings.ToUpper(nonAlnum.ReplaceAllString(feed, "_"))
}

// allNames is every feed name the configuration can refer to.
func allNames(c Config) []string {
	var names []string
	for _, s := range Catalog(c) {
		names = append(names, s.Name)
	}
	return names
}

var osvEcoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Catalog lists every feed this build knows how to fetch and parse, with URLs
// resolved (mirror overrides applied). Whether a feed runs is a separate
// question: see Select.
func Catalog(c Config) []Spec {
	var specs []Spec
	add := func(s Spec) {
		if u, ok := c.URLOverrides[s.Name]; ok {
			s.URL = u
		}
		specs = append(specs, s)
	}
	add(Spec{Name: "kev", Kind: KindKEV, URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"})
	add(Spec{Name: "epss", Kind: KindEPSS, URL: "https://epss.cyentia.com/epss_scores-current.csv.gz"})

	codenames := make([]string, 0, len(ubuntu.Releases))
	for cn := range ubuntu.Releases {
		codenames = append(codenames, cn)
	}
	sort.Strings(codenames)
	for _, cn := range codenames {
		add(Spec{Name: "ubuntu-" + cn, Kind: KindUbuntu, Distro: "ubuntu", Release: ubuntu.Releases[cn],
			URL: "https://security-metadata.canonical.com/oval/com.ubuntu." + cn + ".usn.oval.xml.bz2"})
	}

	rel := map[string]string{}
	for _, cn := range c.DebianReleases {
		if v, ok := debian.Releases[cn]; ok {
			rel[cn] = v
		}
	}
	add(Spec{Name: "debian", Kind: KindDebian, Distro: "debian", Releases: rel,
		URL: "https://security-tracker.debian.org/tracker/data/json"})

	for _, n := range []string{"8", "9"} { // RHEL 10 has no v2 OVAL feed yet (404)
		add(Spec{Name: "rhel-" + n, Kind: KindRHEL, Distro: "rhel", Release: n,
			URL: "https://security.access.redhat.com/data/oval/v2/RHEL" + n + "/rhel-" + n + ".oval.xml.bz2"})
	}

	const suse = "https://ftp.suse.com/pub/projects/security/oval/"
	add(Spec{Name: "suse-leap-15.6", Kind: KindSUSE, Distro: "opensuse-leap", Release: "15.6", URL: suse + "opensuse.leap.15.6-affected.xml.bz2"})
	add(Spec{Name: "suse-leap-16.0", Kind: KindSUSE, Distro: "opensuse-leap", Release: "16.0", URL: suse + "opensuse.leap.16.0-affected.xml.bz2"})
	add(Spec{Name: "suse-tumbleweed", Kind: KindSUSE, Distro: "opensuse-tumbleweed", URL: suse + "opensuse.tumbleweed-affected.xml.bz2"})

	for _, eco := range c.OSVEcosystems {
		if !osvEcoRe.MatchString(eco) {
			continue // reported by Select
		}
		add(Spec{Name: "osv-" + strings.ToLower(eco), Kind: KindOSV, Ecosystem: eco,
			URL: "https://osv-vulnerabilities.storage.googleapis.com/" + eco + "/all.zip"})
	}
	return specs
}

// Select returns the enabled feeds in run order: range feeds first, then KEV,
// then EPSS, so enrichment lands on advisories the same run just created. An
// unknown name, an invalid OSV ecosystem, or a Debian feed with no known release
// is an error rather than a silently skipped feed.
func Select(c Config) ([]Spec, error) {
	for _, eco := range c.OSVEcosystems {
		if !osvEcoRe.MatchString(eco) {
			return nil, fmt.Errorf("DEFENDSEC_FEEDS_OSV_ECOSYSTEMS: %q is not a valid ecosystem name", eco)
		}
	}
	for _, cn := range c.DebianReleases {
		if _, ok := debian.Releases[cn]; !ok {
			return nil, fmt.Errorf("DEFENDSEC_FEEDS_DEBIAN_RELEASES: unknown release %q (known: %s)", cn, strings.Join(knownDebian(), ", "))
		}
	}
	byName := map[string]Spec{}
	for _, s := range Catalog(c) {
		byName[s.Name] = s
	}
	var ranges, kevs, epss []Spec
	seen := map[string]bool{}
	for _, name := range c.Enabled {
		if seen[name] {
			continue
		}
		seen[name] = true
		s, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("DEFENDSEC_FEEDS_ENABLED: unknown feed %q (see `defendsec-feeds list`)", name)
		}
		if s.Kind == KindDebian && len(s.Releases) == 0 {
			return nil, fmt.Errorf("feed debian is enabled but no Debian release is configured")
		}
		if !fetch.ValidName(s.Name) {
			return nil, fmt.Errorf("feed name %q is not a valid cache name", s.Name)
		}
		switch s.Kind {
		case KindKEV:
			kevs = append(kevs, s)
		case KindEPSS:
			epss = append(epss, s)
		default:
			ranges = append(ranges, s)
		}
	}
	out := append(append(ranges, kevs...), epss...)
	if len(out) == 0 {
		return nil, fmt.Errorf("no feeds enabled")
	}
	return out, nil
}

func knownDebian() []string {
	var out []string
	for k := range debian.Releases {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Only narrows specs to the named feeds, erroring on a name that is not among
// them.
func Only(specs []Spec, names []string) ([]Spec, error) {
	if len(names) == 0 {
		return specs, nil
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []Spec
	for _, s := range specs {
		if want[s.Name] {
			out = append(out, s)
			delete(want, s.Name)
		}
	}
	for n := range want {
		return nil, fmt.Errorf("--only: %q is not an enabled feed", n)
	}
	return out, nil
}

// LoadEnvFile reads KEY=VALUE lines (as in /etc/defendsec/feeds.env) and calls
// set for each variable that is not already present in the environment, so a
// real environment variable always wins. Blank lines and # comments are
// ignored; values may be wrapped in matching single or double quotes. It
// returns os.ErrNotExist (wrapped) if the file is absent.
func LoadEnvFile(path string, lookup func(string) (string, bool), set func(k, v string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return fmt.Errorf("%s:%d: want KEY=VALUE", path, n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, exists := lookup(k); exists {
			continue
		}
		if err := set(k, v); err != nil {
			return err
		}
	}
	return sc.Err()
}
