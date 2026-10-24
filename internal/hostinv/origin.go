package hostinv

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"defendsec/internal/lifecycle"
)

// Where a package came from.
//
// Application end-of-life applies only to software from outside the host's own
// distribution (see internal/lifecycle), so the agent reads, for every package,
// the repository that carries the installed version. Reading is all it does,
// with one precaution for apt: `apt-cache policy` (like `apt list --upgradable`
// and `apt-get indextargets`) run as root writes apt's derived package cache,
// /var/cache/apt/pkgcache.bin, when that file is missing or older than the
// indexes. That is a write to the host, and it is avoidable: apt builds the same
// cache in memory when Dir::Cache::pkgcache and Dir::Cache::srcpkgcache are
// empty (see aptReadOnly), which costs about a second and a half per call
// instead of a fraction of one, so the calls are batched. `rpm -qa` changes
// nothing.
//
// dpkg: `apt-cache policy` with no arguments lists every source with the
// Origin: its Release file declares ("release o=Debian,a=stable,..."); with
// package names it lists, per version, the sources that carry it. A version no
// source carries any more (a package installed from a downloaded .deb, a
// repository since removed) has only /var/lib/dpkg/status and gets no origin;
// the server then falls back to signatures in the version string and otherwise
// treats it as unknown rather than guessing.
//
// rpm: the Vendor tag, and the Packager where the vendor is blank.

// aptSource is one apt repository line: the origin its Release file declares
// and the repository's address.
type aptSource struct {
	Label string
	Repo  string
}

var (
	// "  500 http://deb.debian.org/debian trixie/main amd64 Packages"
	aptSourceLine = regexp.MustCompile(`^\s*(-?\d+)\s+(\S+)\s+(\S+)\s+\S+\s+Packages\s*$`)
	// "     release v=13.0,o=Debian,a=testing,n=trixie,l=Debian,c=main,b=amd64"
	aptReleaseLine = regexp.MustCompile(`^\s+release\s+(.+?)\s*$`)
	// "      origin deb.debian.org"
	aptOriginHostLine = regexp.MustCompile(`^\s+origin\s+(\S+)\s*$`)
	// "php8.0-cli:" or "libc6:amd64:"
	aptPackageLine = regexp.MustCompile(`^(\S+):\s*$`)
	// "  Installed: 8.0.30-3+..."
	aptInstalledLine = regexp.MustCompile(`^\s+Installed:\s+(\S+)\s*$`)
	// " *** 8.0.30-3+... 500" (installed) or "     8.0.29-1 500"
	aptVersionRow = regexp.MustCompile(`^ (?:\*\*\*|   ) (\S+)\s+(-?\d+)\s*$`)
	// "        500 http://deb.debian.org/debian trixie/main amd64 Packages" or "        100 /var/lib/dpkg/status"
	aptRowSource = regexp.MustCompile(`^\s{6,}(-?\d+)\s+(\S+)(?:\s+(\S+)\s+\S+\s+Packages)?\s*$`)
)

// ParseAptSources reads `apt-cache policy` (no arguments) and returns the
// sources keyed by "<url> <suite>/<component>", the form the per-package
// listing repeats. The local dpkg database is not a source.
func ParseAptSources(out string) map[string]aptSource {
	sources := map[string]aptSource{}
	var cur string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := aptSourceLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(m[2], "/") {
			cur = m[2] + " " + m[3]
			sources[cur] = aptSource{Repo: redactURL(m[2])}
			continue
		}
		if cur == "" {
			continue
		}
		if m := aptReleaseLine.FindStringSubmatch(line); m != nil {
			s := sources[cur]
			for _, kv := range strings.Split(m[1], ",") {
				if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && k == "o" {
					s.Label = v
				}
			}
			sources[cur] = s
			continue
		}
		if m := aptOriginHostLine.FindStringSubmatch(line); m != nil {
			// Release files without a usable Origin: field still name the host.
			if s := sources[cur]; !usableLabel(s.Label) {
				s.Label = m[1]
				sources[cur] = s
			}
		}
	}
	return sources
}

// usableLabel reports whether an Origin: value names anything. NodeSource's
// says ". nodistro", which does not; its host does.
func usableLabel(l string) bool {
	l = strings.TrimSpace(l)
	return l != "" && (l[0] >= 'A' && l[0] <= 'Z' || l[0] >= 'a' && l[0] <= 'z' || l[0] >= '0' && l[0] <= '9')
}

// aptInstalled is what the per-package listing says about one package: the
// installed version and the keys of the sources that carry that version.
type aptInstalled struct {
	Version string
	Sources []string
}

// ParseAptPolicy reads `apt-cache policy <packages>`.
func ParseAptPolicy(out string) map[string]aptInstalled {
	res := map[string]aptInstalled{}
	var name, installed string
	var inInstalledRow bool
	var cur aptInstalled
	flush := func() {
		if name != "" && installed != "" && installed != "(none)" {
			cur.Version = installed
			if _, dup := res[name]; !dup {
				res[name] = cur
			}
		}
		name, installed, inInstalledRow, cur = "", "", false, aptInstalled{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := aptPackageLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, " ") {
			flush()
			name = m[1]
			if i := strings.Index(name, ":"); i > 0 { // multiarch "libc6:amd64"
				name = name[:i]
			}
			continue
		}
		if m := aptInstalledLine.FindStringSubmatch(line); m != nil {
			installed = m[1]
			continue
		}
		if m := aptVersionRow.FindStringSubmatch(line); m != nil {
			inInstalledRow = installed != "" && m[1] == installed
			continue
		}
		if inInstalledRow {
			if m := aptRowSource.FindStringSubmatch(line); m != nil && m[3] != "" && !strings.HasPrefix(m[2], "/") {
				cur.Sources = append(cur.Sources, m[2]+" "+m[3])
			}
		}
	}
	flush()
	return res
}

// pickOrigin chooses the origin to report for a package whose installed version
// is carried by the given sources. If the distribution itself carries the
// version, that is the answer: a build both the distribution and a third party
// publish is the distribution's to patch. Otherwise the first third-party
// source, in name order so a run is repeatable.
func pickOrigin(distro string, keys []string, sources map[string]aptSource) (label, repo string) {
	type cand struct{ label, repo string }
	var cands []cand
	for _, k := range keys {
		if s, ok := sources[k]; ok && s.Label != "" {
			cands = append(cands, cand{s.Label, s.Repo})
		}
	}
	if len(cands) == 0 {
		return "", ""
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].label != cands[j].label {
			return cands[i].label < cands[j].label
		}
		return cands[i].repo < cands[j].repo
	})
	for _, c := range cands {
		if lifecycle.OwnLabel(distro, c.label) {
			return c.label, c.repo
		}
	}
	return cands[0].label, cands[0].repo
}

// annotateDpkgOrigins fills Origin and OriginRepo on every package whose
// installed version an apt repository still carries.
func annotateDpkgOrigins(items []Software, distro string) {
	if len(items) == 0 {
		return
	}
	sources := ParseAptSources(runApt("apt-cache", "policy"))
	if len(sources) == 0 {
		return // no apt, or no readable indexes: every origin stays unknown
	}
	const batch = 1500
	installed := map[string]aptInstalled{}
	for i := 0; i < len(items); i += batch {
		end := i + batch
		if end > len(items) {
			end = len(items)
		}
		args := []string{"policy"}
		for _, it := range items[i:end] {
			args = append(args, it.Name)
		}
		for k, v := range ParseAptPolicy(runApt("apt-cache", args...)) {
			installed[k] = v
		}
	}
	for i := range items {
		in, ok := installed[items[i].Name]
		if !ok || in.Version != items[i].Version {
			continue // not the version apt thinks is installed: say nothing
		}
		items[i].Origin, items[i].OriginRepo = pickOrigin(distro, in.Sources, sources)
	}
}

// redactURL keeps scheme, host and path: a repository address can carry
// credentials (a userinfo part before the host), and the inventory must
// never.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if i := strings.Index(raw, "@"); i >= 0 {
			return "" // cannot be parsed and may hold credentials: say nothing
		}
		return raw
	}
	return u.Scheme + "://" + u.Host + u.Path
}

var packagerEmail = regexp.MustCompile(`\s*<[^>]*>\s*`)

// rpmOrigin turns the rpm Vendor and Packager tags into an origin. "(none)"
// and blanks are no information. The packager, with its e-mail address
// removed, stands in for a missing vendor and is the repository evidence.
func rpmOrigin(vendor, packager string) (origin, repo string) {
	vendor, packager = clean(vendor), clean(packager)
	packager = strings.TrimSpace(packagerEmail.ReplaceAllString(packager, " "))
	switch {
	case vendor != "":
		return vendor, packager
	case packager != "":
		return packager, ""
	}
	return "", ""
}

func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "(none)" {
		return ""
	}
	return s
}
