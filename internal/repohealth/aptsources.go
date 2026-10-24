package repohealth

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

// AptSource is one enabled apt repository: one (URI, suite) pair of one source
// entry. A source line naming three components is one AptSource: the Release
// file is per suite.
type AptSource struct {
	URI   string
	Suite string
	// File is the configuration file that defines it.
	File string
	// SignedBy are the keyring files named by signed-by (paths only);
	// SignedByInline are armored keys given inline in a .sources file;
	// Fingerprints are fingerprint-form signed-by values (the host's trusted
	// keyrings, narrowed by fingerprint). All empty means the legacy default:
	// trusted.gpg and trusted.gpg.d.
	SignedBy       []string
	SignedByInline []string
	Fingerprints   []string
	// Trusted is [trusted=yes]: apt skips signature checks for it.
	Trusted bool
	// IgnoreValidUntil is Check-Valid-Until: no.
	IgnoreValidUntil bool
}

// ID is the repository's stable key, with credentials removed.
func (s AptSource) ID() string { return RedactURI(s.URI) + " " + s.Suite }

// Label is the repository as an administrator would name it.
func (s AptSource) Label() string { return s.ID() }

// RedactURI keeps scheme, host and path of a repository address. A repository
// address can carry credentials (a userinfo part before the host), and the
// inventory must never.
func RedactURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		if strings.Contains(raw, "@") {
			return ""
		}
		return strings.TrimRight(raw, "/")
	}
	if u.Host == "" {
		return u.Scheme + ":" + strings.TrimRight(u.Opaque+u.Path, "/")
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
}

// ParseAptSourcesList reads a one-line-style file (sources.list, *.list). Lines
// that are not binary-package sources, comments and sources it cannot read are
// skipped; the second result lists lines it had to skip for want of
// understanding (mirror methods, cdrom), so the caller can say what it did not
// check.
func ParseAptSourcesList(file, text string) (srcs []AptSource, skipped []string) {
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "deb" {
			continue
		}
		rest := fields[1:]
		var opts map[string][]string
		if strings.HasPrefix(rest[0], "[") {
			// Options run to the closing bracket and may contain spaces.
			joined := strings.Join(rest, " ")
			end := strings.Index(joined, "]")
			if end < 0 {
				continue
			}
			opts = parseAptOptions(joined[1:end])
			rest = strings.Fields(joined[end+1:])
		}
		if len(rest) < 2 {
			continue
		}
		s := AptSource{URI: rest[0], Suite: rest[1], File: file}
		applyAptOptions(&s, opts)
		if skip := unsupportedURI(s.URI); skip != "" {
			skipped = append(skipped, skip)
			continue
		}
		srcs = append(srcs, s)
	}
	return srcs, skipped
}

func parseAptOptions(s string) map[string][]string {
	out := map[string][]string{}
	for _, kv := range strings.Fields(s) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(k)] = append(out[strings.ToLower(k)], v)
	}
	return out
}

func applyAptOptions(s *AptSource, opts map[string][]string) {
	for k, vs := range opts {
		v := strings.Join(vs, ",")
		switch k {
		case "signed-by":
			s.addSignedBy(v)
		case "trusted", "allow-insecure", "allow-weak":
			if k == "trusted" && yes(v) || k == "allow-insecure" && yes(v) {
				s.Trusted = true
			}
		case "check-valid-until":
			if !yes(v) {
				s.IgnoreValidUntil = true
			}
		}
	}
}

func yes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on", "with", "enable":
		return true
	}
	return false
}

// addSignedBy takes a signed-by value: comma- or whitespace-separated paths or
// fingerprints, or one inline armored key block.
func (s *AptSource) addSignedBy(v string) {
	if strings.Contains(v, "BEGIN PGP PUBLIC KEY BLOCK") {
		s.SignedByInline = append(s.SignedByInline, v)
		return
	}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		switch {
		case strings.HasPrefix(f, "/"):
			s.SignedBy = append(s.SignedBy, f)
		case isHex(f) && len(f) >= 16:
			s.Fingerprints = append(s.Fingerprints, strings.ToUpper(f))
		}
	}
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func unsupportedURI(uri string) string {
	switch {
	case strings.HasPrefix(uri, "cdrom:"):
		return "cdrom source not checked"
	case strings.HasPrefix(uri, "mirror:"), strings.HasPrefix(uri, "mirror+"):
		return "mirror-method source not checked (its index is named after the mirror list)"
	}
	return ""
}

// ParseAptSourcesDeb822 reads a deb822-style file (*.sources). A stanza with
// Enabled: no is skipped; one that does not list Types: deb is skipped (it is
// deb-src only).
func ParseAptSourcesDeb822(file, text string) (srcs []AptSource, skipped []string) {
	for _, st := range deb822Stanzas(text) {
		if v, ok := st["enabled"]; ok && !yes(v) {
			continue
		}
		hasDeb := false
		for _, t := range strings.Fields(st["types"]) {
			if t == "deb" {
				hasDeb = true
			}
		}
		if !hasDeb {
			continue
		}
		base := AptSource{File: file}
		if v, ok := st["trusted"]; ok && yes(v) {
			base.Trusted = true
		}
		if v, ok := st["allow-insecure"]; ok && yes(v) {
			base.Trusted = true
		}
		if v, ok := st["check-valid-until"]; ok && !yes(v) {
			base.IgnoreValidUntil = true
		}
		if v, ok := st["signed-by"]; ok {
			base.addSignedBy(v)
		}
		for _, uri := range strings.Fields(st["uris"]) {
			if skip := unsupportedURI(uri); skip != "" {
				skipped = append(skipped, skip)
				continue
			}
			for _, suite := range strings.Fields(st["suites"]) {
				s := base
				s.URI, s.Suite = uri, suite
				srcs = append(srcs, s)
			}
		}
	}
	return srcs, skipped
}

// deb822Stanzas splits a deb822 file into stanzas of lowercased field name to
// value. Continuation lines (leading space or tab) join the value with a
// newline, and a lone "." line stands for a blank line, as inside an inline key
// block.
func deb822Stanzas(text string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	last := ""
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
		}
		cur, last = map[string]string{}, ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case strings.HasPrefix(line, "#"):
		case line[0] == ' ' || line[0] == '\t':
			if last == "" {
				continue
			}
			cont := strings.TrimSpace(line)
			if cont == "." {
				cont = ""
			}
			cur[last] += "\n" + cont
		default:
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			last = strings.ToLower(strings.TrimSpace(k))
			cur[last] = strings.TrimSpace(v)
		}
	}
	flush()
	return out
}

// quoteSet are the bytes apt escapes (as %xx, lower-case hex) when it turns a
// repository address into a file name under /var/lib/apt/lists. Taken from
// apt-pkg/contrib/strutl.cc URItoFileName, and checked against the file names
// of real hosts (see the test data).
const quoteSet = "\\|{}[]<>\"^~_=!@#$%&*"

// URIToFileName is how apt names, under /var/lib/apt/lists, the file it keeps
// for the address uri: scheme and credentials removed, characters in quoteSet
// and everything outside printable ASCII escaped, "/" replaced by "_".
func URIToFileName(uri string) string {
	u, err := url.Parse(uri)
	var s string
	if err == nil && u.Scheme != "" {
		switch {
		case u.Host != "":
			s = u.Host + u.Path
			if u.RawQuery != "" {
				s += "?" + u.RawQuery
			}
		default:
			s = u.Opaque + u.Path
		}
	} else {
		s = uri
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/':
			b.WriteByte('_')
		case c <= 0x20 || c >= 0x7f || strings.IndexByte(quoteSet, c) >= 0:
			fmt.Fprintf(&b, "%%%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ReleaseBases returns the addresses, without the file name, where a source's
// Release files live: <uri>/dists/<suite>/ normally, <uri>/<suite> for a flat
// repository (a suite ending in "/", usually "./"). apt names the lists file
// after the address it fetched, and for the usual "./" suite that address is
// <uri>/./, so the file is <host>_._InRelease (measured on Ubuntu 22.04 with an
// http flat repository), not <host>_InRelease.
func (s AptSource) ReleaseBases() []string {
	uri := strings.TrimRight(s.URI, "/")
	if strings.HasSuffix(s.Suite, "/") {
		suite := path.Clean(s.Suite)
		if suite == "." {
			return []string{uri + "/./"}
		}
		return []string{uri + "/" + suite + "/", uri + "/./" + suite + "/"}
	}
	return []string{uri + "/dists/" + s.Suite + "/"}
}

// ListFileNames returns the candidate names, under /var/lib/apt/lists, of the
// source's InRelease, Release and Release.gpg, in that order of preference.
func (s AptSource) ListFileNames() (inRelease, release, releaseGPG []string) {
	for _, base := range s.ReleaseBases() {
		n := URIToFileName(base)
		if strings.HasSuffix(base, "/") && !strings.HasSuffix(n, "_") {
			n += "_"
		}
		inRelease = append(inRelease, n+"InRelease")
		release = append(release, n+"Release")
		releaseGPG = append(releaseGPG, n+"Release.gpg")
	}
	return
}

// SortSources orders sources by id so a run is repeatable.
func SortSources(srcs []AptSource) {
	sort.SliceStable(srcs, func(i, j int) bool { return srcs[i].ID() < srcs[j].ID() })
}

// DedupSources drops repeated (URI, suite) pairs, keeping the first.
func DedupSources(srcs []AptSource) []AptSource {
	seen := map[string]bool{}
	out := srcs[:0:0]
	for _, s := range srcs {
		k := s.URI + "\x00" + s.Suite
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}
