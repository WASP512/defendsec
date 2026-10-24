package hostinv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"defendsec/internal/repohealth"
)

// Repository health.
//
// The agent reads what it needs to tell whether the host's package indexes are
// being refreshed and verified: the enabled repositories, the Release files apt
// already holds, the signature on each (checked with gpgv, which only reads),
// the dates inside them, and for rpm hosts the key files and the metadata the
// package manager cached. It never refreshes anything. In particular nothing
// here runs apt-get update, dnf makecache or zypper refresh, and nothing writes
// to apt's or dnf's state: the point of the check is that a refresh can fail
// quietly, so the check must not be a refresh.
//
// The judgement (is this old? is this a finding?) is made by the server, in
// internal/repohealth, so the threshold is one setting for the fleet.

// verifyFunc runs gpgv over files with the given keyrings (host paths and
// in-memory keyrings) and returns its --status-fd output and stderr. An error
// means gpgv could not be run at all; a bad signature is not an error.
type verifyFunc func(keyrings []string, mem [][]byte, files []string) (status, stderr string, err error)

// repoEnv is everything the collector reads from the host, so tests can point
// it at a fixture tree and a fake gpgv.
type repoEnv struct {
	root       string // prefix for every path; "" is the real file system
	now        func() time.Time
	verify     verifyFunc
	have       func(name string) bool
	rpm        func(args ...string) (string, bool)
	releasever string
	basearch   string
}

func (e repoEnv) path(p string) string { return filepath.Join(e.root, p) }

func (e repoEnv) read(p string) ([]byte, error) { return os.ReadFile(e.path(p)) }

func (e repoEnv) mtime(p string) (time.Time, bool) {
	st, err := os.Stat(e.path(p))
	if err != nil {
		return time.Time{}, false
	}
	return st.ModTime().UTC(), true
}

func (e repoEnv) glob(pattern string) []string {
	m, _ := filepath.Glob(e.path(pattern))
	sort.Strings(m)
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, strings.TrimPrefix(p, strings.TrimRight(e.root, "/")))
	}
	return out
}

// CollectRepoHealth reads the host's repository evidence. On a platform or
// package manager it does not read it returns an empty report (Manager == "").
func CollectRepoHealth() repohealth.Report {
	if runtime.GOOS != "linux" {
		return repohealth.Report{}
	}
	return collectRepoHealth(realRepoEnv())
}

func realRepoEnv() repoEnv {
	kv := osRelease()
	releasever := kv["VERSION_ID"]
	switch kv["ID"] {
	case "rhel", "centos", "rocky", "almalinux", "ol":
		releasever, _, _ = strings.Cut(releasever, ".")
	}
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	case "386":
		arch = "i686"
	}
	return repoEnv{
		now:    time.Now,
		verify: runGPGV,
		have: func(name string) bool {
			_, err := exec.LookPath(name)
			return err == nil
		},
		rpm: func(args ...string) (string, bool) {
			out, code := runAllowExit("rpm", nil, args...)
			return out, code == 0
		},
		releasever: releasever,
		basearch:   arch,
	}
}

func collectRepoHealth(e repoEnv) repohealth.Report {
	switch {
	case e.have("apt-get"):
		return collectApt(e)
	case e.have("dnf") || e.have("yum"):
		return collectRPM(e, repohealth.ManagerDNF, []string{"/etc/yum.repos.d/*.repo"},
			[]string{"/etc/dnf/dnf.conf", "/etc/yum.conf"},
			[]string{"/var/cache/dnf", "/var/cache/yum", "/var/cache/libdnf5"})
	case e.have("zypper"):
		return collectRPM(e, repohealth.ManagerZypper, []string{"/etc/zypp/repos.d/*.repo"}, nil,
			[]string{"/var/cache/zypp/raw"})
	}
	return repohealth.Report{}
}

// ---- apt ----------------------------------------------------------------------

const (
	aptListsDir = "/var/lib/apt/lists"
	aptStamp    = "/var/lib/apt/periodic/update-success-stamp"
)

func collectApt(e repoEnv) repohealth.Report {
	rep := repohealth.Report{Manager: repohealth.ManagerApt, Repos: []repohealth.Repo{}}

	srcs, limits := e.aptSources()
	rep.Limits = append(rep.Limits, limits...)
	srcs = repohealth.DedupSources(srcs)
	repohealth.SortSources(srcs)

	// When did the host last refresh its indexes? The success stamp is apt's
	// own record of a completed `apt-get update`. Without one (Debian does not
	// ship the hook) the lists/partial directory, which apt writes to on every
	// refresh attempt, is the next best evidence; it also moves on a failed
	// attempt, which is why the success stamp wins when there is one.
	if t, ok := e.mtime(aptStamp); ok {
		rep.LastRefresh, rep.LastRefreshSource = &t, "update-success-stamp"
	} else if t, ok := e.mtime(aptListsDir + "/partial"); ok {
		rep.LastRefresh, rep.LastRefreshSource = &t, "lists directory"
	}

	tk := &trustedKeyrings{e: e}
	gpgvMissing := false
	for _, s := range srcs {
		repo, note := e.checkAptSource(s, tk)
		if note == noGPGV {
			gpgvMissing = true
		}
		rep.Repos = append(rep.Repos, repo)
	}
	if gpgvMissing {
		rep.Limits = append(rep.Limits, "gpgv is not installed or not runnable: repository signatures were not checked")
	}
	return rep
}

const noGPGV = "gpgv unavailable"

// aptSources reads every enabled binary-package source apt would read.
func (e repoEnv) aptSources() (srcs []repohealth.AptSource, limits []string) {
	files := append([]string{"/etc/apt/sources.list"}, e.glob("/etc/apt/sources.list.d/*")...)
	for _, f := range files {
		base := filepath.Base(f)
		isMain := f == "/etc/apt/sources.list"
		deb822 := strings.HasSuffix(base, ".sources")
		if !isMain && !deb822 && !strings.HasSuffix(base, ".list") {
			continue // apt ignores other names (.save, .distUpgrade, ~)
		}
		raw, err := e.read(f)
		if err != nil {
			if !os.IsNotExist(err) {
				limits = append(limits, "cannot read "+f)
			}
			continue
		}
		var got []repohealth.AptSource
		var skipped []string
		if deb822 {
			got, skipped = repohealth.ParseAptSourcesDeb822(f, string(raw))
		} else {
			got, skipped = repohealth.ParseAptSourcesList(f, string(raw))
		}
		srcs = append(srcs, got...)
		for _, s := range skipped {
			limits = append(limits, f+": "+s)
		}
	}
	return srcs, limits
}

// trustedKeyrings is the keyring set apt uses for a source that names none:
// trusted.gpg and trusted.gpg.d. Armored (.asc) files are merged into one
// in-memory keyring. Built once per run.
type trustedKeyrings struct {
	e     repoEnv
	built bool
	paths []string
	mem   [][]byte
}

func (t *trustedKeyrings) get() ([]string, [][]byte) {
	if t.built {
		return t.paths, t.mem
	}
	t.built = true
	if _, ok := t.e.mtime("/etc/apt/trusted.gpg"); ok {
		t.paths = append(t.paths, "/etc/apt/trusted.gpg")
	}
	var armored []byte
	for _, f := range t.e.glob("/etc/apt/trusted.gpg.d/*") {
		switch {
		case strings.HasSuffix(f, ".gpg"):
			t.paths = append(t.paths, f)
		case strings.HasSuffix(f, ".asc"):
			raw, err := t.e.read(f)
			if err != nil {
				continue
			}
			if bin, err := repohealth.Dearmor(raw); err == nil {
				armored = append(armored, bin...)
			}
		}
	}
	if len(armored) > 0 {
		t.mem = append(t.mem, armored)
	}
	return t.paths, t.mem
}

// keyringsFor returns the keyrings a source is verified against, how the report
// says so, and a problem with them if there is one.
func (e repoEnv) keyringsFor(s repohealth.AptSource, tk *trustedKeyrings) (paths []string, mem [][]byte, via, problem string) {
	if len(s.SignedBy) == 0 && len(s.SignedByInline) == 0 {
		p, m := tk.get()
		return p, m, "trusted.gpg and trusted.gpg.d", ""
	}
	var missing []string
	for _, p := range s.SignedBy {
		raw, err := e.read(p)
		if err != nil {
			missing = append(missing, p)
			continue
		}
		if strings.HasSuffix(p, ".asc") || bytes.Contains(raw, []byte("-----BEGIN PGP")) {
			bin, err := repohealth.Dearmor(raw)
			if err != nil {
				missing = append(missing, p)
				continue
			}
			mem = append(mem, bin)
			continue
		}
		paths = append(paths, p)
	}
	for _, in := range s.SignedByInline {
		if bin, err := repohealth.Dearmor([]byte(in)); err == nil {
			mem = append(mem, bin)
		}
	}
	via = "signed-by"
	if len(s.SignedBy) > 0 {
		via = "signed-by " + strings.Join(s.SignedBy, " ")
	} else {
		via = "signed-by (inline key)"
	}
	if len(missing) > 0 {
		problem = "keyring not readable: " + strings.Join(missing, " ")
	}
	return paths, mem, via, problem
}

func (e repoEnv) checkAptSource(s repohealth.AptSource, tk *trustedKeyrings) (repohealth.Repo, string) {
	repo := repohealth.Repo{
		ID: s.ID(), Label: s.Label(), URI: repohealth.RedactURI(s.URI), Suite: s.Suite, Source: s.File,
		IgnoreValidUntil: s.IgnoreValidUntil,
	}
	inNames, relNames, gpgNames := s.ListFileNames()
	var release, inRelease, detached string
	for i := range inNames {
		if p := aptListsDir + "/" + inNames[i]; inRelease == "" && e.exists(p) {
			inRelease = p
		}
		if p := aptListsDir + "/" + relNames[i]; release == "" && e.exists(p) {
			release = p
		}
		if p := aptListsDir + "/" + gpgNames[i]; detached == "" && e.exists(p) {
			detached = p
		}
	}
	where := "the copy apt holds in " + aptListsDir
	// apt keeps no copy of a file: repository: the index is read where it is.
	if inRelease == "" && release == "" && strings.HasPrefix(s.URI, "file:") {
		for _, base := range s.ReleaseBases() {
			dir := strings.TrimRight(filePathOf(base), "/")
			if e.exists(dir + "/InRelease") {
				inRelease = dir + "/InRelease"
			} else if e.exists(dir + "/Release") {
				release, detached = dir+"/Release", dir+"/Release.gpg"
			}
			if inRelease != "" || release != "" {
				where = "the index in place (apt keeps no copy of a file: repository)"
				break
			}
		}
	}
	if inRelease == "" && release == "" {
		repo.Signature = repohealth.SigNoIndex
		repo.Detail = "No Release file under " + aptListsDir + " for this source."
		return repo, ""
	}

	// Dates, from whichever file apt would read.
	read := inRelease
	if read == "" {
		read = release
	}
	if raw, err := e.read(read); err == nil {
		h := repohealth.ParseRelease(string(raw))
		repo.ReleaseDate, repo.ValidUntil = h.Date, h.ValidUntil
	}

	if s.Trusted {
		repo.Signature = repohealth.SigNotChecked
		repo.Detail = "The source is marked trusted=yes: apt does not check its signature."
		return repo, ""
	}
	paths, mem, via, problem := e.keyringsFor(s, tk)
	repo.SignedBy = via
	if problem != "" {
		// A keyring the source names is missing or unreadable: apt cannot
		// verify the repository either, which is the missing-key case.
		repo.Signature = repohealth.SigNoPubkey
		repo.Detail = problem + "."
		return repo, ""
	}
	if len(paths) == 0 && len(mem) == 0 {
		repo.Signature = repohealth.SigNoPubkey
		repo.Detail = "The host has no keyring this source could be verified against (" + via + ")."
		return repo, ""
	}
	var files []string
	switch {
	case inRelease != "":
		files = []string{e.path(inRelease)}
	case detached != "" && e.exists(detached):
		files = []string{e.path(detached), e.path(release)}
	default:
		repo.Signature = repohealth.SigUnsigned
		repo.Detail = "The Release file has no InRelease or Release.gpg beside it."
		return repo, ""
	}
	hostPaths := make([]string, 0, len(paths))
	for _, p := range paths {
		hostPaths = append(hostPaths, e.path(p))
	}
	status, stderr, err := e.verify(hostPaths, mem, files)
	if err != nil {
		repo.Signature = repohealth.SigUnverified
		repo.Detail = "gpgv could not be run: " + err.Error()
		return repo, noGPGV
	}
	if strings.Contains(stderr, "keyblock resource") && !strings.Contains(status, "GOODSIG") {
		repo.Signature = repohealth.SigUnverified
		repo.Detail = "gpgv could not read a keyring: " + firstLine(stderr)
		return repo, ""
	}
	v := repohealth.ParseGPGVStatus(status)
	repo.Signature, repo.KeyID = v.Sig, v.KeyID
	switch v.Sig {
	case repohealth.SigGood:
		repo.Detail = "Signature verified against " + via + " on " + where + "."
	default:
		repo.Detail = "gpgv checked " + where + " against " + via + "."
		if v.UID != "" {
			repo.Detail += " Key: " + v.UID + "."
		}
	}
	return repo, ""
}

// filePathOf is the path part of a file: repository address (file:/x, file:///x).
func filePathOf(uri string) string {
	p := strings.TrimPrefix(uri, "file:")
	if strings.HasPrefix(p, "//") {
		p = p[2:]
	}
	return p
}

func (e repoEnv) exists(p string) bool {
	_, err := os.Stat(e.path(p))
	return err == nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// runGPGV is the real verifyFunc: gpgv with --status-fd 1, one --keyring per
// keyring, in-memory keyrings handed over as inherited descriptors.
func runGPGV(keyrings []string, mem [][]byte, files []string) (string, string, error) {
	bin, err := exec.LookPath("gpgv")
	if err != nil {
		return "", "", err
	}
	args := []string{"--status-fd", "1"}
	for _, k := range keyrings {
		args = append(args, "--keyring", k)
	}
	var extra []*os.File
	defer func() {
		for _, f := range extra {
			f.Close()
		}
	}()
	for _, m := range mem {
		f, err := memKeyring(m)
		if err != nil {
			return "", "", err
		}
		extra = append(extra, f)
		args = append(args, "--keyring", fmt.Sprintf("/dev/fd/%d", 2+len(extra)))
	}
	args = append(args, files...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.ExtraFiles = extra
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return "", "", err // could not start
		}
		// gpgv exits non-zero for a bad or missing signature; that is a verdict.
	}
	return out.String(), errb.String(), nil
}

// ---- rpm (dnf, yum, zypper) -----------------------------------------------------

var cacheDirName = regexp.MustCompile(`^(.+)-[0-9a-f]{8,}$`)

func collectRPM(e repoEnv, manager string, repoGlobs, confFiles, cacheRoots []string) repohealth.Report {
	rep := repohealth.Report{Manager: manager, Repos: []repohealth.Repo{}}
	vars := map[string]string{"releasever": e.releasever, "basearch": e.basearch}

	var mainGPG *bool
	for _, f := range confFiles {
		if raw, err := e.read(f); err == nil {
			if v := repohealth.MainGPGCheck(string(raw)); v != nil {
				mainGPG = v
				break
			}
		}
	}

	var repos []repohealth.RPMRepo
	for _, g := range repoGlobs {
		for _, f := range e.glob(g) {
			raw, err := e.read(f)
			if err != nil {
				rep.Limits = append(rep.Limits, "cannot read "+f)
				continue
			}
			repos = append(repos, repohealth.ParseRepoFile(f, string(raw), vars)...)
		}
	}
	sort.SliceStable(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })

	imported := e.importedKeys()

	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		repo := repohealth.Repo{ID: r.ID, Label: r.ID, URI: repohealth.RedactURI(r.Address), Source: r.File}
		if r.Name != "" {
			repo.Label = r.ID + " (" + r.Name + ")"
		}
		// Cached metadata: dnf and zypper touch repomd.xml when they fetch or
		// revalidate it, so its mtime is the age of what the host knows.
		repo.MetadataTime = e.repomdTime(r.ID, cacheRoots)

		gpgcheck := mainGPG != nil && *mainGPG
		if r.GPGCheck != nil {
			gpgcheck = *r.GPGCheck
		}
		repoGPG := r.RepoGPGCheck != nil && *r.RepoGPGCheck
		switch {
		case !gpgcheck && !repoGPG:
			repo.Signature = repohealth.SigNotChecked
			repo.Detail = "The repository has gpgcheck=0: no signature is checked."
		default:
			e.checkRPMKeys(&repo, r, imported)
		}
		if repo.MetadataTime == nil && repo.Signature != repohealth.SigExpiredKey {
			// Enabled, and the package manager has never cached its metadata.
			if repo.Signature == repohealth.SigGood || repo.Signature == repohealth.SigNotChecked {
				repo.Signature = repohealth.SigNoIndex
				repo.Detail = "No cached repomd.xml found under " + strings.Join(cacheRoots, ", ") + "."
			}
		}
		rep.Repos = append(rep.Repos, repo)
	}
	return rep
}

func (e repoEnv) repomdTime(id string, cacheRoots []string) *time.Time {
	var best *time.Time
	for _, root := range cacheRoots {
		// dnf and yum: <root>/<id>-<hash>/repodata/repomd.xml; zypper: <root>/<alias>/repodata/repomd.xml.
		for _, p := range e.glob(root + "/*/repodata/repomd.xml") {
			dir := filepath.Base(filepath.Dir(filepath.Dir(p)))
			name := dir
			if m := cacheDirName.FindStringSubmatch(dir); m != nil {
				name = m[1]
			}
			if name != id && dir != id {
				continue
			}
			if t, ok := e.mtime(p); ok && (best == nil || t.After(*best)) {
				tt := t
				best = &tt
			}
		}
	}
	return best
}

// importedKeys reads the keys rpm has imported (the gpg-pubkey pseudo
// packages), keyed by short key id, so a repository's key file can be compared
// with the copy rpm actually checks packages against. Best effort: a host
// where rpm cannot be queried simply has none.
func (e repoEnv) importedKeys() map[string]repohealth.KeyInfo {
	out := map[string]repohealth.KeyInfo{}
	if e.rpm == nil {
		return out
	}
	list, ok := e.rpm("-q", "gpg-pubkey", "--qf", "%{VERSION}-%{RELEASE}\\n")
	if !ok {
		return out
	}
	for _, nvr := range strings.Fields(list) {
		desc, ok := e.rpm("-q", "gpg-pubkey-"+nvr, "--qf", "%{DESCRIPTION}")
		if !ok {
			continue
		}
		keys, err := repohealth.ReadKeys([]byte(desc))
		if err != nil {
			continue
		}
		for _, k := range keys {
			out[k.ShortID()] = k
		}
	}
	return out
}

// checkRPMKeys sets the repository's signature state from the keys its gpgkey=
// lines name. Only a key file the agent can read from disk is judged: a
// gpgkey=https://... address is not fetched, and the repository is then
// "not checked" rather than "unverified", because nothing about it is wrong or
// unknown in a way this agent could fix by looking harder.
func (e repoEnv) checkRPMKeys(repo *repohealth.Repo, r repohealth.RPMRepo, imported map[string]repohealth.KeyInfo) {
	now := e.now()
	var remote int
	var keys []repohealth.KeyInfo
	var unreadable []string
	for _, loc := range r.GPGKeys {
		p := repohealth.LocalKeyPath(loc)
		if p == "" {
			remote++
			continue
		}
		raw, err := e.read(p)
		if err != nil {
			unreadable = append(unreadable, p)
			continue
		}
		ks, err := repohealth.ReadKeys(raw)
		if err != nil || len(ks) == 0 {
			unreadable = append(unreadable, p)
			continue
		}
		keys = append(keys, ks...)
	}
	repo.SignedBy = "gpgkey"
	switch {
	case len(keys) > 0:
		// What rpm checks against is the imported copy when there is one.
		allExpired, allRevoked := true, true
		var latest *time.Time
		for _, k := range keys {
			use := k
			if imp, ok := imported[k.ShortID()]; ok {
				use = imp
			}
			if !use.Expired(now) {
				allExpired = false
			}
			if !use.Revoked {
				allRevoked = false
			}
			if use.Expires != nil && (latest == nil || use.Expires.After(*latest)) {
				t := *use.Expires
				latest = &t
			}
			if repo.KeyID == "" {
				repo.KeyID = k.ShortID()
			}
		}
		repo.KeyExpires = latest
		switch {
		case allRevoked:
			repo.Signature = repohealth.SigRevoked
			repo.Detail = "Every key in the repository's gpgkey files is revoked."
		case allExpired:
			repo.Signature = repohealth.SigExpiredKey
			repo.Detail = "Every key in the repository's gpgkey files has expired"
			if latest != nil {
				repo.Detail += " (the last on " + latest.Format("2006-01-02") + ")"
			}
			repo.Detail += "."
		default:
			repo.Signature = repohealth.SigGood
			repo.Detail = "A key in the gpgkey files is current."
		}
	case len(unreadable) > 0:
		repo.Signature = repohealth.SigUnverified
		repo.Detail = "key file not readable: " + strings.Join(unreadable, " ")
	case remote > 0:
		repo.Signature = repohealth.SigNotChecked
		repo.Detail = "gpgkey is a remote address, which the agent does not fetch."
	default:
		repo.Signature = repohealth.SigNotChecked
		repo.Detail = "The repository names no gpgkey."
	}
}

func runtimeGOOS() string { return runtime.GOOS }
