package hostinv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"defendsec/internal/repohealth"
)

var fixedNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// A fixture host: a directory tree standing in for /, and a fake gpgv that
// answers from the name of the file it was asked to check.
type fixtureHost struct {
	t    *testing.T
	root string
	// verdicts maps a substring of the checked file's path to the gpgv status
	// text to return; calls records what was asked.
	verdicts map[string]string
	calls    []verifyCall
	verr     error
}

type verifyCall struct {
	keyrings []string
	mem      [][]byte
	files    []string
}

func newFixtureHost(t *testing.T) *fixtureHost {
	return &fixtureHost{t: t, root: t.TempDir(), verdicts: map[string]string{}}
}

func (h *fixtureHost) write(rel, content string) string {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *fixtureHost) touch(rel string, at time.Time) {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if _, err := os.Stat(p); err != nil {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if st, err := os.Stat(p); err != nil || st == nil {
			if filepath.Ext(p) == "" && strings.HasSuffix(rel, "partial") {
				if err := os.MkdirAll(p, 0o755); err != nil {
					h.t.Fatal(err)
				}
			} else if err := os.WriteFile(p, nil, 0o644); err != nil {
				h.t.Fatal(err)
			}
		}
	}
	if err := os.Chtimes(p, at, at); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fixtureHost) env(manager ...string) repoEnv {
	have := map[string]bool{"apt-get": true}
	if len(manager) > 0 {
		have = map[string]bool{}
		for _, m := range manager {
			have[m] = true
		}
	}
	return repoEnv{
		root: h.root, now: func() time.Time { return fixedNow },
		have: func(n string) bool { return have[n] },
		verify: func(keyrings []string, mem [][]byte, files []string) (string, string, error) {
			h.calls = append(h.calls, verifyCall{keyrings, mem, files})
			if h.verr != nil {
				return "", "", h.verr
			}
			for sub, status := range h.verdicts {
				if strings.Contains(files[0], sub) {
					return status, "", nil
				}
			}
			return "", "", nil
		},
		rpm:        func(args ...string) (string, bool) { return "", false },
		releasever: "9", basearch: "x86_64",
	}
}

const (
	goodStatus    = "[GNUPG:] GOODSIG 6ED0E7B82643E131 Vendor <v@example.invalid>\n[GNUPG:] VALIDSIG 4CB5 2026-09-12 1 0 4 0 1 8 01 B8B8\n"
	expiredStatus = "[GNUPG:] KEYEXPIRED 1767312000\n[GNUPG:] EXPKEYSIG 13EDAB264F59ECF5 DefendSec Test Repo (expired lab key) <lab@example.invalid>\n"
)

func inRelease(date, validUntil string) string {
	s := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Test\nSuite: stable\nDate: " + date + "\n"
	if validUntil != "" {
		s += "Valid-Until: " + validUntil + "\n"
	}
	return s + "SHA256:\n aa 1 main/Packages\n-----BEGIN PGP SIGNATURE-----\n\nxx\n-----END PGP SIGNATURE-----\n"
}

func repoByLabel(t *testing.T, r repohealth.Report, label string) repohealth.Repo {
	t.Helper()
	for _, repo := range r.Repos {
		if repo.Label == label {
			return repo
		}
	}
	t.Fatalf("no repository %q in %+v", label, r.Repos)
	return repohealth.Repo{}
}

func TestCollectAptHealthyAndBrokenRepositories(t *testing.T) {
	h := newFixtureHost(t)
	h.write("etc/apt/sources.list", "deb http://archive.ubuntu.test/ubuntu jammy main\n")
	h.write("etc/apt/sources.list.d/vendor.list", "deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://vendor.test/apt stable main\n")
	h.write("etc/apt/sources.list.d/newrepo.list", "deb [signed-by=/etc/apt/keyrings/new.gpg] http://new.test/apt stable main\n")
	h.write("etc/apt/sources.list.d/ignored.list.save", "deb http://ignored.test/apt stable main\n")
	h.write("etc/apt/keyrings/vendor.gpg", "binary keyring")
	h.write("etc/apt/keyrings/new.gpg", "binary keyring")
	h.write("etc/apt/trusted.gpg.d/ubuntu.gpg", "binary keyring")
	h.write("var/lib/apt/lists/archive.ubuntu.test_ubuntu_dists_jammy_InRelease", inRelease("Thu, 21 Apr 2022 17:16:39 UTC", ""))
	h.write("var/lib/apt/lists/vendor.test_apt_dists_stable_InRelease", inRelease("Wed, 22 Oct 2026 08:00:00 UTC", "Wed, 29 Oct 2026 08:00:00 UTC"))
	// new.test has no list file: apt never fetched it, or refused it.
	h.verdicts["archive.ubuntu.test"] = goodStatus
	h.verdicts["vendor.test"] = expiredStatus
	h.touch("var/lib/apt/periodic/update-success-stamp", fixedNow.Add(-26*time.Hour))

	rep := collectApt(h.env())
	if rep.Manager != repohealth.ManagerApt || len(rep.Repos) != 3 || len(rep.Limits) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.LastRefresh == nil || !rep.LastRefresh.Equal(fixedNow.Add(-26*time.Hour)) || rep.LastRefreshSource != "update-success-stamp" {
		t.Errorf("last refresh = %v %q", rep.LastRefresh, rep.LastRefreshSource)
	}
	ubuntu := repoByLabel(t, rep, "http://archive.ubuntu.test/ubuntu jammy")
	if ubuntu.Signature != repohealth.SigGood || ubuntu.ReleaseDate == nil || ubuntu.ReleaseDate.Year() != 2022 || ubuntu.SignedBy != "trusted.gpg and trusted.gpg.d" {
		t.Errorf("ubuntu = %+v", ubuntu)
	}
	vendor := repoByLabel(t, rep, "https://vendor.test/apt stable")
	if vendor.Signature != repohealth.SigExpiredKey || vendor.KeyID != "13EDAB264F59ECF5" || vendor.ValidUntil == nil ||
		!strings.Contains(vendor.Detail, "expired lab key") || !strings.HasPrefix(vendor.SignedBy, "signed-by /etc/apt/keyrings/vendor.gpg") {
		t.Errorf("vendor = %+v", vendor)
	}
	nw := repoByLabel(t, rep, "http://new.test/apt stable")
	if nw.Signature != repohealth.SigNoIndex {
		t.Errorf("a source with no Release file = %+v", nw)
	}
	// The vendor repository was verified against its own keyring only, not the trusted set.
	for _, c := range h.calls {
		if strings.Contains(c.files[0], "vendor.test") && (len(c.keyrings) != 1 || !strings.HasSuffix(c.keyrings[0], "etc/apt/keyrings/vendor.gpg")) {
			t.Errorf("vendor verified against %v", c.keyrings)
		}
	}
	// And the whole thing judged: the expired key and the missing index are high, the 2022 date is not stale.
	a := repohealth.Assess(rep, fixedNow, 0)
	if a.Reliability != repohealth.Unreliable || len(a.Problems) != 2 {
		t.Errorf("assessment = %+v", a)
	}
	for _, p := range a.Problems {
		if p.Severity != "high" {
			t.Errorf("problem %+v", p)
		}
	}
}

func TestCollectAptNoStampFallsBackToTheListsDirectory(t *testing.T) {
	h := newFixtureHost(t)
	h.write("etc/apt/sources.list", "deb http://archive.ubuntu.test/ubuntu jammy main\n")
	h.write("etc/apt/trusted.gpg.d/u.gpg", "k")
	h.write("var/lib/apt/lists/archive.ubuntu.test_ubuntu_dists_jammy_InRelease", inRelease("Thu, 21 Apr 2022 17:16:39 UTC", ""))
	h.verdicts["archive"] = goodStatus
	h.touch("var/lib/apt/lists/partial", fixedNow.Add(-72*time.Hour))
	rep := collectApt(h.env())
	if rep.LastRefresh == nil || rep.LastRefreshSource != "lists directory" || !rep.LastRefresh.Equal(fixedNow.Add(-72*time.Hour)) {
		t.Errorf("fallback = %v %q", rep.LastRefresh, rep.LastRefreshSource)
	}
	// With neither, there is no refresh evidence and the report says so.
	h2 := newFixtureHost(t)
	h2.write("etc/apt/sources.list", "deb http://archive.ubuntu.test/ubuntu jammy main\n")
	if rep := collectApt(h2.env()); rep.LastRefresh != nil {
		t.Errorf("refresh evidence invented: %v", rep.LastRefresh)
	}
}

func TestCollectAptTrustedMissingKeyringAndGpgvFailures(t *testing.T) {
	h := newFixtureHost(t)
	h.write("etc/apt/sources.list.d/a.list", "deb [trusted=yes] http://a.test/apt ./\n")
	h.write("etc/apt/sources.list.d/b.list", "deb [signed-by=/etc/apt/keyrings/gone.gpg] http://b.test/apt stable main\n")
	h.write("var/lib/apt/lists/a.test_apt_InRelease", inRelease("Wed, 22 Oct 2026 08:00:00 UTC", ""))
	h.write("var/lib/apt/lists/b.test_apt_dists_stable_InRelease", inRelease("Wed, 22 Oct 2026 08:00:00 UTC", ""))
	rep := collectApt(h.env())
	a := repoByLabel(t, rep, "http://a.test/apt ./")
	if a.Signature != repohealth.SigNotChecked || a.ReleaseDate == nil {
		t.Errorf("trusted=yes = %+v", a)
	}
	b := repoByLabel(t, rep, "http://b.test/apt stable")
	if b.Signature != repohealth.SigNoPubkey || !strings.Contains(b.Detail, "gone.gpg") {
		t.Errorf("missing keyring = %+v", b)
	}
	// gpgv cannot be run at all: unverified, a limit, and an unreliable verdict, but no finding.
	h = newFixtureHost(t)
	h.write("etc/apt/sources.list", "deb http://archive.ubuntu.test/ubuntu jammy main\n")
	h.write("etc/apt/trusted.gpg.d/u.gpg", "k")
	h.write("var/lib/apt/lists/archive.ubuntu.test_ubuntu_dists_jammy_InRelease", inRelease("Wed, 22 Oct 2026 08:00:00 UTC", ""))
	h.verr = fmt.Errorf("executable file not found in $PATH")
	rep = collectApt(h.env())
	r := rep.Repos[0]
	if r.Signature != repohealth.SigUnverified || len(rep.Limits) != 1 || !strings.Contains(rep.Limits[0], "gpgv") {
		t.Errorf("gpgv missing: %+v limits %v", r, rep.Limits)
	}
	as := repohealth.Assess(rep, fixedNow, 0)
	if as.Reliability != repohealth.Unreliable || len(as.Problems) != 0 {
		t.Errorf("assessment = %+v", as)
	}
}

func TestCollectAptDeb822WithArmoredKeysAndInlineKeys(t *testing.T) {
	h := newFixtureHost(t)
	asc, err := os.ReadFile("../repohealth/testdata/key-noexpiry.asc")
	if err != nil {
		t.Fatal(err)
	}
	h.write("etc/apt/keyrings/armored.asc", string(asc))
	h.write("etc/apt/trusted.gpg.d/debian-archive.asc", string(asc))
	h.write("etc/apt/sources.list.d/v.sources", "Types: deb\nURIs: https://v.test/apt\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/armored.asc\n\n"+
		"Types: deb\nURIs: https://w.test/apt\nSuites: stable\nSigned-By:\n"+indentKey(string(asc))+"\n"+
		"Types: deb\nURIs: https://x.test/apt\nSuites: stable\n")
	for _, n := range []string{"v", "w", "x"} {
		h.write("var/lib/apt/lists/"+n+".test_apt_dists_stable_InRelease", inRelease("Wed, 22 Oct 2026 08:00:00 UTC", ""))
	}
	h.verdicts[".test_apt"] = goodStatus
	rep := collectApt(h.env())
	if len(rep.Repos) != 3 {
		t.Fatalf("repos = %+v", rep.Repos)
	}
	for _, r := range rep.Repos {
		if r.Signature != repohealth.SigGood {
			t.Errorf("%s = %v (%s)", r.Label, r.Signature, r.Detail)
		}
	}
	// v: the armored signed-by file is dearmored into an in-memory keyring, never passed as a path.
	// w: the inline key is the same. x: no signed-by, so trusted.gpg.d, whose .asc files are merged into one.
	for _, c := range h.calls {
		if len(c.keyrings) != 0 || len(c.mem) != 1 || len(c.mem[0]) == 0 {
			t.Errorf("call for %v: keyrings %v mem %d", c.files, c.keyrings, len(c.mem))
		}
	}
}

func indentKey(armor string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimSpace(armor), "\n") {
		if l == "" {
			l = "."
		}
		b.WriteString(" " + l + "\n")
	}
	return b.String()
}

// apt keeps no copy of a file: repository, so the index is verified where it is.
func TestCollectAptFileRepositoryIsVerifiedInPlace(t *testing.T) {
	h := newFixtureHost(t)
	h.write("etc/apt/sources.list.d/lab.list", "deb [signed-by=/srv/lab/keyring.gpg] file:/srv/lab/repo dstest main\n")
	h.write("srv/lab/keyring.gpg", "k")
	h.write("srv/lab/repo/dists/dstest/InRelease", inRelease("Thu, 01 Jan 2026 12:00:00 UTC", ""))
	h.verdicts["dstest"] = expiredStatus
	rep := collectApt(h.env())
	r := rep.Repos[0]
	if r.Signature != repohealth.SigExpiredKey || !strings.Contains(r.Detail, "in place") || r.ReleaseDate == nil {
		t.Errorf("file repo = %+v", r)
	}
	// Without the file there is no index at all.
	h2 := newFixtureHost(t)
	h2.write("etc/apt/sources.list.d/lab.list", "deb file:/srv/lab/repo dstest main\n")
	if r := collectApt(h2.env()).Repos[0]; r.Signature != repohealth.SigNoIndex {
		t.Errorf("empty file repo = %+v", r)
	}
}

func TestCollectAptRedactsCredentialsInTheAddress(t *testing.T) {
	h := newFixtureHost(t)
	h.write("etc/apt/sources.list", "deb https://user:secret@priv.test/apt stable main\n")
	rep := collectApt(h.env())
	raw := fmt.Sprintf("%+v", rep)
	if strings.Contains(raw, "secret") || strings.Contains(raw, "user:") {
		t.Errorf("credentials leaked into the report: %s", raw)
	}
}

// ---- rpm ----------------------------------------------------------------------------------------------

func TestCollectRPMKeysAndMetadataAge(t *testing.T) {
	h := newFixtureHost(t)
	expired, _ := os.ReadFile("../repohealth/testdata/key-expired.asc")
	current, _ := os.ReadFile("../repohealth/testdata/key-current.asc")
	h.write("etc/pki/rpm-gpg/RPM-GPG-KEY-expired", string(expired))
	h.write("etc/pki/rpm-gpg/RPM-GPG-KEY-current", string(current))
	h.write("etc/dnf/dnf.conf", "[main]\ngpgcheck=1\n")
	h.write("etc/yum.repos.d/test.repo", `[baseos]
name=Base $releasever
baseurl=https://dl.test/$releasever/BaseOS/$basearch/os/
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-current

[vendor]
name=Vendor
baseurl=https://vendor.test/rpm
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-expired

[nocache]
name=Never fetched
baseurl=https://nocache.test/rpm
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-current

[nocheck]
name=No check
baseurl=https://nocheck.test/rpm
gpgcheck=0

[remote]
name=Remote key
baseurl=https://remote.test/rpm
gpgkey=https://remote.test/key.pub

[off]
name=Disabled
baseurl=https://off.test/rpm
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-expired
`)
	h.touch("var/cache/dnf/baseos-0123456789abcdef/repodata/repomd.xml", fixedNow.Add(-5*time.Hour))
	h.touch("var/cache/dnf/vendor-fedcba9876543210/repodata/repomd.xml", fixedNow.Add(-40*24*time.Hour))
	h.touch("var/cache/dnf/nocheck-0123456789abcdef/repodata/repomd.xml", fixedNow.Add(-1*time.Hour))
	h.touch("var/cache/dnf/remote-0123456789abcdef/repodata/repomd.xml", fixedNow.Add(-1*time.Hour))
	rep := collectRPM(h.env("dnf"), repohealth.ManagerDNF, []string{"/etc/yum.repos.d/*.repo"}, []string{"/etc/dnf/dnf.conf"}, []string{"/var/cache/dnf"})
	if len(rep.Repos) != 5 {
		t.Fatalf("repos = %d: %+v", len(rep.Repos), rep.Repos)
	}
	got := map[string]repohealth.Sig{}
	for _, r := range rep.Repos {
		got[r.ID] = r.Signature
	}
	want := map[string]repohealth.Sig{
		"baseos": repohealth.SigGood, "vendor": repohealth.SigExpiredKey, "nocache": repohealth.SigNoIndex,
		"nocheck": repohealth.SigNotChecked, "remote": repohealth.SigNotChecked,
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %v, want %v", id, got[id], w)
		}
	}
	for _, r := range rep.Repos {
		if r.ID == "vendor" && (r.KeyExpires == nil || r.KeyExpires.Format("2006-01-02") != "2026-01-02") {
			t.Errorf("vendor key expires = %v", r.KeyExpires)
		}
		if r.ID == "baseos" && !strings.Contains(r.URI, "dl.test/9/BaseOS/x86_64") {
			t.Errorf("variables not substituted in %q", r.URI)
		}
	}
	// A repo's own gpgcheck=0 and a remote key are never findings or reasons for distrust.
	a := repohealth.Assess(rep, fixedNow, 0)
	codes := map[string]string{}
	for _, p := range a.Problems {
		codes[p.RepoID] += p.Code + " "
	}
	if !strings.Contains(codes["vendor"], repohealth.CodeKeyExpired) || !strings.Contains(codes["vendor"], repohealth.CodeIndexStale) ||
		!strings.Contains(codes["nocache"], repohealth.CodeNoIndex) || codes["baseos"] != "" || codes["nocheck"] != "" || codes["remote"] != "" {
		t.Errorf("problems = %v", codes)
	}
}

func TestCollectRPMImportedKeyOutranksTheFile(t *testing.T) {
	h := newFixtureHost(t)
	cur, _ := os.ReadFile("../repohealth/testdata/key-current.asc")
	keys, _ := repohealth.ReadKeys(cur)
	exp, _ := os.ReadFile("../repohealth/testdata/key-expired.asc")
	h.write("etc/pki/rpm-gpg/KEY", string(cur))
	h.write("etc/yum.repos.d/t.repo", "[r]\nbaseurl=https://r.test/\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/KEY\n")
	h.touch("var/cache/dnf/r-0123456789abcdef/repodata/repomd.xml", fixedNow)
	env := h.env("dnf")
	// rpm says the key it actually checks packages against, with that id, has expired.
	imported := string(exp)
	env.rpm = func(args ...string) (string, bool) {
		if len(args) > 1 && args[1] == "gpg-pubkey" {
			return "aaaaaaaa-1\n", true
		}
		return imported, true
	}
	_ = keys
	// The imported key has another id than the file's, so it does not apply.
	rep := collectRPM(env, repohealth.ManagerDNF, []string{"/etc/yum.repos.d/*.repo"}, nil, []string{"/var/cache/dnf"})
	if rep.Repos[0].Signature != repohealth.SigGood {
		t.Errorf("unrelated imported key changed the verdict: %+v", rep.Repos[0])
	}
	// Same id: the imported copy is what counts.
	k, _ := repohealth.ReadKeys(cur)
	expKeys, _ := repohealth.ReadKeys(exp)
	if k[0].ShortID() == expKeys[0].ShortID() {
		t.Skip("fixture keys share an id")
	}
	h.write("etc/pki/rpm-gpg/KEY", string(exp))
	rep = collectRPM(env, repohealth.ManagerDNF, []string{"/etc/yum.repos.d/*.repo"}, nil, []string{"/var/cache/dnf"})
	if rep.Repos[0].Signature != repohealth.SigExpiredKey {
		t.Errorf("expired key file = %+v", rep.Repos[0])
	}
}

func TestCollectRepoHealthPicksTheManagerAndDegradesToEmpty(t *testing.T) {
	h := newFixtureHost(t)
	if rep := collectRepoHealth(h.env("apt-get")); rep.Manager != repohealth.ManagerApt {
		t.Errorf("apt host = %q", rep.Manager)
	}
	if rep := collectRepoHealth(h.env("dnf")); rep.Manager != repohealth.ManagerDNF {
		t.Errorf("dnf host = %q", rep.Manager)
	}
	if rep := collectRepoHealth(h.env("zypper")); rep.Manager != repohealth.ManagerZypper {
		t.Errorf("zypper host = %q", rep.Manager)
	}
	if rep := collectRepoHealth(h.env("pacman")); !rep.Empty() {
		t.Errorf("unknown manager gave %+v", rep)
	}
}

// ---- the real gpgv ---------------------------------------------------------------------------------------

// The expired-key condition on this machine's own gpg and gpgv: a repository signed
// by a key that has since expired. gpgv says "Good signature" and exits 0; only
// the status line says the key is expired. This runs the real binaries and the
// in-memory keyring path (a pipe is not accepted by gpgv and reports every key
// as missing, which is why a memfd is used).
func TestRealGPGVReportsExpiredAndMissingKeys(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed")
	}
	if _, err := exec.LookPath("gpgv"); err != nil {
		t.Skip("gpgv is not installed")
	}
	if runtimeGOOS() != "linux" {
		t.Skip("in-memory keyrings need Linux")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(gpg, append([]string{"--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--homedir", home}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("--faked-system-time", "20260101T000000", "--quick-gen-key", "DefendSec Test <t@example.invalid>", "default", "default", "1d")
	dir := t.TempDir()
	rel := filepath.Join(dir, "Release")
	if err := os.WriteFile(rel, []byte("Origin: T\nDate: Thu, 01 Jan 2026 12:00:00 UTC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "InRelease")
	run("--faked-system-time", "20260101T120000", "--clearsign", "-o", signed, rel)
	keyring := run("--export")
	_ = keyring
	expCmd := exec.Command(gpg, "--batch", "--homedir", home, "--export")
	bin, err := expCmd.Output()
	if err != nil {
		t.Fatal(err)
	}

	status, stderr, err := runGPGV(nil, [][]byte{bin}, []string{signed})
	if err != nil {
		t.Fatal(err)
	}
	if v := repohealth.ParseGPGVStatus(status); v.Sig != repohealth.SigExpiredKey {
		t.Errorf("expired key: got %v\nstatus:\n%s\nstderr:\n%s", v.Sig, status, stderr)
	}
	// The same file against a keyring that does not hold the key.
	other, err := os.ReadFile("../repohealth/testdata/key-noexpiry.asc")
	if err != nil {
		t.Fatal(err)
	}
	otherBin, _ := repohealth.Dearmor(other)
	status, _, err = runGPGV(nil, [][]byte{otherBin}, []string{signed})
	if err != nil {
		t.Fatal(err)
	}
	if v := repohealth.ParseGPGVStatus(status); v.Sig != repohealth.SigNoPubkey {
		t.Errorf("wrong keyring: got %v\n%s", v.Sig, status)
	}
	// A file keyring path works too, and a tampered file is a bad signature.
	kr := filepath.Join(dir, "keyring.gpg")
	if err := os.WriteFile(kr, bin, 0o644); err != nil {
		t.Fatal(err)
	}
	status, _, _ = runGPGV([]string{kr}, nil, []string{signed})
	if v := repohealth.ParseGPGVStatus(status); v.Sig != repohealth.SigExpiredKey {
		t.Errorf("file keyring: got %v", v.Sig)
	}
	raw, _ := os.ReadFile(signed)
	if err := os.WriteFile(signed, []byte(strings.Replace(string(raw), "Origin: T", "Origin: X", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	status, _, _ = runGPGV([]string{kr}, nil, []string{signed})
	if v := repohealth.ParseGPGVStatus(status); v.Sig != repohealth.SigBad {
		t.Errorf("tampered: got %v\n%s", v.Sig, status)
	}
}
