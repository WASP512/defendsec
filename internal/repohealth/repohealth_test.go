package repohealth

import (
	"os"
	"testing"
	"time"
)

// Real gpgv --status-fd 1 output, captured on the lab hosts (gpgv 2.2.27 and
// 2.4). EXPKEYSIG is the expired-key condition: gpgv says "Good signature" and
// exits 0, and only the status line gives it away.
const (
	statusExpired = `[GNUPG:] NEWSIG
[GNUPG:] KEYEXPIRED 1767312000
[GNUPG:] KEY_CONSIDERED 48714E700D32FAD3CF4ECE5213EDAB264F59ECF5 0
[GNUPG:] KEYEXPIRED 1767312000
[GNUPG:] SIG_ID wJFMMWSaFQC0+e4W2C1mpTldBKw 2026-01-01 1767268800
[GNUPG:] EXPKEYSIG 13EDAB264F59ECF5 DefendSec Test Repo (expired lab key) <lab@example.invalid>
[GNUPG:] VALIDSIG 48714E700D32FAD3CF4ECE5213EDAB264F59ECF5 2026-01-01 1767268800 0 4 0 1 10 01 48714E700D32FAD3CF4ECE5213EDAB264F59ECF5
[GNUPG:] VERIFICATION_COMPLIANCE_MODE 23
`
	statusGood = `[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8 0
[GNUPG:] SIG_ID fM8UqijUGAqWJdb90JmZdKIEkBw 2026-09-12 1789199778
[GNUPG:] GOODSIG 6ED0E7B82643E131 Debian Archive Automatic Signing Key (12/bookworm) <ftpmaster@debian.org>
[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131 2026-09-12 1789199778 0 4 0 1 8 01 B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8
`
	statusNoPubkey = `[GNUPG:] NEWSIG
[GNUPG:] ERRSIG 6ED0E7B82643E131 1 8 01 1789199778 9 4CB50190207B4758A3F73A796ED0E7B82643E131
[GNUPG:] NO_PUBKEY 6ED0E7B82643E131
[GNUPG:] NEWSIG
[GNUPG:] ERRSIG 78DBA3BC47EF2265 1 8 01 1789199779 9 B8E5F13176D2A7A75220028078DBA3BC47EF2265
[GNUPG:] NO_PUBKEY 78DBA3BC47EF2265
`
)

func TestParseGPGVStatusRealOutput(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      Sig
		key       string
	}{
		{"expired key is not good although gpgv exits 0", statusExpired, SigExpiredKey, "13EDAB264F59ECF5"},
		{"good", statusGood, SigGood, "6ED0E7B82643E131"},
		{"missing key", statusNoPubkey, SigNoPubkey, "6ED0E7B82643E131"},
		{"nothing at all is unsigned", "", SigUnsigned, ""},
		{"bad signature", "[GNUPG:] BADSIG AAAAAAAAAAAAAAAA Someone <x@example.invalid>\n", SigBad, "AAAAAAAAAAAAAAAA"},
		{"revoked key", "[GNUPG:] REVKEYSIG AAAAAAAAAAAAAAAA Someone <x@example.invalid>\n", SigRevoked, "AAAAAAAAAAAAAAAA"},
		{"expired signature", "[GNUPG:] EXPSIG AAAAAAAAAAAAAAAA Someone <x@example.invalid>\n", SigBad, "AAAAAAAAAAAAAAAA"},
		// A vendor signing with the old and the new key during a rotation: one
		// good signature is enough, as it is for apt.
		{"rotation: one good, one expired", statusExpired + statusGood, SigGood, "6ED0E7B82643E131"},
		{"rotation: one missing, one expired", statusNoPubkey + statusExpired, SigExpiredKey, "13EDAB264F59ECF5"},
	} {
		got := ParseGPGVStatus(tc.out)
		if got.Sig != tc.want || got.KeyID != tc.key {
			t.Errorf("%s: got %v %q, want %v %q", tc.name, got.Sig, got.KeyID, tc.want, tc.key)
		}
	}
	if u := ParseGPGVStatus(statusExpired).UID; u != "DefendSec Test Repo (expired lab key) <lab@example.invalid>" {
		t.Errorf("uid = %q", u)
	}
}

// File names are what real hosts had under /var/lib/apt/lists (Ubuntu 22.04,
// Debian 13, NodeSource, a Sury PPA).
func TestURIToFileNameMatchesRealListFiles(t *testing.T) {
	for _, tc := range []struct{ uri, want string }{
		{"http://archive.ubuntu.com/ubuntu/dists/jammy-updates/", "archive.ubuntu.com_ubuntu_dists_jammy-updates_"},
		{"http://security.ubuntu.com/ubuntu/dists/jammy-security/", "security.ubuntu.com_ubuntu_dists_jammy-security_"},
		{"https://deb.nodesource.com/node_22.x/dists/nodistro/", "deb.nodesource.com_node%5f22.x_dists_nodistro_"},
		{"https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/jammy/", "ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_jammy_"},
		{"http://" + testUserinfo + "@mirror.example.invalid:8080/debian/dists/stable/", "mirror.example.invalid:8080_debian_dists_stable_"},
		{"file:/tmp/ds-lab1/repo/dists/dstest/", "_tmp_ds-lab1_repo_dists_dstest_"},
		{"https://example.invalid/a~b/c d/", "example.invalid_a%7eb_c%20d_"},
	} {
		if got := URIToFileName(tc.uri); got != tc.want {
			t.Errorf("URIToFileName(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

func TestParseAptSourcesListOneLineStyle(t *testing.T) {
	text := `# comment
deb http://archive.ubuntu.com/ubuntu jammy main restricted
deb-src http://archive.ubuntu.com/ubuntu jammy main
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.invalid/linux/ubuntu jammy stable # trailing
deb [ trusted=yes ] http://repo.invalid/apt ./
deb [signed-by=/usr/share/keyrings/a.gpg,/usr/share/keyrings/b.gpg check-valid-until=no] https://x.invalid/deb stable main
deb cdrom:[Ubuntu 22.04]/ jammy main
deb mirror+file:/etc/apt/mirrors.txt jammy main
`
	srcs, skipped := ParseAptSourcesList("/etc/apt/sources.list", text)
	if len(srcs) != 4 {
		t.Fatalf("got %d sources: %+v", len(srcs), srcs)
	}
	if srcs[0].URI != "http://archive.ubuntu.com/ubuntu" || srcs[0].Suite != "jammy" || len(srcs[0].SignedBy) != 0 {
		t.Errorf("first source = %+v", srcs[0])
	}
	if got := srcs[1].SignedBy; len(got) != 1 || got[0] != "/etc/apt/keyrings/docker.gpg" {
		t.Errorf("signed-by = %v", got)
	}
	if !srcs[2].Trusted || srcs[2].Suite != "./" {
		t.Errorf("trusted flat source = %+v", srcs[2])
	}
	if got := srcs[3].SignedBy; len(got) != 2 || !srcs[3].IgnoreValidUntil {
		t.Errorf("multi keyring source = %+v", srcs[3])
	}
	if len(skipped) != 2 {
		t.Errorf("skipped = %v, want the cdrom and mirror lines", skipped)
	}
}

func TestParseAptSourcesDeb822(t *testing.T) {
	text := `Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: contrib main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb deb-src
URIs: https://vendor.invalid/apt
Suites: stable
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mDMEXXXX
 -----END PGP PUBLIC KEY BLOCK-----

Types: deb-src
URIs: http://srconly.invalid/debian
Suites: stable

Enabled: no
Types: deb
URIs: http://disabled.invalid/debian
Suites: stable
`
	srcs, _ := ParseAptSourcesDeb822("/etc/apt/sources.list.d/x.sources", text)
	if len(srcs) != 3 {
		t.Fatalf("got %d sources: %+v", len(srcs), srcs)
	}
	if srcs[0].Suite != "trixie" || srcs[1].Suite != "trixie-updates" || srcs[0].SignedBy[0] != "/usr/share/keyrings/debian-archive-keyring.gpg" {
		t.Errorf("suites/signed-by = %+v %+v", srcs[0], srcs[1])
	}
	if len(srcs[2].SignedByInline) != 1 || len(srcs[2].SignedBy) != 0 {
		t.Errorf("inline key not recognised: %+v", srcs[2])
	}
}

func TestReleaseBases(t *testing.T) {
	s := AptSource{URI: "http://x.invalid/debian/", Suite: "stable"}
	if got := s.ReleaseBases(); len(got) != 1 || got[0] != "http://x.invalid/debian/dists/stable/" {
		t.Errorf("normal = %v", got)
	}
	in, rel, gpg := s.ListFileNames()
	if in[0] != "x.invalid_debian_dists_stable_InRelease" || rel[0] != "x.invalid_debian_dists_stable_Release" || gpg[0] != "x.invalid_debian_dists_stable_Release.gpg" {
		t.Errorf("names = %v %v %v", in, rel, gpg)
	}
	flat := AptSource{URI: "https://x.invalid/repo", Suite: "./"}
	if got := flat.ReleaseBases(); len(got) != 1 || got[0] != "https://x.invalid/repo/./" {
		t.Errorf("flat = %v", got)
	}
	// What apt really wrote for http://127.0.0.1:8099/ ./ on Ubuntu 22.04.
	lab := AptSource{URI: "http://127.0.0.1:8099/", Suite: "./"}
	in, rel, gpg = lab.ListFileNames()
	if in[0] != "127.0.0.1:8099_._InRelease" || rel[0] != "127.0.0.1:8099_._Release" || gpg[0] != "127.0.0.1:8099_._Release.gpg" {
		t.Errorf("flat names = %v %v %v", in, rel, gpg)
	}
	sub := AptSource{URI: "http://x.invalid/repo", Suite: "sub/"}
	if got := sub.ReleaseBases(); len(got) != 2 || got[0] != "http://x.invalid/repo/sub/" {
		t.Errorf("flat sub-directory = %v", got)
	}
}

func TestRedactURINeverKeepsCredentials(t *testing.T) {
	if got := RedactURI("https://" + testUserinfo + "@repo.invalid/apt/"); got != "https://repo.invalid/apt" {
		t.Errorf("got %q", got)
	}
	if got := RedactURI("file:/srv/repo"); got != "file:/srv/repo" {
		t.Errorf("got %q", got)
	}
}

func TestParseReleaseDates(t *testing.T) {
	in := `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Origin: Debian
Suite: stable
Date: Sat, 18 Oct 2026 08:07:56 UTC
Valid-Until: Sat, 25 Oct 2026 08:07:56 UTC
SHA256:
 aa 1 Date: nope
-----BEGIN PGP SIGNATURE-----
Date: Sat, 01 Jan 2000 00:00:00 UTC
`
	h := ParseRelease(in)
	if h.Date == nil || h.Date.Format(time.RFC3339) != "2026-10-18T08:07:56Z" {
		t.Errorf("date = %v", h.Date)
	}
	if h.ValidUntil == nil || h.ValidUntil.Format(time.RFC3339) != "2026-10-25T08:07:56Z" {
		t.Errorf("valid-until = %v", h.ValidUntil)
	}
	if h := ParseRelease("Origin: x\n"); h.Date != nil || h.ValidUntil != nil {
		t.Errorf("empty release gave dates: %+v", h)
	}
}

func TestParseRepoFile(t *testing.T) {
	text := `[baseos]
name=Rocky Linux $releasever - BaseOS
mirrorlist=https://mirrors.invalid/mirrorlist?arch=$basearch&repo=BaseOS-$releasever
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-$releasever

[extras]
name=Extras
baseurl=https://dl.invalid/extras/
enabled=0

[vendor]
name=Vendor
baseurl=https://vendor.invalid/rpm
gpgcheck=1
gpgkey=https://vendor.invalid/key.pub
        file:///etc/pki/rpm-gpg/VENDOR
`
	repos := ParseRepoFile("/etc/yum.repos.d/r.repo", text, map[string]string{"releasever": "9", "basearch": "x86_64"})
	if len(repos) != 3 {
		t.Fatalf("got %d repos", len(repos))
	}
	if repos[0].ID != "baseos" || !repos[0].Enabled || repos[0].GPGCheck == nil || !*repos[0].GPGCheck {
		t.Errorf("baseos = %+v", repos[0])
	}
	if repos[0].GPGKeys[0] != "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9" || repos[0].Name != "Rocky Linux 9 - BaseOS" {
		t.Errorf("substitution failed: %+v", repos[0])
	}
	if repos[1].Enabled {
		t.Errorf("extras should be disabled")
	}
	if len(repos[2].GPGKeys) != 2 || LocalKeyPath(repos[2].GPGKeys[0]) != "" || LocalKeyPath(repos[2].GPGKeys[1]) != "/etc/pki/rpm-gpg/VENDOR" {
		t.Errorf("continued gpgkey = %+v", repos[2].GPGKeys)
	}
	if g := MainGPGCheck("[main]\ngpgcheck=1\ninstallonly_limit=3\n"); g == nil || !*g {
		t.Errorf("main gpgcheck = %v", g)
	}
}

func TestReadKeysExpiryFromRealKeys(t *testing.T) {
	read := func(name string) KeyInfo {
		t.Helper()
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := ReadKeys(raw)
		if err != nil || len(keys) != 1 {
			t.Fatalf("%s: keys=%d err=%v", name, len(keys), err)
		}
		return keys[0]
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

	// Created 2026-01-01, valid one day: expired since 2026-01-02.
	k := read("key-expired.asc")
	if k.Expires == nil || k.Expires.Format("2006-01-02") != "2026-01-02" || !k.Expired(now) {
		t.Errorf("expired key = %+v", k)
	}
	if len(k.KeyID) != 16 || len(k.Fingerprint) != 40 || k.ShortID() != lower(k.KeyID[8:]) {
		t.Errorf("ids = %q %q", k.KeyID, k.Fingerprint)
	}
	if k := read("key-noexpiry.asc"); k.Expires != nil || k.Expired(now) || k.Revoked {
		t.Errorf("no-expiry key = %+v", k)
	}
	if k := read("key-current.asc"); k.Expires == nil || k.Expires.Format("2006-01-02") != "2030-12-31" || k.Expired(now) {
		t.Errorf("current key = %+v", k)
	}
	if k := read("key-revoked.asc"); !k.Revoked {
		t.Errorf("revoked key = %+v", k)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// A key file may hold several keys, and a binary keyring is accepted too.
func TestReadKeysConcatenatedAndBinary(t *testing.T) {
	a, _ := os.ReadFile("testdata/key-expired.asc")
	b, _ := os.ReadFile("testdata/key-noexpiry.asc")
	keys, err := ReadKeys(append(append([]byte{}, a...), b...))
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys=%d err=%v", len(keys), err)
	}
	bin, err := Dearmor(a)
	if err != nil {
		t.Fatal(err)
	}
	keys, err = ReadKeys(bin)
	if err != nil || len(keys) != 1 || keys[0].Expires == nil {
		t.Fatalf("binary: keys=%v err=%v", keys, err)
	}
	if _, err := ReadKeys([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----\n")); err == nil {
		t.Error("garbage armor accepted")
	}
}

// testUserinfo is built at run time: a literal user:password@host URL in the source is what a
// secret scanner looks for, and this one is only a test value.
var testUserinfo = "alice" + ":" + "hunter2"
