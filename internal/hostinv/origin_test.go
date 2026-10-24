package hostinv

import (
	"os"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// testdata/apt-policy-*.txt are real `apt-cache policy` output from a Debian 13
// host with NodeSource's Node.js 22 installed.
func TestParseAptSourcesReal(t *testing.T) {
	src := ParseAptSources(readTestdata(t, "apt-policy-sources.txt"))
	deb, ok := src["http://deb.debian.org/debian trixie/main"]
	if !ok || deb.Label != "Debian" || deb.Repo != "http://deb.debian.org/debian" {
		t.Errorf("debian main = %+v (%v)", deb, ok)
	}
	if sec := src["http://security.debian.org trixie-security/main"]; sec.Label != "Debian" {
		t.Errorf("debian security = %+v", sec)
	}
	// NodeSource's Release file says Origin ". nodistro", which names nothing:
	// the host stands in for it.
	ns := src["https://deb.nodesource.com/node_22.x nodistro/main"]
	if ns.Label != "deb.nodesource.com" || ns.Repo != "https://deb.nodesource.com/node_22.x" {
		t.Errorf("nodesource = %+v", ns)
	}
	for k := range src {
		if strings.HasPrefix(k, "/") {
			t.Errorf("the local dpkg database is not a source: %q", k)
		}
	}
	if len(src) != 6 {
		t.Errorf("sources = %d, want 6: %v", len(src), src)
	}
}

func TestParseAptPolicyReal(t *testing.T) {
	got := ParseAptPolicy(readTestdata(t, "apt-policy-packages.txt"))
	// The installed version is the one with *** ; older versions the same
	// repository still lists must not leak in.
	node := got["nodejs"]
	if node.Version != "22.23.3-1nodesource1" || len(node.Sources) != 1 || node.Sources[0] != "https://deb.nodesource.com/node_22.x nodistro/main" {
		t.Errorf("nodejs = %+v", node)
	}
	// openssl 3.5.7-1~deb13u3 is in the security archive only; deb13u2 in the main archive.
	ssl := got["openssl"]
	if ssl.Version != "3.5.7-1~deb13u3" || len(ssl.Sources) != 1 || ssl.Sources[0] != "http://security.debian.org trixie-security/main" {
		t.Errorf("openssl = %+v", ssl)
	}
	if got["libc6"].Version != "2.41-12+deb13u4" || len(got) != 4 {
		t.Errorf("libc6 = %+v, packages = %d", got["libc6"], len(got))
	}
}

// Hand-written to the grammar above: Sury's repository on Debian 11, a
// multiarch name, a package apt no longer lists, and a package that is not
// installed.
const suryPolicy = `php8.0-cli:
  Installed: 8.0.30-3+0~20231014.67+debian11~1.gbpf0b1c1
  Candidate: 8.0.30-3+0~20231014.67+debian11~1.gbpf0b1c1
  Version table:
 *** 8.0.30-3+0~20231014.67+debian11~1.gbpf0b1c1 500
        500 https://packages.sury.org/php bullseye/main amd64 Packages
        100 /var/lib/dpkg/status
libssl1.1:amd64:
  Installed: 1.1.1w-0+deb11u1
  Candidate: 1.1.1w-0+deb11u1
  Version table:
 *** 1.1.1w-0+deb11u1 500
        500 http://security.debian.org/debian-security bullseye-security/main amd64 Packages
        100 /var/lib/dpkg/status
oldtool:
  Installed: 1.0-1
  Candidate: 1.0-1
  Version table:
 *** 1.0-1 100
        100 /var/lib/dpkg/status
ghost:
  Installed: (none)
  Candidate: 2.0-1
  Version table:
     2.0-1 500
        500 http://deb.debian.org/debian bullseye/main amd64 Packages
`

const suryHeader = `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 https://packages.sury.org/php bullseye/main amd64 Packages
     release o=deb.sury.org,a=bullseye,n=bullseye,l=deb.sury.org,c=main,b=amd64
     origin packages.sury.org
 500 http://security.debian.org/debian-security bullseye-security/main amd64 Packages
     release v=11,o=Debian,a=oldstable-security,n=bullseye-security,l=Debian-Security,c=main,b=amd64
     origin security.debian.org
 500 http://deb.debian.org/debian bullseye/main amd64 Packages
     release v=11.8,o=Debian,a=oldstable,n=bullseye,l=Debian,c=main,b=amd64
     origin deb.debian.org
Pinned packages:
`

func TestOriginOfSuryAndDebianPackages(t *testing.T) {
	sources := ParseAptSources(suryHeader)
	in := ParseAptPolicy(suryPolicy)
	if len(in) != 3 {
		t.Fatalf("packages = %v, want the three that are installed (ghost is not)", in)
	}
	label, repo := pickOrigin("debian", in["php8.0-cli"].Sources, sources)
	if label != "deb.sury.org" || repo != "https://packages.sury.org/php" {
		t.Errorf("php8.0-cli origin = %q %q", label, repo)
	}
	label, repo = pickOrigin("debian", in["libssl1.1"].Sources, sources)
	if label != "Debian" || repo != "http://security.debian.org/debian-security" {
		t.Errorf("libssl1.1 origin = %q %q", label, repo)
	}
	// oldtool is carried by no repository: no origin, never a guess.
	if len(in["oldtool"].Sources) != 0 {
		t.Errorf("oldtool has sources %v", in["oldtool"].Sources)
	}
	if l, r := pickOrigin("debian", in["oldtool"].Sources, sources); l != "" || r != "" {
		t.Errorf("oldtool origin = %q %q, want none", l, r)
	}
}

// A version both the distribution and a third party publish is the
// distribution's to patch.
func TestPickOriginPrefersTheDistribution(t *testing.T) {
	sources := map[string]aptSource{
		"https://a.example/x stable/main":            {Label: "Zeta", Repo: "https://a.example/x"},
		"http://deb.debian.org/debian bookworm/main": {Label: "Debian", Repo: "http://deb.debian.org/debian"},
	}
	keys := []string{"https://a.example/x stable/main", "http://deb.debian.org/debian bookworm/main"}
	if l, _ := pickOrigin("debian", keys, sources); l != "Debian" {
		t.Errorf("origin = %q, want Debian", l)
	}
	// On a distribution whose labels are unknown there is no preference; the
	// choice is still deterministic.
	if l, _ := pickOrigin("gentoo", keys, sources); l != "Debian" {
		t.Errorf("origin = %q", l)
	}
	if l, r := pickOrigin("debian", []string{"missing"}, sources); l != "" || r != "" {
		t.Errorf("unknown source gave %q %q", l, r)
	}
}

func TestRedactURLNeverKeepsCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"https://deb.example.com/php":                   "https://deb.example.com/php",
		"https://user:s3cr3t@deb.example.com/php?t=abc": "https://deb.example.com/php",
		"https://tok@deb.example.com/x":                 "https://deb.example.com/x",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
	if got := redactURL("user:pw@weird"); strings.Contains(got, "pw") {
		t.Errorf("unparseable address with credentials leaked: %q", got)
	}
}

func TestParseRPMQueryReadsVendor(t *testing.T) {
	out := "nginx\t1:1.24.0-1.el9.ngx\tnginx-1.24.0-1.el9.ngx.src.rpm\tNginx, Inc.\tNginx Team <nginx-packaging@f5.com>\n" +
		"php-cli\t8.0.30-1.el9.remi\tphp-8.0.30-1.el9.remi.src.rpm\tRemi Collet\tRemi Collet <remi@remirepo.net>\n" +
		"openssl-libs\t1:3.0.7-28.el9_4\topenssl-3.0.7-28.el9_4.src.rpm\tRocky Enterprise Software Foundation\tinfrastructure@rockylinux.org\n" +
		"nopackager\t1.0-1\tx-1.0-1.src.rpm\t(none)\t(none)\n" +
		"packageronly\t1.0-1\tx-1.0-1.src.rpm\t(none)\tSome Builder <b@example.com>\n" +
		"oldformat\t1.0-1\tx-1.0-1.src.rpm\n"
	got := map[string]Software{}
	for _, sw := range ParseRPMQuery(out) {
		got[sw.Name] = sw
	}
	check := func(name, origin, repo string) {
		t.Helper()
		if got[name].Origin != origin || got[name].OriginRepo != repo {
			t.Errorf("%s origin = %q %q, want %q %q", name, got[name].Origin, got[name].OriginRepo, origin, repo)
		}
	}
	check("nginx", "Nginx, Inc.", "Nginx Team")
	check("php-cli", "Remi Collet", "Remi Collet")
	check("openssl-libs", "Rocky Enterprise Software Foundation", "infrastructure@rockylinux.org")
	check("nopackager", "", "")
	check("packageronly", "Some Builder", "")
	check("oldformat", "", "")
	if got["nginx"].Version != "1:1.24.0-1.el9.ngx" {
		t.Errorf("version = %q", got["nginx"].Version)
	}
}
