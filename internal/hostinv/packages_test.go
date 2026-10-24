package hostinv

import (
	"reflect"
	"testing"
)

func TestParseDpkgSource(t *testing.T) {
	for _, tc := range []struct{ in, name, ver string }{
		{"", "", ""},
		{"openssh", "openssh", ""},
		{"glibc (2.36-9+deb12u4)", "glibc", "2.36-9+deb12u4"},
		{"  linux-signed-amd64 (6.1.115+1)  ", "linux-signed-amd64", "6.1.115+1"},
		{"odd (unterminated", "odd", ""},
	} {
		name, ver := ParseDpkgSource(tc.in)
		if name != tc.name || ver != tc.ver {
			t.Errorf("ParseDpkgSource(%q) = %q, %q; want %q, %q", tc.in, name, ver, tc.name, tc.ver)
		}
	}
}

// dpkg-query output as captured from a Debian host: a binary built from a
// differently named source, a binNMU with a source version, a package with no
// Source: field, and a package that was removed but kept its config files.
func TestParseDpkgQuery(t *testing.T) {
	out := "openssh-server\t1:9.2p1-2+deb12u3\topenssh\tii \n" +
		"libc6\t2.36-9+deb12u4+b1\tglibc (2.36-9+deb12u4)\tii \n" +
		"bash\t5.2.15-2+b7\t\tii \n" +
		"oldpkg\t1.0-1\t\trc \n" +
		"half-installed\t2.0-1\tsrc\tiU \n" +
		"\n"
	got := ParseDpkgQuery(out)
	want := []Software{
		{Name: "openssh-server", Version: "1:9.2p1-2+deb12u3", SourcePackage: "openssh"},
		{Name: "libc6", Version: "2.36-9+deb12u4+b1", SourcePackage: "glibc", SourceVersion: "2.36-9+deb12u4"},
		{Name: "bash", Version: "5.2.15-2+b7", SourcePackage: "bash"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDpkgQuery =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseSourceRPM(t *testing.T) {
	for _, tc := range []struct{ in, name, ver string }{
		{"openssl-3.0.7-27.el9.src.rpm", "openssl", "3.0.7-27.el9"},
		{"kernel-5.14.0-427.13.1.el9_4.src.rpm", "kernel", "5.14.0-427.13.1.el9_4"},
		{"python-pip-21.2.3-8.el9.src.rpm", "python-pip", "21.2.3-8.el9"},
		{"openssh-9.6p1-150600.6.9.1.src.rpm", "openssh", "9.6p1-150600.6.9.1"},
		{"(none)", "", ""},
		{"", "", ""},
		{"gpg-pubkey", "", ""},
		{"notasource-1.0-1.x86_64.rpm", "", ""},
	} {
		name, ver := ParseSourceRPM(tc.in)
		if name != tc.name || ver != tc.ver {
			t.Errorf("ParseSourceRPM(%q) = %q, %q; want %q, %q", tc.in, name, ver, tc.name, tc.ver)
		}
	}
}

// rpm -qa output from a Rocky 9 host: epoch present on openssl-libs, absent
// ("") on openssh-server, the key pseudo-package, and two installed kernels.
func TestParseRPMQuery(t *testing.T) {
	out := "openssl-libs\t1:3.0.7-28.el9_4\topenssl-3.0.7-28.el9_4.src.rpm\n" +
		"openssh-server\t8.7p1-38.el9_4.4\topenssh-8.7p1-38.el9_4.4.src.rpm\n" +
		"gpg-pubkey\t350d275d-6279464b\t(none)\n" +
		"kernel-core\t5.14.0-362.8.1.el9_3\tkernel-5.14.0-362.8.1.el9_3.src.rpm\n" +
		"kernel-core\t5.14.0-427.13.1.el9_4\tkernel-5.14.0-427.13.1.el9_4.src.rpm\n" +
		"kernel-core\t5.14.0-284.11.1.el9_2\tkernel-5.14.0-284.11.1.el9_2.src.rpm\n"
	got := map[string]Software{}
	for _, sw := range ParseRPMQuery(out) {
		got[sw.Name] = sw
	}
	if len(got) != 3 {
		t.Fatalf("got %d packages, want 3 (no gpg-pubkey, one kernel-core): %+v", len(got), got)
	}
	if sw := got["openssl-libs"]; sw.Version != "1:3.0.7-28.el9_4" || sw.SourcePackage != "openssl" || sw.SourceVersion != "3.0.7-28.el9_4" {
		t.Errorf("openssl-libs = %+v (the epoch must survive)", sw)
	}
	if sw := got["kernel-core"]; sw.Version != "5.14.0-427.13.1.el9_4" {
		t.Errorf("kernel-core = %+v, want the newest installed version", sw)
	}
}
