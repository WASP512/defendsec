package nevra

import "testing"

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want NEVRA
	}{
		{"kernel-0:5.14.0-687.59.1.el9_8.x86_64.rpm", NEVRA{"kernel", "0", "5.14.0", "687.59.1.el9_8", "x86_64"}},
		{"openssl-libs-1:3.0.1-43.el9_0.i686.rpm", NEVRA{"openssl-libs", "1", "3.0.1", "43.el9_0", "i686"}},
		// A name with dashes and digits; no epoch in the file name means 0.
		{"python3-libs-3.9.18-3.el9_4.2.noarch", NEVRA{"python3-libs", "0", "3.9.18", "3.el9_4.2", "noarch"}},
		{"kernel-0:5.14.0-687.59.1.el9_8.src.rpm", NEVRA{"kernel", "0", "5.14.0", "687.59.1.el9_8", "src"}},
	} {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
	got, _ := Parse("kernel-0:5.14.0-687.59.1.el9_8.x86_64.rpm")
	if got.EVR() != "0:5.14.0-687.59.1.el9_8" {
		t.Errorf("EVR = %q", got.EVR())
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "kernel", "kernel-5.14.0.x86_64", "kernel.rpm", "-1-2.x86_64", "kernel-x:1-2.x86_64"} {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", in, got)
		}
	}
}

func TestSourceAndModular(t *testing.T) {
	src, _ := Parse("kernel-0:5.14.0-687.59.1.el9_8.src.rpm")
	if !src.IsSource() {
		t.Error("src.rpm not recognised as source")
	}
	mod, _ := Parse("nodejs-1:18.12.1-1.module+el9.1.0+16755+0e7c4a5f.x86_64.rpm")
	if !mod.IsModular() {
		t.Error("module build not recognised")
	}
	plain, _ := Parse("nodejs-1:18.12.1-1.el9.x86_64.rpm")
	if plain.IsModular() || plain.IsSource() {
		t.Error("plain build misclassified")
	}
}
