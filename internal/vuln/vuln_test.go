package vuln

import "testing"

// Behavioural cases for the boolean wrapper. Version ordering itself is
// covered by version_test.go and the backport semantics by compare_test.go.
func TestVersionOlderThan(t *testing.T) {
	cases := []struct {
		installed string
		floor     string
		want      bool
	}{
		// Previously asserted true. Ubuntu 22.04 carries the fix for
		// CVE-2024-6387 in 1:8.9p1-3ubuntu0.10, so flagging this host was a
		// false positive; the honest answer is that a version comparison
		// cannot decide, and an undecidable case must not alert.
		{"1:8.9p1-3ubuntu0.11", "9.8p1", false},
		{"1:9.8p1-1", "9.8p1", false},
		{"3.0.2-0ubuntu1.18", "3.0.14", false},
		{"3.0.14", "3.0.14", false},

		// Plain upstream builds still resolve definitively.
		{"3.0.2", "3.0.14", true},
		{"1.1.1a", "1.1.1g", true},
		{"2.0~rc1", "2.0", true},
		{"3.0.15", "3.0.14", false},
	}
	for _, tc := range cases {
		got := VersionOlderThan(tc.installed, tc.floor)
		if got != tc.want {
			t.Errorf("VersionOlderThan(%q, %q) = %v, want %v", tc.installed, tc.floor, got, tc.want)
		}
	}
}

func TestPackageMatches(t *testing.T) {
	if !PackageMatches("git", "git") {
		t.Fatal("git should match git")
	}
	if PackageMatches("git", "git-lfs") {
		t.Fatal("git should not match git-lfs")
	}
	if !PackageMatches("docker", "docker.io") {
		t.Fatal("docker.io should match docker")
	}
	if PackageMatches("docker", "docker-compose") {
		t.Fatal("docker-compose should not match docker")
	}
	if !PackageMatches("google chrome", "Google Chrome") {
		t.Fatal("Google Chrome should match google chrome")
	}
	if !PackageMatches("openssh", "openssh-server") {
		t.Fatal("openssh-server should match openssh")
	}
	if !PackageMatches("openssl", "openssl-libs") {
		t.Fatal("openssl-libs should match openssl")
	}
	if !PackageMatches("kernel", "kernel-core") {
		t.Fatal("kernel-core should match kernel")
	}
	if !PackageMatches("curl", "libcurl") {
		t.Fatal("libcurl should match curl")
	}
}
