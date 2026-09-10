package vuln

import "testing"

func TestVersionOlderThan(t *testing.T) {
	cases := []struct {
		installed string
		floor     string
		want      bool
	}{
		{"1:8.9p1-3ubuntu0.11", "9.8p1", true},
		{"1:9.8p1-1", "9.8p1", false},
		{"3.0.2-0ubuntu1.18", "3.0.14", true},
		{"3.0.14", "3.0.14", false},
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
}
