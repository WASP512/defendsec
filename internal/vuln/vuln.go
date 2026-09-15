package vuln

import "strings"

var packageAliases = map[string]string{
	"docker.io":            "docker",
	"docker-ce":            "docker",
	"docker-ee":            "docker",
	"google-chrome":        "google chrome",
	"google-chrome-stable": "google chrome",
	"google chrome":        "google chrome",
	"adobe-photoshop":      "adobe photoshop",
	// Fedora/RHEL RPM names ↔ common advisory package labels
	"openssh":         "openssh",
	"openssh-server":  "openssh",
	"openssh-clients": "openssh",
	"openssl":         "openssl",
	"openssl-libs":    "openssl",
	"openssl-devel":   "openssl",
	"kernel":          "kernel",
	"kernel-core":     "kernel",
	"kernel-modules":  "kernel",
	"glibc":           "glibc",
	"glibc-common":    "glibc",
	"curl":            "curl",
	"libcurl":         "curl",
	"libcurl-minimal": "curl",
}

func StripDebianEpoch(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// VersionOlderThan reports whether installed is strictly older than the patched
// floor.
//
// Deprecated: prefer Assess, which distinguishes "not vulnerable" from "cannot
// tell". This wrapper collapses VerdictUnknown to false so that an undecidable
// comparison never raises an alert on its own.
func VersionOlderThan(installed, floor string) bool {
	return Assess(installed, floor, SchemeAuto).Verdict == VerdictVulnerable
}

func canonicalPackage(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if v, ok := packageAliases[lower]; ok {
		return v
	}
	dashed := strings.ReplaceAll(lower, "_", "-")
	if v, ok := packageAliases[dashed]; ok {
		return v
	}
	return strings.ReplaceAll(dashed, "-", " ")
}

// PackageMatches reports whether an installed package name matches an advisory package.
func PackageMatches(advisoryPackage, installedName string) bool {
	return canonicalPackage(installedName) == canonicalPackage(advisoryPackage)
}

func IsHighOrCritical(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high", "critical":
		return true
	default:
		return false
	}
}
