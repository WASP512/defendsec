package vuln

import (
	"strconv"
	"strings"
)

var packageAliases = map[string]string{
	"docker.io":            "docker",
	"docker-ce":            "docker",
	"docker-ee":            "docker",
	"google-chrome":        "google chrome",
	"google-chrome-stable": "google chrome",
	"google chrome":        "google chrome",
	"adobe-photoshop":      "adobe photoshop",
	// Fedora/RHEL RPM names ↔ common advisory package labels
	"openssh":        "openssh",
	"openssh-server": "openssh",
	"openssh-clients": "openssh",
	"openssl":        "openssl",
	"openssl-libs":   "openssl",
	"openssl-devel":  "openssl",
	"kernel":         "kernel",
	"kernel-core":    "kernel",
	"kernel-modules": "kernel",
	"glibc":          "glibc",
	"glibc-common":   "glibc",
	"curl":           "curl",
	"libcurl":        "curl",
	"libcurl-minimal": "curl",
}

func StripDebianEpoch(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func parseVersion(raw string) []int {
	s := StripDebianEpoch(raw)
	var parts []int
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		if seg == "" {
			continue
		}
		n, err := strconv.Atoi(seg)
		if err != nil {
			continue
		}
		parts = append(parts, n)
	}
	return parts
}

// VersionOlderThan reports whether installed is strictly older than the patched floor.
func VersionOlderThan(installed, floor string) bool {
	a := parseVersion(installed)
	b := parseVersion(floor)
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		left := 0
		if i < len(a) {
			left = a[i]
		}
		right := 0
		if i < len(b) {
			right = b[i]
		}
		if left < right {
			return true
		}
		if left > right {
			return false
		}
	}
	return false
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
