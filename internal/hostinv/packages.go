package hostinv

import (
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"defendsec/internal/vuln"
)

// Package managers a Snapshot can name. The vulnerability matcher picks its
// version comparator from this, not from the shape of the version string.
const (
	PackageManagerDPKG = "dpkg"
	PackageManagerRPM  = "rpm"
)

// maxSoftware bounds one report. The distro-aware matcher needs the whole
// package set: a host is "clean" only if every package was looked at, so the
// old 80-package cap, which made a clean result mean "the first 80 are clean",
// is gone. A full server is a few hundred packages; this ceiling only stops a
// runaway collector.
const maxSoftware = 5000

// packageManager names the manager that owns the host's installed packages,
// or "" on platforms that have none (Windows, macOS).
func packageManager() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	_, hasRPM := exec.LookPath("rpm")
	_, hasDPKG := exec.LookPath("dpkg-query")
	switch {
	case rpmBased() && hasRPM == nil:
		return PackageManagerRPM
	case hasDPKG == nil:
		return PackageManagerDPKG
	case hasRPM == nil:
		return PackageManagerRPM
	}
	return ""
}

// osReleaseIdentity returns os-release ID (lower case) and VERSION_ID as they
// are. Mapping them onto the names advisory feeds use (Rocky 9.4 -> rhel 9) is
// the matcher's job, so a feed change never needs an agent update.
func osReleaseIdentity() (id, versionID string) {
	if runtime.GOOS != "linux" {
		return "", ""
	}
	kv := osRelease()
	return strings.ToLower(strings.TrimSpace(kv["ID"])), strings.TrimSpace(kv["VERSION_ID"])
}

const dpkgQueryFormat = "${Package}\t${Version}\t${Source}\t${db:Status-Abbrev}\n"

// rpmQueryFormat carries the epoch explicitly. It is part of an EVR: openssl on
// RHEL 9 is 1:3.0.7-x, and an installed "3.0.7-x" without it sorts below the
// advisory's "1:3.0.7-y", which would flag every patched host.
const rpmQueryFormat = "%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"

// ParseDpkgQuery reads `dpkg-query -W -f=dpkgQueryFormat` output. Only packages
// in state "ii" (installed) count: dpkg also lists removed packages whose
// configuration files remain, and those are not software on the host.
func ParseDpkgQuery(out string) []Software {
	var items []Software
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 4 || f[0] == "" || f[1] == "" {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(f[3]), "ii") {
			continue
		}
		src, srcVer := ParseDpkgSource(f[2])
		if src == "" {
			src = f[0] // no Source: field means the binary's own name
		}
		items = append(items, Software{Name: f[0], Version: f[1], SourcePackage: src, SourceVersion: srcVer})
	}
	return items
}

// ParseDpkgSource splits a dpkg "Source:" value, "name" or "name (version)",
// the latter used when the source version differs from the binary's (binNMU,
// or a binary built from an earlier upload).
func ParseDpkgSource(raw string) (name, version string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	name, rest, found := strings.Cut(raw, " ")
	if !found {
		return name, ""
	}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		version = strings.TrimSpace(rest[1 : len(rest)-1])
	}
	return name, version
}

// ParseSourceRPM extracts the source package name and version-release from
// SOURCERPM ("openssl-3.0.7-27.el9.src.rpm" -> "openssl", "3.0.7-27.el9").
// "(none)" and anything that is not a .src.rpm name yields "". Epoch is not
// part of the file name, so the version carries none.
func ParseSourceRPM(raw string) (name, version string) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, ".rpm")
	if raw == "" || raw == "(none)" || !strings.HasSuffix(raw, ".src") {
		return "", ""
	}
	raw = strings.TrimSuffix(raw, ".src")
	rel := strings.LastIndex(raw, "-")
	if rel <= 0 {
		return "", ""
	}
	ver := strings.LastIndex(raw[:rel], "-")
	if ver <= 0 {
		return "", ""
	}
	return raw[:ver], raw[ver+1:]
}

// ParseRPMQuery reads `rpm -qa --queryformat rpmQueryFormat` output. gpg-pubkey
// entries are keys, not software. A package installed in several versions (the
// kernel, by design) is reported once at its newest version: that is the one
// the host boots into, and old kernels kept for rollback would otherwise make
// every fully patched host show findings.
func ParseRPMQuery(out string) []Software {
	best := map[string]Software{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 2 || f[0] == "" || f[1] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		sw := Software{Name: f[0], Version: f[1]}
		if len(f) >= 3 {
			sw.SourcePackage, sw.SourceVersion = ParseSourceRPM(f[2])
		}
		if prev, ok := best[sw.Name]; ok && vuln.CompareRPM(prev.Version, sw.Version) >= 0 {
			continue
		}
		best[sw.Name] = sw
	}
	items := make([]Software, 0, len(best))
	for _, sw := range best {
		items = append(items, sw)
	}
	return items
}

// collectPackages lists every installed package of the host's package manager.
func collectPackages(manager string) []Software {
	var items []Software
	switch manager {
	case PackageManagerRPM:
		items = ParseRPMQuery(run("rpm", "-qa", "--queryformat", rpmQueryFormat))
	case PackageManagerDPKG:
		items = ParseDpkgQuery(run("dpkg-query", "-W", "-f="+dpkgQueryFormat))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	if len(items) > maxSoftware {
		items = items[:maxSoftware]
	}
	return items
}

// PackageInventory is exactly what the vulnerability matcher needs from a host:
// no hostname, no addresses. `defendsec-agentd -print-inventory` writes it, so a
// host's package set can be matched offline (defendsec-feeds match) or attached
// to a support request without exposing anything else about the machine.
type PackageInventory struct {
	Distro         string     `json:"distro"`
	DistroRelease  string     `json:"distro_release"`
	PackageManager string     `json:"package_manager"`
	Software       []Software `json:"software"`
}

// CollectPackages gathers only the package inventory.
func CollectPackages() PackageInventory {
	inv := PackageInventory{PackageManager: packageManager()}
	inv.Distro, inv.DistroRelease = osReleaseIdentity()
	inv.Software = collectPackages(inv.PackageManager)
	return inv
}
