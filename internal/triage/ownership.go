// Package triage explains alerts by correlating DefendSec's own records
// (roadmap 4.3).
//
// # No model is involved
//
// The roadmap lists this under the AI control plane, and it would have been
// easy to make it a prompt. It is deterministic correlation instead, for two
// reasons. A timeline join is exactly right for the question being asked —
// "was this file rewritten by a package upgrade?" has a factual answer in
// stored data — and a self-hosted security product that needs an outbound API
// call to triage an alert is one that stops triaging when the network is the
// thing under attack.
//
// The output is also meant to be *read by* an agent, through the MCP surface.
// Handing a model a correlated timeline is more useful than handing it raw
// rows and hoping, and it means the explanation an operator sees in the
// console and the one an agent reasons over are the same explanation.
//
// # What a correlation proves
//
// Less than it looks like. A package upgrade immediately before a
// configuration file changes is a strong ordinary explanation, and it is also
// precisely the cover an attacker would choose. So this package explains and
// never resolves: see Explanation.
package triage

import (
	"path/filepath"
	"sort"
	"strings"
)

// Path ownership.
//
// On Linux the authoritative answer is the package manager's own — `dpkg -S`
// or `rpm -qf` — which DefendSec does not ask for today: it would need a new
// agent capability and a protocol field, and it is worth doing later.
//
// Until then this is a curated map covering the paths DefendSec watches by
// default, which is a short and stable list. The important property is what
// it does for anything else: it returns no owner rather than guessing from
// the path, and every explanation carries whether ownership was known. A
// wrong owner would produce a confident explanation of the wrong thing, which
// is worse than no explanation.
var pathOwners = map[string][]string{
	"/etc/ssh/sshd_config":        {"openssh-server", "openssh"},
	"/etc/ssh/sshd_config.d":      {"openssh-server", "openssh"},
	"/etc/ssh/ssh_config":         {"openssh-client", "openssh-clients", "openssh"},
	"/etc/sudoers":                {"sudo"},
	"/etc/sudoers.d":              {"sudo"},
	"/etc/passwd":                 {"passwd", "shadow-utils", "base-passwd"},
	"/etc/group":                  {"passwd", "shadow-utils", "base-passwd"},
	"/etc/shadow":                 {"passwd", "shadow-utils", "base-passwd"},
	"/etc/crypto-policies/config": {"crypto-policies"},
	"/etc/pam.d":                  {"pam", "libpam-runtime", "pam-configs"},
	"/etc/login.defs":             {"shadow-utils", "login", "passwd"},
	"/etc/nsswitch.conf":          {"glibc", "libc-bin", "libc6"},
	"/etc/audit/auditd.conf":      {"audit", "auditd"},
	"/etc/audit/rules.d":          {"audit", "auditd"},
	"/etc/systemd/system.conf":    {"systemd"},
	"/etc/chrony.conf":            {"chrony"},
	"/etc/ntp.conf":               {"ntp"},
	"/etc/fstab":                  {"util-linux", "mount"},
	"/etc/selinux/config":         {"selinux-policy", "libselinux"},
	"/etc/default/grub":           {"grub2-common", "grub-common"},
	"/etc/docker/daemon.json":     {"docker", "docker-ce", "docker.io"},
	"/etc/kubernetes/manifests":   {"kubelet", "kubernetes-node"},
}

// unownedPaths are watched paths that genuinely belong to no package. Listed
// explicitly so "no owner" can mean "nothing owns this" rather than "nobody
// has filled in the table", which are very different facts for a reader.
var unownedPaths = map[string]string{
	"/etc/hosts":       "Managed locally or by the network configuration, not by a package. A change here is a local edit by definition.",
	"/etc/resolv.conf": "Usually rewritten by the resolver or DHCP client rather than owned by a package.",
	"/etc/hostname":    "Set locally; no package rewrites it.",
	"/etc/machine-id":  "Generated at install; no package rewrites it.",
}

// Ownership is what is known about which package owns a path.
type Ownership struct {
	Path string `json:"path"`
	// Packages are the candidate owners. Several, because the same file is
	// owned by differently-named packages across distributions and DefendSec
	// does not know which one this host uses.
	Packages []string `json:"packages,omitempty"`
	// Known is false when the path is not in the curated map. An explanation
	// built on unknown ownership says so rather than implying a lookup
	// happened.
	Known bool `json:"known"`
	// Unowned is true for a path that belongs to no package at all, which is
	// a different and stronger fact than ownership merely being unknown: it
	// means a package upgrade cannot be the explanation.
	Unowned bool `json:"unowned"`
	// Note explains an unowned path.
	Note string `json:"note,omitempty"`
}

// OwnersOf resolves a watched path to its candidate owning packages.
//
// A path under a watched directory resolves to that directory's owner, so
// /etc/ssh/sshd_config.d/99-hardening.conf is attributed to openssh-server.
func OwnersOf(path string) Ownership {
	path = strings.TrimSpace(path)
	if path == "" {
		return Ownership{Path: path}
	}
	clean := filepath.Clean(path)

	if note, ok := unownedPaths[clean]; ok {
		return Ownership{Path: path, Known: true, Unowned: true, Note: note}
	}
	if pkgs, ok := pathOwners[clean]; ok {
		return Ownership{Path: path, Packages: pkgs, Known: true}
	}

	// Walk up to a watched directory. A drop-in file under a config directory
	// is owned by whatever owns the directory.
	for dir := filepath.Dir(clean); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if note, ok := unownedPaths[dir]; ok {
			return Ownership{Path: path, Known: true, Unowned: true, Note: note}
		}
		if pkgs, ok := pathOwners[dir]; ok {
			return Ownership{Path: path, Packages: pkgs, Known: true}
		}
	}
	return Ownership{Path: path}
}

// KnownOwnedPaths lists the paths the curated map covers, so the coverage of
// this mechanism can be reported rather than assumed.
func KnownOwnedPaths() []string {
	out := make([]string, 0, len(pathOwners)+len(unownedPaths))
	for p := range pathOwners {
		out = append(out, p)
	}
	for p := range unownedPaths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
