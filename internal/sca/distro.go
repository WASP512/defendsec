package sca

import (
	"bufio"
	"os"
	"strings"
)

// Distros are the Linux families DefendSec supports.
var Distros = []string{"ubuntu", "debian", "fedora", "rhel", "opensuse"}

// KnownDistro reports whether d is one of Distros.
func KnownDistro(d string) bool {
	for _, x := range Distros {
		if x == d {
			return true
		}
	}
	return false
}

// DistroFamily maps os-release ID and ID_LIKE onto a family. Ubuntu is
// checked before Debian because Ubuntu's ID_LIKE is "debian"; RHEL rebuilds
// (Rocky, Alma, CentOS Stream) are rhel. Returns "" for anything else.
func DistroFamily(id, idLike string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	fields := append([]string{id}, strings.Fields(strings.ToLower(idLike))...)
	has := func(names ...string) bool {
		for _, f := range fields {
			for _, n := range names {
				if f == n || strings.HasPrefix(f, n+"-") {
					return true
				}
			}
		}
		return false
	}
	switch {
	case id == "ubuntu":
		return "ubuntu"
	case id == "debian":
		return "debian"
	case id == "fedora":
		return "fedora"
	case has("rhel", "centos", "rocky", "almalinux"):
		return "rhel"
	case has("opensuse", "suse", "sles", "sled"):
		return "opensuse"
	case has("ubuntu"):
		return "ubuntu"
	case has("debian"):
		return "debian"
	case has("fedora"):
		return "fedora"
	}
	return ""
}

// distro reads the host's family from os-release under its root.
func (h *Host) distro() string {
	if h.Distro != "" {
		return h.Distro
	}
	f, err := os.Open(h.resolve("/etc/os-release"))
	if err != nil {
		return ""
	}
	defer f.Close()
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	return DistroFamily(kv["ID"], kv["ID_LIKE"])
}

// appliesTo reports whether a check applies to this host's distro. A host
// whose family cannot be determined runs only distro-neutral checks.
func (c Check) appliesTo(distro string) bool {
	if len(c.Distros) == 0 {
		return true
	}
	for _, d := range c.Distros {
		if d == distro {
			return true
		}
	}
	return false
}
