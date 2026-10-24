// Package nevra splits RPM file names ("kernel-0:5.14.0-687.59.1.el9_8.x86_64.rpm")
// into their parts. The rebuild distributions' errata feeds (Rocky, AlmaLinux)
// name fixed packages this way.
package nevra

import (
	"errors"
	"fmt"
	"strings"
)

// NEVRA is one RPM's identity.
type NEVRA struct {
	Name    string
	Epoch   string // "0" when the file name carries none
	Version string
	Release string
	Arch    string
}

// EVR is "epoch:version-release", the form Red Hat's OVAL feed uses for a fixed
// version, so a rebuild's range compares and prints the same way as the
// upstream one. The epoch is always written, "0:" included.
func (n NEVRA) EVR() string {
	return n.Epoch + ":" + n.Version + "-" + n.Release
}

// IsSource reports whether the file is a source RPM.
func (n NEVRA) IsSource() bool { return n.Arch == "src" || n.Arch == "nosrc" }

// IsModular reports whether the build belongs to an AppStream module stream
// ("1:18.12.1-1.module+el9.1.0+16755+0e7c4a5f"). The feed parsers skip those: a
// module's package is only relevant when its stream is enabled, and DefendSec
// does not collect enabled streams.
func (n NEVRA) IsModular() bool {
	return strings.Contains(n.Release, ".module+") || strings.Contains(n.Release, ".module_")
}

// Parse reads "name-[epoch:]version-release.arch[.rpm]". Names may contain
// dashes; versions and releases may not, so the split works from the right.
func Parse(s string) (NEVRA, error) {
	orig := s
	s = strings.TrimSuffix(strings.TrimSpace(s), ".rpm")
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 || dot == len(s)-1 {
		return NEVRA{}, fmt.Errorf("nevra %q: no architecture", orig)
	}
	arch := s[dot+1:]
	rest := s[:dot]
	relDash := strings.LastIndexByte(rest, '-')
	if relDash <= 0 {
		return NEVRA{}, fmt.Errorf("nevra %q: no release", orig)
	}
	release := rest[relDash+1:]
	rest = rest[:relDash]
	verDash := strings.LastIndexByte(rest, '-')
	if verDash <= 0 {
		return NEVRA{}, fmt.Errorf("nevra %q: no version", orig)
	}
	name := rest[:verDash]
	ev := rest[verDash+1:]
	epoch, version := "0", ev
	if i := strings.IndexByte(ev, ':'); i >= 0 {
		epoch, version = ev[:i], ev[i+1:]
	}
	if epoch == "" {
		epoch = "0"
	}
	if name == "" || version == "" || release == "" {
		return NEVRA{}, errors.New("nevra " + orig + ": empty field")
	}
	for _, r := range epoch {
		if r < '0' || r > '9' {
			return NEVRA{}, fmt.Errorf("nevra %q: epoch %q is not a number", orig, epoch)
		}
	}
	return NEVRA{Name: name, Epoch: epoch, Version: version, Release: release, Arch: arch}, nil
}

// Join builds a NEVRA from separate fields, as Alma's errata list them.
func Join(name, epoch, version, release, arch string) NEVRA {
	if epoch == "" {
		epoch = "0"
	}
	return NEVRA{Name: name, Epoch: epoch, Version: version, Release: release, Arch: arch}
}
