package sca

import (
	"context"
	"strings"
	"testing"

	"defendsec/internal/posture"
	"defendsec/packs"
)

func TestPostureChecksReadTheCollectedReport(t *testing.T) {
	pack := &Pack{ID: "p", Checks: []Check{
		{ID: "enc", Type: "posture", Probe: posture.WinBitLocker},
		{ID: "fw", Type: "posture", Probe: posture.WinFirewall},
		{ID: "uac", Type: "posture", Probe: posture.WinUAC},
		{ID: "smb", Type: "posture", Probe: posture.WinSMB1},
	}}
	h := &Host{Posture: posture.Report{
		posture.WinBitLocker: {Probe: posture.WinBitLocker, State: posture.Pass, Detail: "on"},
		posture.WinFirewall:  {Probe: posture.WinFirewall, State: posture.Fail, Detail: "off"},
		posture.WinUAC:       {Probe: posture.WinUAC, State: posture.Unknown, Detail: "no registry"},
	}}
	got := map[string]Result{}
	for _, r := range h.EvalPack(context.Background(), pack) {
		got[r.CheckID] = r
	}
	if len(got) != 2 {
		t.Fatalf("unknown and uncollected probes must yield no result; got %v", got)
	}
	if !got["enc"].Pass || got["fw"].Pass || got["fw"].Detail != "off" {
		t.Errorf("results: %+v", got)
	}
}

func TestPostureCheckWithUnknownProbeFailsToLoad(t *testing.T) {
	p := &Pack{ID: "p", Checks: []Check{{ID: "x", Type: "posture", Probe: "bitlocker_typo"}}}
	if err := p.validateChecks(); err == nil {
		t.Fatal("a typo'd probe must be refused at load")
	}
}

// The embedded copy is what an installed agent runs; it must match the
// directory, or agents and server disagree about what a check is.
func TestEmbeddedPacksMatchTheDirectory(t *testing.T) {
	onDisk, err := LoadDir(PacksDir())
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := loadFS(packs.SCA, "sca", "embedded")
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != len(embedded) {
		t.Fatalf("%d packs on disk, %d embedded", len(onDisk), len(embedded))
	}
	for i := range onDisk {
		if onDisk[i].ID != embedded[i].ID || len(onDisk[i].Checks) != len(embedded[i].Checks) {
			t.Errorf("pack %d differs: %s vs %s", i, onDisk[i].ID, embedded[i].ID)
		}
	}
}

func TestDistroFamily(t *testing.T) {
	for _, c := range []struct{ id, like, want string }{
		{"ubuntu", "debian", "ubuntu"},
		{"debian", "", "debian"},
		{"fedora", "", "fedora"},
		{"rhel", "fedora", "rhel"},
		{"rocky", "rhel centos fedora", "rhel"},
		{"almalinux", "rhel centos fedora", "rhel"},
		{"opensuse-leap", "suse opensuse", "opensuse"},
		{"opensuse-tumbleweed", "opensuse suse", "opensuse"},
		{"linuxmint", "ubuntu debian", "ubuntu"},
		{"arch", "", ""},
	} {
		if got := DistroFamily(c.id, c.like); got != c.want {
			t.Errorf("%s/%s = %q, want %q", c.id, c.like, got, c.want)
		}
	}
}

// Every shipped Linux pack must give each supported distro a sensible
// check set: no distro left with a package name that does not exist there.
func TestDistroScopedChecks(t *testing.T) {
	packs, err := LoadDir(PacksDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, distro := range Distros {
		var auditPkgs []string
		for _, p := range packs {
			for _, c := range p.Checks {
				if c.appliesTo(distro) && c.Type == "package" && c.Present != nil && *c.Present && strings.Contains(c.Title, "audit") {
					auditPkgs = append(auditPkgs, c.Package)
				}
			}
		}
		want := map[string]string{"ubuntu": "auditd", "debian": "auditd", "fedora": "audit", "rhel": "audit", "opensuse": "audit"}[distro]
		if len(auditPkgs) != 1 || auditPkgs[0] != want {
			t.Errorf("%s audit package checks = %v, want [%s]", distro, auditPkgs, want)
		}
	}
	if (&Pack{ID: "p", Checks: []Check{{ID: "x", Type: "sysctl", Key: "a", Expect: "1", Distros: []string{"arch"}}}}).validateChecks() == nil {
		t.Error("an unknown distro must fail to load")
	}
}

func TestEvalPackSkipsOtherDistros(t *testing.T) {
	pack := &Pack{ID: "p", Checks: []Check{
		{ID: "everywhere", Type: "sysctl", Key: "kernel.x", Expect: "1"},
		{ID: "rpm-only", Type: "sysctl", Key: "kernel.y", Expect: "1", Distros: []string{"fedora", "rhel"}},
	}}
	got := map[string]bool{}
	for _, r := range (&Host{Root: t.TempDir(), Distro: "ubuntu"}).EvalPack(context.Background(), pack) {
		got[r.CheckID] = true
	}
	if !got["everywhere"] || got["rpm-only"] {
		t.Errorf("results %v", got)
	}
}
