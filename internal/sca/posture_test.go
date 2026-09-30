package sca

import (
	"context"
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
