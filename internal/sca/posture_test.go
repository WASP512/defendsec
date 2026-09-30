package sca

import (
	"context"
	"testing"

	"defendsec/internal/posture"
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
