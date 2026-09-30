package control

import (
	"testing"

	"defendsec/internal/presence"
)

// Agent-evaluated results for check types other than file_regex — sysctl,
// mount options, file modes, commands, and platform posture — must survive
// the server's merge. They were silently dropped: the merge only carried
// agent results for file_regex checks, so everything added in roadmap 3.7
// was evaluated on the host and then discarded before alerting.
func TestAgentResultsOfEveryCheckTypeSurviveTheMerge(t *testing.T) {
	s := testServer()
	dev := presence.Device{ID: "d", Platform: "linux"}
	agent := []presence.ScaResult{
		{PackID: "sca-linux-cis-v8-ig1", CheckID: "cis-4.1-ip-forward-disabled", Title: "IP forwarding", Severity: "medium", Pass: false},
		{PackID: "windows-posture", CheckID: "bitlocker-os-volume", Title: "BitLocker", Severity: "high", Pass: false},
	}
	merged := s.evaluateSca(dev, agent)
	got := map[string]presence.ScaResult{}
	for _, r := range merged {
		got[r.PackID+"/"+r.CheckID] = r
	}
	for _, want := range agent {
		if _, ok := got[want.PackID+"/"+want.CheckID]; !ok {
			t.Errorf("%s/%s was dropped by the merge", want.PackID, want.CheckID)
		}
	}
}

// A result has to carry the controls its check names, or the alert raised
// from it is tagged only with the generic SCA signal.
func TestMergedResultsCarryTheirChecksControls(t *testing.T) {
	s := testServer()
	dev := presence.Device{ID: "d", Platform: "linux"}
	merged := s.evaluateSca(dev, []presence.ScaResult{
		{PackID: "sca-linux-cis-v8-ig1", CheckID: "cis-4.1-ip-forward-disabled", Pass: false},
	})
	for _, r := range merged {
		if r.CheckID == "cis-4.1-ip-forward-disabled" && len(r.Controls) == 0 {
			t.Error("the result lost the controls its check names")
		}
	}
}
