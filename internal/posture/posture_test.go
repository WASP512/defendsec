package posture

import (
	"os"
	"strings"
	"testing"
)

const winHealthy = "\uFEFF" + `{"os":{"caption":"Microsoft Windows 11 Pro","version":"10.0.22631","build":"22631","totalMemoryKb":16777216,"uptimeSeconds":3600},
"serial":"ABC123","model":"LENOVO 20XW",
"bitlocker":{"protectionStatus":"On","volumeStatus":"FullyEncrypted","encryptionPercentage":100},
"defender":{"amServiceEnabled":true,"antivirusEnabled":true,"realTimeProtectionEnabled":true,"signatureAgeDays":0,"tamperProtected":true},
"firewall":[{"name":"Domain","enabled":"True"},{"name":"Private","enabled":"True"},{"name":"Public","enabled":"True"}],
"smb1":false,"enableLua":1,"rdpDenied":1,"rdpNla":1,
"software":[{"name":"7-Zip","version":"23.01"},{"name":"7-Zip","version":"23.01"},{"name":"Git","version":"2.45"}]}`

func TestParseWindowsHealthy(t *testing.T) {
	rep, facts, err := ParseWindows([]byte(winHealthy))
	if err != nil {
		t.Fatal(err)
	}
	for id, f := range rep {
		if f.State != Pass {
			t.Errorf("%s = %v (%s), want pass", id, f.State, f.Detail)
		}
	}
	if len(rep) != 9 {
		t.Errorf("got %d probes, want 9", len(rep))
	}
	if facts.MemoryMb != 16384 || facts.OSName != "Microsoft Windows 11 Pro" || facts.Serial != "ABC123" {
		t.Errorf("facts: %+v", facts)
	}
	if facts.DiskEncryption == nil || !*facts.DiskEncryption || facts.Firewall == nil || !*facts.Firewall {
		t.Error("inventory booleans should be true")
	}
	if len(facts.Software) != 2 {
		t.Errorf("software not de-duplicated: %v", facts.Software)
	}
}

// A suspended BitLocker volume is fully encrypted and unprotected.
func TestParseWindowsSuspendedBitLockerFails(t *testing.T) {
	raw := `{"bitlocker":{"protectionStatus":"Off","volumeStatus":"FullyEncrypted","encryptionPercentage":100}}`
	rep, facts, err := ParseWindows([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if rep[WinBitLocker].State != Fail || !strings.Contains(rep[WinBitLocker].Detail, "100%") {
		t.Errorf("bitlocker: %+v", rep[WinBitLocker])
	}
	if facts.DiskEncryption == nil || *facts.DiskEncryption {
		t.Error("disk encryption should be reported false")
	}
}

// PowerShell emits a single profile as an object, not an array.
func TestParseWindowsSingleFirewallProfileObject(t *testing.T) {
	rep, _, err := ParseWindows([]byte(`{"firewall":{"name":"Public","enabled":"False"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if f := rep[WinFirewall]; f.State != Fail || !strings.Contains(f.Detail, "Public") {
		t.Errorf("firewall: %+v", f)
	}
}

// Missing cmdlets are Unknown, never Fail and never Pass.
func TestParseWindowsMissingSectionsAreUnknown(t *testing.T) {
	raw := `{"bitlockerError":"The term 'Get-BitLockerVolume' is not recognized","defenderError":"Invalid class"}`
	rep, facts, err := ParseWindows([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{WinBitLocker, WinDefenderAV, WinDefenderRealtime, WinDefenderTamper, WinDefenderSignatures, WinFirewall, WinSMB1, WinUAC, WinRDPNLA} {
		if rep[id].State != Unknown {
			t.Errorf("%s = %v, want unknown", id, rep[id].State)
		}
	}
	if !strings.Contains(rep[WinBitLocker].Detail, "not recognized") {
		t.Errorf("error not carried: %q", rep[WinBitLocker].Detail)
	}
	if facts.DiskEncryption != nil || facts.Firewall != nil {
		t.Error("unknown must stay nil in inventory")
	}
}

func TestParseWindowsRiskySettings(t *testing.T) {
	raw := `{"defender":{"amServiceEnabled":true,"antivirusEnabled":true,"realTimeProtectionEnabled":false,"signatureAgeDays":9,"tamperProtected":false},
"smb1":true,"enableLua":0,"rdpDenied":0,"rdpNla":0}`
	rep, _, err := ParseWindows([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{WinDefenderRealtime, WinDefenderSignatures, WinDefenderTamper, WinSMB1, WinUAC, WinRDPNLA} {
		if rep[id].State != Fail {
			t.Errorf("%s = %v, want fail", id, rep[id].State)
		}
	}
	if rep[WinDefenderAV].State != Pass {
		t.Error("AV itself is on")
	}
}

func TestParseWindowsRejectsGarbage(t *testing.T) {
	if _, _, err := ParseWindows([]byte("Get-MpComputerStatus : access denied")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseWindowsUpdates(t *testing.T) {
	ups, err := ParseWindowsUpdates([]byte(`{"title":"2024-06 Cumulative Update","kb":"5039212"}`))
	if err != nil || len(ups) != 1 || ups[0].Available != "KB5039212" {
		t.Errorf("single: %+v %v", ups, err)
	}
	ups, err = ParseWindowsUpdates([]byte(""))
	if err != nil || ups != nil {
		t.Errorf("empty: %+v %v", ups, err)
	}
}

// Output of WindowsScript itself, run by PowerShell 7 on Linux where none of
// the Windows cmdlets or registry keys exist. It proves the script parses,
// isolates each failing section, and still emits JSON the parser accepts —
// with every probe Unknown rather than a guess.
func TestWindowsScriptOutputWithNoCmdlets(t *testing.T) {
	raw, err := os.ReadFile("testdata/windows-script-no-cmdlets.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, _, err := ParseWindows(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range Probes["windows"] {
		if rep[id].State != Unknown {
			t.Errorf("%s = %v, want unknown", id, rep[id].State)
		}
	}
}
