package posture

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Windows probe ids. These are what packs/sca/windows-posture-v1.yaml names.
const (
	WinBitLocker          = "bitlocker_os_volume"
	WinDefenderAV         = "defender_antivirus_enabled"
	WinDefenderRealtime   = "defender_realtime_protection"
	WinDefenderSignatures = "defender_signatures_current"
	WinDefenderTamper     = "defender_tamper_protection"
	WinFirewall           = "firewall_all_profiles"
	WinSMB1               = "smbv1_disabled"
	WinUAC                = "uac_enabled"
	WinRDPNLA             = "rdp_requires_nla"
)

// MaxSignatureAgeDays is how stale Defender's definitions may be before the
// check fails. Defender updates several times a day when it can reach the
// internet, so three days means updates are not happening rather than that
// one was missed.
const MaxSignatureAgeDays = 3

// WindowsScript collects posture and inventory in one PowerShell process.
//
// Every value is cast in the script — [string] for enums, [bool], [int64] —
// because Windows PowerShell 5.1's ConvertTo-Json serialises enums as bare
// integers and GpoBoolean's NotConfigured as a truthy 2, and a parser
// guessing at those would guess wrong on some edition. Each section is in
// its own try/catch so a missing cmdlet (no BitLocker module on Home, no
// Defender on a server using another AV) reports its error and leaves the
// rest intact.
const WindowsScript = `$ErrorActionPreference = 'Stop'
$r = [ordered]@{}
try {
  $os = Get-CimInstance Win32_OperatingSystem
  $r.os = [ordered]@{
    caption = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber
    totalMemoryKb = [int64]$os.TotalVisibleMemorySize
    uptimeSeconds = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  }
} catch { $r.osError = $_.Exception.Message }
try { $r.serial = [string](Get-CimInstance Win32_BIOS).SerialNumber } catch {}
try { $cs = Get-CimInstance Win32_ComputerSystem; $r.model = ([string]$cs.Manufacturer + ' ' + [string]$cs.Model).Trim() } catch {}
try {
  $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
  $r.bitlocker = [ordered]@{ protectionStatus = [string]$v.ProtectionStatus; volumeStatus = [string]$v.VolumeStatus; encryptionPercentage = [double]$v.EncryptionPercentage }
} catch { $r.bitlockerError = $_.Exception.Message }
try {
  $m = Get-MpComputerStatus
  $r.defender = [ordered]@{
    amServiceEnabled = [bool]$m.AMServiceEnabled; antivirusEnabled = [bool]$m.AntivirusEnabled
    realTimeProtectionEnabled = [bool]$m.RealTimeProtectionEnabled
    signatureAgeDays = [int]$m.AntivirusSignatureAge; tamperProtected = [bool]$m.IsTamperProtected
  }
} catch { $r.defenderError = $_.Exception.Message }
try {
  $r.firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } })
} catch { $r.firewallError = $_.Exception.Message }
try { $r.smb1 = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol } catch { $r.smb1Error = $_.Exception.Message }
try { $r.enableLua = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA } catch { $r.enableLuaError = $_.Exception.Message }
try {
  $r.rdpDenied = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
  $r.rdpNla = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
} catch { $r.rdpError = $_.Exception.Message }
try {
  $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  $r.software = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion } })
} catch { $r.softwareError = $_.Exception.Message }
$r | ConvertTo-Json -Depth 5 -Compress`

// windowsDoc is the script's output shape.
type windowsDoc struct {
	OS *struct {
		Caption       string `json:"caption"`
		Version       string `json:"version"`
		Build         string `json:"build"`
		TotalMemoryKb int64  `json:"totalMemoryKb"`
		UptimeSeconds int64  `json:"uptimeSeconds"`
	} `json:"os"`
	Serial    string `json:"serial"`
	Model     string `json:"model"`
	BitLocker *struct {
		ProtectionStatus     string  `json:"protectionStatus"`
		VolumeStatus         string  `json:"volumeStatus"`
		EncryptionPercentage float64 `json:"encryptionPercentage"`
	} `json:"bitlocker"`
	BitLockerError string `json:"bitlockerError"`
	Defender       *struct {
		AMServiceEnabled          bool `json:"amServiceEnabled"`
		AntivirusEnabled          bool `json:"antivirusEnabled"`
		RealTimeProtectionEnabled bool `json:"realTimeProtectionEnabled"`
		SignatureAgeDays          int  `json:"signatureAgeDays"`
		TamperProtected           bool `json:"tamperProtected"`
	} `json:"defender"`
	DefenderError  string          `json:"defenderError"`
	Firewall       json.RawMessage `json:"firewall"`
	FirewallError  string          `json:"firewallError"`
	SMB1           *bool           `json:"smb1"`
	SMB1Error      string          `json:"smb1Error"`
	EnableLUA      *int            `json:"enableLua"`
	EnableLUAError string          `json:"enableLuaError"`
	RDPDenied      *int            `json:"rdpDenied"`
	RDPNLA         *int            `json:"rdpNla"`
	RDPError       string          `json:"rdpError"`
	Software       json.RawMessage `json:"software"`
}

type fwProfile struct {
	Name    string `json:"name"`
	Enabled string `json:"enabled"`
}

type swItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// oneOrMany decodes a JSON value that PowerShell may have emitted as either a
// single object or an array of them — which it does depending on the count.
func oneOrMany[T any](raw json.RawMessage) ([]T, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, nil
	}
	if strings.HasPrefix(s, "[") {
		var out []T
		err := json.Unmarshal(raw, &out)
		return out, err
	}
	var one T
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []T{one}, nil
}

// ParseWindows turns the script's output into findings and facts.
func ParseWindows(raw []byte) (Report, Facts, error) {
	// PowerShell may prepend a UTF-8 byte order mark.
	raw = []byte(strings.TrimPrefix(string(raw), "\uFEFF"))
	var doc windowsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, Facts{}, fmt.Errorf("parse posture script output: %w", err)
	}
	rep := Report{}
	var facts Facts

	if doc.OS != nil {
		facts.OSName = strings.TrimSpace(doc.OS.Caption)
		facts.OSVersion = doc.OS.Version
		facts.MemoryMb = doc.OS.TotalMemoryKb / 1024
		facts.UptimeSeconds = doc.OS.UptimeSeconds
	}
	facts.Serial = strings.TrimSpace(doc.Serial)
	facts.HardwareModel = strings.TrimSpace(doc.Model)

	// BitLocker. ProtectionStatus "On" is the only pass: a volume that is
	// fully encrypted with protection suspended ("Off") is readable by anyone
	// who boots it, which is exactly what suspension is for.
	switch {
	case doc.BitLocker != nil && strings.EqualFold(doc.BitLocker.ProtectionStatus, "On"):
		rep.add(Finding{WinBitLocker, Pass, fmt.Sprintf("BitLocker protection is on (%s).", doc.BitLocker.VolumeStatus)})
	case doc.BitLocker != nil && strings.EqualFold(doc.BitLocker.ProtectionStatus, "Off"):
		detail := "BitLocker protection is off on the system volume."
		if doc.BitLocker.EncryptionPercentage > 0 {
			detail = fmt.Sprintf("BitLocker protection is off (%s, %.0f%% encrypted). A suspended volume is readable by anyone who boots it.",
				doc.BitLocker.VolumeStatus, doc.BitLocker.EncryptionPercentage)
		}
		rep.add(Finding{WinBitLocker, Fail, detail})
	default:
		rep.add(Finding{WinBitLocker, Unknown, firstNonEmpty(doc.BitLockerError, "BitLocker status could not be read.")})
	}
	facts.DiskEncryption = stateFrom(rep[WinBitLocker])

	// Defender. Absent Defender is Unknown rather than Fail: a server running
	// another antivirus product legitimately has it disabled, and DefendSec
	// cannot see the other product.
	if d := doc.Defender; d != nil {
		rep.add(boolFinding(WinDefenderAV, d.AntivirusEnabled && d.AMServiceEnabled,
			"Microsoft Defender Antivirus is enabled.", "Microsoft Defender Antivirus is disabled."))
		rep.add(boolFinding(WinDefenderRealtime, d.RealTimeProtectionEnabled,
			"Real-time protection is on.", "Real-time protection is off."))
		rep.add(boolFinding(WinDefenderTamper, d.TamperProtected,
			"Tamper protection is on.", "Tamper protection is off, so malware running as administrator can switch Defender off."))
		rep.add(boolFinding(WinDefenderSignatures, d.SignatureAgeDays <= MaxSignatureAgeDays,
			fmt.Sprintf("Definitions are %d day(s) old.", d.SignatureAgeDays),
			fmt.Sprintf("Definitions are %d days old; updates are not arriving.", d.SignatureAgeDays)))
	} else {
		why := firstNonEmpty(doc.DefenderError, "Defender status could not be read.")
		for _, id := range []string{WinDefenderAV, WinDefenderRealtime, WinDefenderTamper, WinDefenderSignatures} {
			rep.add(Finding{id, Unknown, why})
		}
	}

	// Firewall: every profile must be on. One profile off is a firewall off
	// on whichever network type the host is attached to at the time.
	profiles, err := oneOrMany[fwProfile](doc.Firewall)
	switch {
	case err != nil || len(profiles) == 0:
		rep.add(Finding{WinFirewall, Unknown, firstNonEmpty(doc.FirewallError, "Firewall profiles could not be read.")})
	default:
		var off []string
		for _, p := range profiles {
			if !strings.EqualFold(p.Enabled, "True") {
				off = append(off, p.Name)
			}
		}
		if len(off) == 0 {
			rep.add(Finding{WinFirewall, Pass, "Windows Firewall is on for every profile."})
		} else {
			rep.add(Finding{WinFirewall, Fail, "Windows Firewall is off for: " + strings.Join(off, ", ") + "."})
		}
	}
	facts.Firewall = stateFrom(rep[WinFirewall])

	if doc.SMB1 != nil {
		rep.add(boolFinding(WinSMB1, !*doc.SMB1, "SMBv1 is disabled.", "SMBv1 is enabled; it is the protocol WannaCry and NotPetya spread over."))
	} else {
		rep.add(Finding{WinSMB1, Unknown, firstNonEmpty(doc.SMB1Error, "SMB configuration could not be read.")})
	}

	if doc.EnableLUA != nil {
		rep.add(boolFinding(WinUAC, *doc.EnableLUA == 1, "User Account Control is on.", "User Account Control is off; every administrator process runs elevated."))
	} else {
		rep.add(Finding{WinUAC, Unknown, firstNonEmpty(doc.EnableLUAError, "UAC setting could not be read.")})
	}

	// RDP: only a finding when RDP is on. A host with RDP disabled passes,
	// because the risk the check describes does not exist there.
	switch {
	case doc.RDPDenied == nil:
		rep.add(Finding{WinRDPNLA, Unknown, firstNonEmpty(doc.RDPError, "Remote Desktop settings could not be read.")})
	case *doc.RDPDenied == 1:
		rep.add(Finding{WinRDPNLA, Pass, "Remote Desktop is disabled."})
	case doc.RDPNLA != nil && *doc.RDPNLA == 1:
		rep.add(Finding{WinRDPNLA, Pass, "Remote Desktop requires Network Level Authentication."})
	default:
		rep.add(Finding{WinRDPNLA, Fail, "Remote Desktop is enabled without Network Level Authentication, exposing the logon screen to unauthenticated users."})
	}

	items, _ := oneOrMany[swItem](doc.Software)
	seen := map[string]bool{}
	for _, it := range items {
		name := strings.TrimSpace(it.Name)
		key := name + "\x00" + it.Version
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		facts.Software = append(facts.Software, Software{Name: name, Version: strings.TrimSpace(it.Version)})
	}
	return rep, facts, nil
}

func boolFinding(id string, ok bool, passDetail, failDetail string) Finding {
	if ok {
		return Finding{id, Pass, passDetail}
	}
	return Finding{id, Fail, failDetail}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
