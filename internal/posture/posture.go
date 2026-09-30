// Package posture checks the security posture of Windows and macOS hosts
// (roadmap 5.1, 5.2): disk encryption, antivirus, firewall, and the platform
// protections an auditor asks about first.
//
// # Parsers are pure; collection is not
//
// Every check is split into running a native tool and parsing what it
// printed. The parsers are ordinary functions over captured output and are
// tested on Linux against real-world samples, which is the only way this code
// is exercised in DefendSec's CI. The collectors that run the tools are small
// and build-tagged by nothing — they check runtime.GOOS — so the same code is
// compiled for every platform and a Windows-only typo still fails the build.
//
// # Unknown is not a failure
//
// A probe that cannot run — a cmdlet missing on a Home edition, a tool that
// needs root — reports Unknown with the reason, and Unknown produces no SCA
// result at all. Reporting it as a failure would raise alerts about checks
// that never ran; reporting it as a pass would claim evidence nobody has.
// Missing evidence shows up in the compliance view as missing evidence.
package posture

// State is a probe's outcome.
type State int

const (
	Unknown State = iota
	Fail
	Pass
)

func (s State) String() string {
	switch s {
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	default:
		return "unknown"
	}
}

// Finding is one probe's result.
type Finding struct {
	Probe  string
	State  State
	Detail string
}

// Report is every probe run on a host, keyed by probe id.
type Report map[string]Finding

func (r Report) add(f Finding) { r[f.Probe] = f }

// Facts are inventory values collected alongside posture, where the same
// tool invocation yields both.
type Facts struct {
	OSName        string
	OSVersion     string
	MemoryMb      int64
	UptimeSeconds int64
	Serial        string
	HardwareModel string
	// DiskEncryption and Firewall feed the two fixed inventory fields the
	// server already understands; nil means unknown.
	DiskEncryption *bool
	Firewall       *bool
	Software       []Software
}

// Software is one installed application.
type Software struct {
	Name    string
	Version string
}

func boolPtr(b bool) *bool { return &b }

// stateFrom maps a finding to the tri-state inventory fields.
func stateFrom(f Finding) *bool {
	switch f.State {
	case Pass:
		return boolPtr(true)
	case Fail:
		return boolPtr(false)
	default:
		return nil
	}
}

// Probes lists every probe id, per platform.
var Probes = map[string][]string{
	"windows": {WinBitLocker, WinDefenderAV, WinDefenderRealtime, WinDefenderSignatures,
		WinDefenderTamper, WinFirewall, WinSMB1, WinUAC, WinRDPNLA},
	"darwin": {MacFileVault, MacFirewall, MacStealth, MacSIP, MacGatekeeper,
		MacXProtect, MacSecurityUpdates, MacAutoLogin},
}

// KnownProbe reports whether id names a probe on any platform.
func KnownProbe(id string) bool {
	for _, ids := range Probes {
		for _, p := range ids {
			if p == id {
				return true
			}
		}
	}
	return false
}
