package posture

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// macOS probe ids. These are what packs/sca/macos-posture-v1.yaml names.
const (
	MacFileVault       = "filevault_enabled"
	MacFirewall        = "application_firewall_enabled"
	MacStealth         = "firewall_stealth_mode"
	MacSIP             = "system_integrity_protection"
	MacGatekeeper      = "gatekeeper_enabled"
	MacXProtect        = "xprotect_present"
	MacSecurityUpdates = "security_data_auto_install"
	MacAutoLogin       = "automatic_login_disabled"
)

// MacCommand is one output a macOS collector gathers. Out is what the tool
// printed; Err is set when it could not be run at all, which is different
// from it running and reporting something unwelcome.
type MacCommand struct {
	Out  string
	Exit int
	Err  string
}

func (c MacCommand) ran() bool { return c.Err == "" }

// MacInputs is everything the macOS parser reads. Collection fills it by
// running the tools named on each field; tests fill it from captured output.
type MacInputs struct {
	FDESetup   MacCommand // fdesetup status
	Firewall   MacCommand // socketfilterfw --getglobalstate
	Stealth    MacCommand // socketfilterfw --getstealthmode
	CSRUtil    MacCommand // csrutil status
	Spctl      MacCommand // spctl --status
	XProtect   MacCommand // defaults read <XProtect.bundle>/Contents/Info CFBundleShortVersionString
	ConfigData MacCommand // defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall
	Critical   MacCommand // defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall
	AutoLogin  MacCommand // defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser
	SwVers     MacCommand // sw_vers
	MemSize    MacCommand // sysctl -n hw.memsize
	Model      MacCommand // sysctl -n hw.model
	BootTime   MacCommand // sysctl -n kern.boottime
	NowUnix    int64
}

var (
	fwStateRe = regexp.MustCompile(`\(State = (\d)\)`)
	bootSecRe = regexp.MustCompile(`sec = (\d+)`)
)

// ParseMac turns collected macOS tool output into findings and facts.
func ParseMac(in MacInputs) (Report, Facts) {
	rep := Report{}
	var facts Facts

	// FileVault. "Encryption in progress" is not yet protection; "Off" with
	// decryption in progress is the reverse. Only a plain "On" passes.
	switch out := strings.TrimSpace(in.FDESetup.Out); {
	case !in.FDESetup.ran():
		rep.add(Finding{MacFileVault, Unknown, in.FDESetup.Err})
	case strings.HasPrefix(out, "FileVault is On") && !strings.Contains(out, "in progress"):
		rep.add(Finding{MacFileVault, Pass, "FileVault is on."})
	case strings.HasPrefix(out, "FileVault is On"):
		rep.add(Finding{MacFileVault, Fail, "FileVault encryption is still in progress: " + firstLine(out)})
	case strings.HasPrefix(out, "FileVault is Off"):
		rep.add(Finding{MacFileVault, Fail, "FileVault is off; the disk is readable by anyone holding the machine."})
	default:
		rep.add(Finding{MacFileVault, Unknown, "Unrecognised fdesetup output: " + firstLine(out)})
	}
	facts.DiskEncryption = stateFrom(rep[MacFileVault])

	// Application firewall. State 1 is on, 2 is on and blocking everything;
	// 0 is off. The trailing state number is stable across releases where
	// the prose in front of it is not.
	switch m := fwStateRe.FindStringSubmatch(in.Firewall.Out); {
	case !in.Firewall.ran():
		rep.add(Finding{MacFirewall, Unknown, in.Firewall.Err})
	case m != nil && m[1] != "0":
		rep.add(Finding{MacFirewall, Pass, "The application firewall is on."})
	case m != nil || strings.Contains(in.Firewall.Out, "disabled"):
		rep.add(Finding{MacFirewall, Fail, "The application firewall is off."})
	case strings.Contains(in.Firewall.Out, "enabled"):
		rep.add(Finding{MacFirewall, Pass, "The application firewall is on."})
	default:
		rep.add(Finding{MacFirewall, Unknown, "Unrecognised socketfilterfw output: " + firstLine(in.Firewall.Out)})
	}
	facts.Firewall = stateFrom(rep[MacFirewall])

	switch out := strings.ToLower(in.Stealth.Out); {
	case !in.Stealth.ran():
		rep.add(Finding{MacStealth, Unknown, in.Stealth.Err})
	case strings.Contains(out, "stealth mode is on") || strings.Contains(out, "stealth mode enabled"):
		rep.add(Finding{MacStealth, Pass, "Stealth mode is on."})
	case strings.Contains(out, "stealth mode is off") || strings.Contains(out, "stealth mode disabled"):
		rep.add(Finding{MacStealth, Fail, "Stealth mode is off; the host answers probes on closed ports."})
	default:
		rep.add(Finding{MacStealth, Unknown, "Unrecognised stealth-mode output: " + firstLine(in.Stealth.Out)})
	}

	// SIP. A custom configuration ("enabled" followed by a list with some
	// protections disabled) is a failure: it is how SIP is partially
	// switched off, and it still prints the word enabled.
	switch out := in.CSRUtil.Out; {
	case !in.CSRUtil.ran():
		rep.add(Finding{MacSIP, Unknown, in.CSRUtil.Err})
	case strings.Contains(out, "status: enabled") && !strings.Contains(out, ": disabled"):
		rep.add(Finding{MacSIP, Pass, "System Integrity Protection is on."})
	case strings.Contains(out, "status: enabled"):
		rep.add(Finding{MacSIP, Fail, "System Integrity Protection has a custom configuration with protections disabled."})
	case strings.Contains(out, "status: disabled"):
		rep.add(Finding{MacSIP, Fail, "System Integrity Protection is off."})
	default:
		rep.add(Finding{MacSIP, Unknown, "Unrecognised csrutil output: " + firstLine(out)})
	}

	switch out := strings.TrimSpace(in.Spctl.Out); {
	case !in.Spctl.ran():
		rep.add(Finding{MacGatekeeper, Unknown, in.Spctl.Err})
	case out == "assessments enabled":
		rep.add(Finding{MacGatekeeper, Pass, "Gatekeeper is on."})
	case out == "assessments disabled":
		rep.add(Finding{MacGatekeeper, Fail, "Gatekeeper is off; unsigned applications run without warning."})
	default:
		rep.add(Finding{MacGatekeeper, Unknown, "Unrecognised spctl output: " + firstLine(out)})
	}

	// XProtect: present with a version. DefendSec does not know Apple's
	// current version, so it reports what is there rather than guessing
	// whether it is the latest; security_data_auto_install covers updates.
	switch v := strings.TrimSpace(in.XProtect.Out); {
	case !in.XProtect.ran():
		rep.add(Finding{MacXProtect, Unknown, in.XProtect.Err})
	case in.XProtect.Exit == 0 && v != "":
		rep.add(Finding{MacXProtect, Pass, "XProtect " + v + " is installed."})
	default:
		rep.add(Finding{MacXProtect, Fail, "The XProtect bundle is missing."})
	}

	// Security data updates. These keys are absent unless someone has
	// changed them, and absent means Apple's default: on. "defaults read"
	// exits 1 for a missing key.
	rep.add(macAutoInstall(in.ConfigData, in.Critical))

	// Automatic login: the key existing is the failure.
	switch {
	case !in.AutoLogin.ran():
		rep.add(Finding{MacAutoLogin, Unknown, in.AutoLogin.Err})
	case in.AutoLogin.Exit == 0 && strings.TrimSpace(in.AutoLogin.Out) != "":
		rep.add(Finding{MacAutoLogin, Fail, fmt.Sprintf("Automatic login is enabled for %q; FileVault is bypassed at boot.", strings.TrimSpace(in.AutoLogin.Out))})
	default:
		rep.add(Finding{MacAutoLogin, Pass, "Automatic login is disabled."})
	}

	// Facts.
	for _, line := range strings.Split(in.SwVers.Out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ProductName":
			facts.OSName = strings.TrimSpace(v)
		case "ProductVersion":
			facts.OSVersion = strings.TrimSpace(v)
		}
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(in.MemSize.Out), 10, 64); err == nil {
		facts.MemoryMb = n / (1024 * 1024)
	}
	facts.HardwareModel = strings.TrimSpace(in.Model.Out)
	if m := bootSecRe.FindStringSubmatch(in.BootTime.Out); m != nil && in.NowUnix > 0 {
		if boot, err := strconv.ParseInt(m[1], 10, 64); err == nil && boot <= in.NowUnix {
			facts.UptimeSeconds = in.NowUnix - boot
		}
	}
	return rep, facts
}

func macAutoInstall(configData, critical MacCommand) Finding {
	off := []string{}
	for name, c := range map[string]MacCommand{"ConfigDataInstall": configData, "CriticalUpdateInstall": critical} {
		if !c.ran() {
			return Finding{MacSecurityUpdates, Unknown, c.Err}
		}
		if c.Exit == 0 && strings.TrimSpace(c.Out) == "0" {
			off = append(off, name)
		}
	}
	if len(off) == 0 {
		return Finding{MacSecurityUpdates, Pass, "XProtect and security data updates install automatically."}
	}
	if len(off) == 2 {
		off = []string{"ConfigDataInstall", "CriticalUpdateInstall"}
	}
	return Finding{MacSecurityUpdates, Fail, "Automatic installation is switched off (" + strings.Join(off, ", ") + "); XProtect definitions will go stale."}
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
