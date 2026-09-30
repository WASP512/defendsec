package posture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// ErrUnsupported is returned on platforms whose posture this package does not
// collect. Linux posture is covered by the SCA packs directly.
var ErrUnsupported = errors.New("posture: no collector for this platform")

// Collect runs the native tools for this platform.
func Collect(ctx context.Context) (Report, Facts, error) {
	switch runtime.GOOS {
	case "windows":
		return collectWindows(ctx)
	case "darwin":
		rep, facts := ParseMac(collectMac(ctx))
		return rep, facts, nil
	default:
		return nil, Facts{}, ErrUnsupported
	}
}

func collectWindows(ctx context.Context) (Report, Facts, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	// Windows PowerShell 5.1 is present on every supported Windows; pwsh is
	// not. -NoProfile so a user's profile cannot alter what is reported.
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", WindowsScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, Facts{}, fmt.Errorf("posture script: %w: %s", err, firstLine(stderr.String()))
	}
	return ParseWindows(stdout.Bytes())
}

// XProtectInfo is the plist defaults reads XProtect's version from. The path
// moved in macOS 11; both are tried.
var xprotectInfos = []string{
	"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info",
	"/System/Library/CoreServices/XProtect.bundle/Contents/Info",
}

func collectMac(ctx context.Context) MacInputs {
	run := func(name string, args ...string) MacCommand {
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(c, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return MacCommand{Out: string(out)}
		case errors.As(err, &exit):
			return MacCommand{Out: string(out), Exit: exit.ExitCode()}
		default:
			return MacCommand{Err: fmt.Sprintf("%s could not be run: %v", name, err)}
		}
	}
	const sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	in := MacInputs{
		FDESetup:   run("/usr/bin/fdesetup", "status"),
		Firewall:   run(sfw, "--getglobalstate"),
		Stealth:    run(sfw, "--getstealthmode"),
		CSRUtil:    run("/usr/bin/csrutil", "status"),
		Spctl:      run("/usr/sbin/spctl", "--status"),
		ConfigData: run("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"),
		Critical:   run("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"),
		AutoLogin:  run("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"),
		SwVers:     run("/usr/bin/sw_vers"),
		MemSize:    run("/usr/sbin/sysctl", "-n", "hw.memsize"),
		Model:      run("/usr/sbin/sysctl", "-n", "hw.model"),
		BootTime:   run("/usr/sbin/sysctl", "-n", "kern.boottime"),
		NowUnix:    time.Now().Unix(),
	}
	for _, p := range xprotectInfos {
		if _, err := os.Stat(p + ".plist"); err == nil {
			in.XProtect = run("/usr/bin/defaults", "read", p, "CFBundleShortVersionString")
			break
		}
		in.XProtect = MacCommand{Exit: 1}
	}
	return in
}

// Inventory is what the non-posture half of a Windows or macOS report needs.
type Inventory struct {
	Software []Software
	Updates  []Update
	// UpdateStatus mirrors the Linux collector's values: ok, error, unsupported.
	UpdateStatus string
}

// CollectInventory gathers software (macOS only; Windows software comes with
// the posture script) and pending updates.
func CollectInventory(ctx context.Context) Inventory {
	switch runtime.GOOS {
	case "windows":
		c, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(c, "powershell.exe", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-Command", WindowsUpdateScript).Output()
		if err != nil {
			return Inventory{UpdateStatus: "error"}
		}
		ups, err := ParseWindowsUpdates(out)
		if err != nil {
			return Inventory{UpdateStatus: "error"}
		}
		return Inventory{Updates: ups, UpdateStatus: "ok"}
	case "darwin":
		var inv Inventory
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(c, "/usr/sbin/system_profiler", "-json", "-detailLevel", "mini", "SPApplicationsDataType").Output(); err == nil {
			inv.Software, _ = ParseMacApps(out)
		}
		c2, cancel2 := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel2()
		out, err := exec.CommandContext(c2, "/usr/sbin/softwareupdate", "-l").CombinedOutput()
		if err != nil && len(out) == 0 {
			inv.UpdateStatus = "error"
			return inv
		}
		inv.Updates, inv.UpdateStatus = ParseMacUpdates(string(out)), "ok"
		return inv
	default:
		return Inventory{UpdateStatus: "unsupported"}
	}
}
