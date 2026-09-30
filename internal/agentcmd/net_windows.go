package agentcmd

import (
	"os"

	"golang.org/x/sys/windows"
)

func isolateDescription() string {
	return "network isolated with Windows Firewall: only the control plane is reachable"
}

// privileged is an elevated token; the service runs as LocalSystem.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

func applyNetIsolate(dir string) error {
	ep, err := resolveControlPlane(lookupHost)
	if err != nil {
		return err
	}
	// Record the profiles first: release must put back exactly what was
	// there, including a firewall that was off. Not when already isolated:
	// the current profiles are then the isolated ones, and recording them
	// would make release restore isolation.
	if len(readSaved(dir).WindowsProfiles) == 0 {
		out, err := runCmd([]string{"netsh", "advfirewall", "show", "allprofiles"})
		if err != nil {
			return err
		}
		if err := writeSaved(dir, isolateSaved{WindowsProfiles: parseWindowsProfiles(out)}); err != nil {
			return err
		}
	}
	// Drop our own rules first, so a repeated isolate does not stack
	// duplicates (netsh allows several rules with one name).
	for _, name := range []string{winRuleAllow, winRuleIn} {
		_, _ = runCmd([]string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + name})
	}
	for _, c := range windowsIsolateCommands(ep) {
		if _, err := runCmd(c); err != nil {
			_ = clearNetIsolate(dir) // do not leave a half-isolated host
			return err
		}
	}
	return nil
}

func clearNetIsolate(dir string) error {
	var firstErr error
	for i, c := range windowsReleaseCommands(readSaved(dir).WindowsProfiles) {
		// Deleting a rule that is not there fails; that is not an error here.
		if _, err := runCmd(c); err != nil && i >= 2 && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		_ = os.Remove(savedPath(dir))
	}
	return firstErr
}
