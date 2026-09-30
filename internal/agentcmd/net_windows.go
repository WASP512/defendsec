package agentcmd

import "golang.org/x/sys/windows"

const isolateDescription = "network isolated with Windows Firewall: only the control plane is reachable"

// privileged is an elevated token; the service runs as LocalSystem.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

func applyNetIsolate(dir string) error {
	ep, err := resolveControlPlane(lookupHost)
	if err != nil {
		return err
	}
	// Record the profiles first: release must put back exactly what was
	// there, including a firewall that was off.
	out, err := runCmd([]string{"netsh", "advfirewall", "show", "allprofiles"})
	if err != nil {
		return err
	}
	if err := writeSaved(dir, isolateSaved{WindowsProfiles: parseWindowsProfiles(out)}); err != nil {
		return err
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
	return firstErr
}
