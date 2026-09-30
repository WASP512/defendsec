package agentcmd

import (
	"os"
	"path/filepath"
)

// pfAnchor sits under com.apple/*, which the stock /etc/pf.conf evaluates,
// so isolation needs no edit to the system's pf configuration.
const pfAnchor = "com.apple/250.DefendSecIsolate"

const isolateDescription = "network isolated with pf: only loopback and the control plane are reachable"

func privileged() bool { return os.Geteuid() == 0 }

func applyNetIsolate(dir string) error {
	ep, err := resolveControlPlane(lookupHost)
	if err != nil {
		return err
	}
	rules := filepath.Join(dir, "pf-isolate.conf")
	if err := os.WriteFile(rules, []byte(pfRules(ep)), 0o600); err != nil {
		return err
	}
	if _, err := runCmd([]string{"/sbin/pfctl", "-a", pfAnchor, "-f", rules}); err != nil {
		return err
	}
	out, err := runCmd([]string{"/sbin/pfctl", "-E"})
	if err != nil {
		_, _ = runCmd([]string{"/sbin/pfctl", "-a", pfAnchor, "-F", "all"})
		return err
	}
	return writeSaved(dir, isolateSaved{PfToken: parsePfToken(out)})
}

func clearNetIsolate(dir string) error {
	_, err := runCmd([]string{"/sbin/pfctl", "-a", pfAnchor, "-F", "all"})
	if tok := readSaved(dir).PfToken; tok != "" {
		_, _ = runCmd([]string{"/sbin/pfctl", "-X", tok})
	}
	return err
}
