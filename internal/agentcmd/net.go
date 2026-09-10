package agentcmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const iptablesChain = "DEFENDSEC_ISOLATE"

func applyNetIsolate() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("network isolate is only implemented on linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("network isolate requires root")
	}
	if err := ensureChain(); err != nil {
		return err
	}
	// Allow loopback and established sessions so the agent can keep talking to the control plane.
	_ = iptables("-C", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	if err := iptables("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"); err != nil && !existsErr(err) {
		return err
	}
	_ = iptables("-C", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err := iptables("-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil && !existsErr(err) {
		return err
	}
	_ = iptables("-C", "OUTPUT", "-j", iptablesChain)
	if err := iptables("-A", "OUTPUT", "-j", iptablesChain); err != nil && !existsErr(err) {
		return err
	}
	_ = iptables("-F", iptablesChain)
	if err := iptables("-A", iptablesChain, "-j", "REJECT", "--reject-with", "icmp-admin-prohibited"); err != nil {
		return err
	}
	return nil
}

func clearNetIsolate() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil
	}
	_ = iptables("-D", "OUTPUT", "-j", iptablesChain)
	_ = iptables("-F", iptablesChain)
	_ = iptables("-X", iptablesChain)
	return nil
}

func ensureChain() error {
	if err := iptables("-N", iptablesChain); err != nil && !existsErr(err) {
		// chain may already exist
		if !strings.Contains(strings.ToLower(err.Error()), "exist") {
			return err
		}
	}
	return nil
}

func iptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func existsErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exist") || strings.Contains(msg, "already")
}
