//go:build linux

package agentcmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Linux isolation. nftables is preferred: one inet table covers IPv4 and
// IPv6, it is replaced atomically, and a base chain that drops cannot be
// overridden by another firewall's accept (firewalld, ufw), because a packet
// must pass every base chain on its hook. Hosts without nft fall back to
// iptables and ip6tables. See net_linux_rules.go for what is allowed.

var activeBackend string

// forceIptables makes isolation use the iptables fallback even where nft
// works. For tests, so both backends are exercised on one machine.
var forceIptables bool

func privileged() bool { return os.Geteuid() == 0 }

func isolateDescription() string {
	switch activeBackend {
	case "nft":
		return "network isolated with nftables (table inet " + nftTable + "): only the control plane is reachable, over IPv4 and IPv6"
	case "iptables":
		return "network isolated with iptables and ip6tables: only the control plane is reachable"
	}
	return "network isolated"
}

func backendPath(dir string) string { return filepath.Join(dir, "isolate-backend") }

func nftUsable() bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	_, err := runCmd([]string{"nft", "list", "tables"})
	return err == nil
}

func applyNetIsolate(dir string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("network isolate requires root")
	}
	ep, err := resolveControlPlane(lookupHost)
	if err != nil {
		return err
	}
	if !forceIptables && nftUsable() {
		f, err := os.CreateTemp(dir, "nft-isolate-*.conf")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(nftRuleset(ep)); err != nil {
			f.Close()
			return err
		}
		f.Close()
		if _, err := runCmd([]string{"nft", "-f", f.Name()}); err != nil {
			return err
		}
		activeBackend = "nft"
		return os.WriteFile(backendPath(dir), []byte("nft"), 0o600)
	}
	if err := iptablesIsolate(ep); err != nil {
		_ = iptablesRelease()
		return err
	}
	activeBackend = "iptables"
	return os.WriteFile(backendPath(dir), []byte("iptables"), 0o600)
}

func clearNetIsolate(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	raw, _ := os.ReadFile(backendPath(dir))
	backend := strings.TrimSpace(string(raw))
	var err error
	if backend == "nft" || backend == "" {
		if _, e := exec.LookPath("nft"); e == nil {
			if _, e := runCmd([]string{"nft", "delete", "table", "inet", nftTable}); e != nil && !strings.Contains(e.Error(), "No such file") {
				err = e
			}
		}
	}
	if backend == "iptables" || backend == "" {
		if e := iptablesRelease(); e != nil && err == nil {
			err = e
		}
	}
	if err == nil {
		_ = os.Remove(backendPath(dir))
		activeBackend = ""
	}
	return err
}

func hasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true // cannot tell: assume it matters
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

func iptablesIsolate(ep endpoint) error {
	families := []struct {
		bin string
		v6  bool
	}{{"iptables", false}, {"ip6tables", true}}
	for _, fam := range families {
		bin, err := findBin(fam.bin)
		if err == nil && fam.v6 {
			// A kernel without IPv6 has ip6tables installed but unusable.
			if _, e := runCmd([]string{bin, "-S"}); e != nil {
				err = e
			}
		}
		if err != nil {
			if fam.v6 && !hasGlobalIPv6() {
				continue // no IPv6 to leave open
			}
			return fmt.Errorf("%s not found; isolation would leave %s open (install nftables or iptables)", fam.bin, map[bool]string{false: "IPv4", true: "IPv6"}[fam.v6])
		}
		for _, chain := range []string{iptOutChain, iptInChain} {
			_, _ = runCmd([]string{bin, "-N", chain}) // exists already on a re-apply
			if _, err := runCmd([]string{bin, "-F", chain}); err != nil {
				return err
			}
		}
		for _, r := range iptablesChainRules(ep, fam.v6) {
			if _, err := runCmd(append([]string{bin}, r...)); err != nil {
				return err
			}
		}
		// Hooked first, so no earlier ACCEPT in OUTPUT or INPUT bypasses it.
		for hook, chain := range map[string]string{"OUTPUT": iptOutChain, "INPUT": iptInChain} {
			if _, err := runCmd([]string{bin, "-C", hook, "-j", chain}); err == nil {
				continue
			}
			if _, err := runCmd([]string{bin, "-I", hook, "1", "-j", chain}); err != nil {
				return err
			}
		}
	}
	return nil
}

func iptablesRelease() error {
	for _, name := range []string{"iptables", "ip6tables"} {
		bin, err := findBin(name)
		if err != nil {
			continue
		}
		for hook, chain := range map[string]string{"OUTPUT": iptOutChain, "INPUT": iptInChain} {
			// Remove every jump, in case an earlier run added more than one.
			for i := 0; i < 10; i++ {
				if _, err := runCmd([]string{bin, "-D", hook, "-j", chain}); err != nil {
					break
				}
			}
			_, _ = runCmd([]string{bin, "-F", chain})
			_, _ = runCmd([]string{bin, "-X", chain})
		}
		// The chain the first version used.
		_, _ = runCmd([]string{bin, "-D", "OUTPUT", "-j", "DEFENDSEC_ISOLATE"})
		_, _ = runCmd([]string{bin, "-F", "DEFENDSEC_ISOLATE"})
		_, _ = runCmd([]string{bin, "-X", "DEFENDSEC_ISOLATE"})
	}
	return nil
}

func findBin(name string) (string, error) {
	for _, n := range []string{name, name + "-nft", name + "-legacy"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}
