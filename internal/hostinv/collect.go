package hostinv

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Software struct {
	Name    string
	Version string
}

type Update struct {
	Name      string
	Current   string
	Available string
}

type FimFile struct {
	Path   string
	SHA256 string
	Size   int64
	Mtime  string
}

type Snapshot struct {
	Hostname       string
	Platform       string
	OSName         string
	OSVersion      string
	Arch           string
	Serial         string
	HardwareModel  string
	CPU            string
	MemoryMb       int64
	DiskEncryption *bool
	Firewall       *bool
	IPAddresses    []string
	Username       string
	UptimeSeconds  int64
	Software       []Software
	PendingUpdates []Update
	PatchInventory string
	Fim            []FimFile
}

func Collect() Snapshot {
	host, _ := os.Hostname()
	snap := Snapshot{
		Hostname:       host,
		Platform:       runtime.GOOS,
		Arch:           runtime.GOARCH,
		OSName:         osName(),
		OSVersion:      osVersion(),
		Serial:         serial(),
		HardwareModel:  hardwareModel(),
		CPU:            cpuLabel(),
		MemoryMb:       memoryMb(),
		DiskEncryption: diskEncryption(),
		Firewall:       firewallOn(),
		IPAddresses:    ipAddresses(),
		Username:       username(),
		UptimeSeconds:  uptimeSeconds(),
		Software:       softwareList(),
	}
	updates, status := pendingUpdates()
	snap.PendingUpdates = updates
	snap.PatchInventory = status
	snap.Fim = fimFiles()
	return snap
}

func run(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func osName() string {
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	if runtime.GOOS == "windows" {
		return "Windows"
	}
	kv := osRelease()
	if kv["NAME"] != "" {
		return kv["NAME"]
	}
	return "Linux"
}

func osVersion() string {
	if runtime.GOOS == "darwin" {
		return run("sw_vers", "-productVersion")
	}
	kv := osRelease()
	if kv["VERSION_ID"] != "" {
		return kv["VERSION_ID"]
	}
	return runtime.Version()
}

func osRelease() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"`)
	}
	return out
}

func memoryMb() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "MemTotal:") {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}

func uptimeSeconds() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	sec, err := strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	if err != nil {
		return 0
	}
	return int64(sec)
}

func diskEncryption() *bool {
	if runtime.GOOS != "linux" {
		return nil
	}
	raw := run("lsblk", "-ln", "-o", "TYPE,MOUNTPOINT")
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "crypt" && parts[len(parts)-1] == "/" {
			v := true
			return &v
		}
	}
	return nil
}

func firewallOn() *bool {
	if runtime.GOOS != "linux" {
		return nil
	}
	ufw := strings.ToLower(run("ufw", "status"))
	if strings.Contains(ufw, "status: active") {
		v := true
		return &v
	}
	if strings.Contains(ufw, "status: inactive") {
		v := false
		return &v
	}
	if strings.ToLower(run("firewall-cmd", "--state")) == "running" {
		v := true
		return &v
	}
	return nil
}

func ipAddresses() []string {
	var found []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return found
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			s := ip.String()
			dup := false
			for _, existing := range found {
				if existing == s {
					dup = true
					break
				}
			}
			if !dup {
				found = append(found, s)
			}
			if len(found) >= 8 {
				return found
			}
		}
	}
	return found
}

func username() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

func serial() string {
	raw, err := os.ReadFile("/sys/class/dmi/id/product_serial")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func hardwareModel() string {
	for _, p := range []string{"/sys/class/dmi/id/product_name", "/sys/firmware/devicetree/base/model"} {
		raw, err := os.ReadFile(p)
		if err == nil {
			if s := strings.TrimSpace(string(raw)); s != "" {
				return s
			}
		}
	}
	return runtime.GOARCH
}

func cpuLabel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(strings.ToLower(sc.Text()), "model name") {
			_, v, _ := strings.Cut(sc.Text(), ":")
			return strings.TrimSpace(v)
		}
	}
	return runtime.GOARCH
}

func softwareList() []Software {
	items := make([]Software, 0)
	seen := map[string]struct{}{}
	add := func(name, version string) {
		key := strings.ToLower(name)
		if name == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		items = append(items, Software{Name: name, Version: version})
	}
	priority := []string{"openssh-server", "openssl", "docker.io", "docker-ce", "containerd", "git", "python3"}
	for _, pkg := range priority {
		raw := run("dpkg-query", "-W", "-f=${Package}\t${Version}", pkg)
		if name, ver, ok := strings.Cut(raw, "\t"); ok {
			add(name, ver)
		}
	}
	raw := run("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	for _, line := range strings.Split(raw, "\n") {
		if name, ver, ok := strings.Cut(line, "\t"); ok {
			add(name, ver)
			if len(items) >= 80 {
				break
			}
		}
	}
	if len(items) <= 7 {
		raw = run("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n")
		for _, line := range strings.Split(raw, "\n") {
			if name, ver, ok := strings.Cut(line, "\t"); ok {
				add(name, ver)
				if len(items) >= 80 {
					break
				}
			}
		}
	}
	return items
}

func pendingUpdates() ([]Update, string) {
	if runtime.GOOS != "linux" {
		return nil, "unsupported"
	}
	if _, err := exec.LookPath("apt"); err != nil {
		return nil, "error"
	}
	raw := run("apt", "list", "--upgradable")
	var updates []Update
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, "/") || strings.Contains(line, "Listing") {
			continue
		}
		name := strings.SplitN(line, "/", 2)[0]
		parts := strings.Fields(line)
		available := ""
		if len(parts) > 1 {
			available = parts[1]
		}
		current := ""
		if _, rest, ok := strings.Cut(line, "upgradable from:"); ok {
			current = strings.Trim(rest, " ]")
		}
		updates = append(updates, Update{Name: name, Current: current, Available: available})
		if len(updates) >= 40 {
			break
		}
	}
	return updates, "ok"
}

func fimFiles() []FimFile {
	var paths []string
	switch runtime.GOOS {
	case "linux":
		paths = []string{"/etc/passwd", "/etc/group", "/etc/hosts", "/etc/ssh/sshd_config", "/etc/sudoers"}
	case "darwin":
		paths = []string{"/etc/hosts", "/etc/ssh/sshd_config"}
	}
	extra := os.Getenv("KEEL_FIM_PATHS")
	if extra != "" {
		for _, item := range strings.Split(extra, string(os.PathListSeparator)) {
			if strings.TrimSpace(item) != "" {
				paths = append(paths, strings.TrimSpace(item))
			}
		}
	}
	var out []FimFile
	for _, p := range paths {
		if f, err := hashFile(p); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func hashFile(path string) (FimFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FimFile{}, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return FimFile{}, err
	}
	sum := sha256.Sum256(raw)
	return FimFile{
		Path:   path,
		SHA256: hex.EncodeToString(sum[:]),
		Size:   st.Size(),
		Mtime:  st.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

func HashPathForTest(path string) (FimFile, error) {
	return hashFile(filepath.Clean(path))
}
