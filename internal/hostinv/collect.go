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

// HostIdentity is a cheap hostname/OS snapshot for heartbeats (no package queries).
type HostIdentity struct {
	Hostname      string
	Platform      string
	OSName        string
	OSVersion     string
	Arch          string
	UptimeSeconds int64
}

func Identity() HostIdentity {
	host, _ := os.Hostname()
	return HostIdentity{
		Hostname:      host,
		Platform:      runtime.GOOS,
		OSName:        osName(),
		OSVersion:     osVersion(),
		Arch:          runtime.GOARCH,
		UptimeSeconds: uptimeSeconds(),
	}
}

func Collect() Snapshot {
	id := Identity()
	snap := Snapshot{
		Hostname:       id.Hostname,
		Platform:       id.Platform,
		Arch:           id.Arch,
		OSName:         id.OSName,
		OSVersion:      id.OSVersion,
		Serial:         serial(),
		HardwareModel:  hardwareModel(),
		CPU:            cpuLabel(),
		MemoryMb:       memoryMb(),
		DiskEncryption: diskEncryption(),
		Firewall:       firewallOn(),
		IPAddresses:    ipAddresses(),
		Username:       username(),
		UptimeSeconds:  id.UptimeSeconds,
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
	// firewalld (Fedora/RHEL): --state exits non-zero when not running.
	fw, code := runAllowExit("firewall-cmd", []int{252}, "--state")
	fw = strings.ToLower(fw)
	if fw == "running" || code == 0 && strings.Contains(fw, "running") {
		v := true
		return &v
	}
	if strings.Contains(fw, "not running") || code == 252 {
		v := false
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

func rpmBased() bool {
	kv := osRelease()
	blob := strings.ToLower(kv["ID"] + " " + kv["ID_LIKE"])
	for _, token := range []string{"fedora", "rhel", "centos", "rocky", "alma", "amzn", "suse", "sles"} {
		if strings.Contains(blob, token) {
			return true
		}
	}
	_, hasRPM := exec.LookPath("rpm")
	_, hasDPKG := exec.LookPath("dpkg-query")
	return hasRPM == nil && hasDPKG != nil
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
	priority := []string{"openssh-server", "openssh", "openssl", "docker.io", "docker-ce", "containerd", "git", "python3"}
	if rpmBased() {
		for _, pkg := range priority {
			raw := run("rpm", "-q", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}", pkg)
			if name, ver, ok := strings.Cut(raw, "\t"); ok && !strings.Contains(raw, "not installed") {
				add(name, ver)
			}
		}
		raw := run("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
		for _, line := range strings.Split(raw, "\n") {
			if name, ver, ok := strings.Cut(line, "\t"); ok {
				add(name, ver)
				if len(items) >= 80 {
					break
				}
			}
		}
		return items
	}
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
		raw = run("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
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

func runAllowExit(name string, allowExit []int, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
			for _, allowed := range allowExit {
				if code == allowed {
					return strings.TrimSpace(string(out)), code
				}
			}
		}
		return "", -1
	}
	return strings.TrimSpace(string(out)), code
}

func pendingUpdates() ([]Update, string) {
	if runtime.GOOS != "linux" {
		return nil, "unsupported"
	}
	if _, err := exec.LookPath("apt"); err == nil {
		return pendingApt()
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return pendingDNF("dnf")
	}
	if _, err := exec.LookPath("yum"); err == nil {
		return pendingDNF("yum")
	}
	return nil, "unsupported"
}

func pendingApt() ([]Update, string) {
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

func pendingDNF(bin string) ([]Update, string) {
	// dnf/yum check-update exits 100 when updates are available.
	raw, code := runAllowExit(bin, []int{100}, "check-update", "-q")
	if code < 0 {
		return nil, "error"
	}
	var updates []Update
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Obsoleting") || strings.HasPrefix(line, "Security:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if i := strings.LastIndex(name, "."); i > 0 {
			// strip arch suffix: openssl.x86_64 → openssl
			arch := name[i+1:]
			if arch == "x86_64" || arch == "aarch64" || arch == "noarch" || arch == "i686" {
				name = name[:i]
			}
		}
		updates = append(updates, Update{Name: name, Available: fields[1]})
		if len(updates) >= 40 {
			break
		}
	}
	return updates, "ok"
}

func FimPaths() []string {
	var paths []string
	switch runtime.GOOS {
	case "linux":
		paths = []string{
			"/etc/passwd",
			"/etc/group",
			"/etc/hosts",
			"/etc/ssh/sshd_config",
			"/etc/ssh/sshd_config.d",
			"/etc/sudoers",
			"/etc/crypto-policies/config",
		}
	case "darwin":
		paths = []string{"/etc/hosts", "/etc/ssh/sshd_config"}
	default:
		paths = []string{}
	}
	if extra := os.Getenv("DEFENDSEC_FIM_PATHS"); extra != "" {
		for _, item := range strings.Split(extra, string(os.PathListSeparator)) {
			if strings.TrimSpace(item) != "" {
				paths = append(paths, strings.TrimSpace(item))
			}
		}
	}
	return paths
}

// ExpandFimPaths turns watch roots into concrete files (directories → *.conf / *.cfg children).
func ExpandFimPaths(roots []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		st, err := os.Stat(root)
		if err != nil {
			add(root)
			continue
		}
		if !st.IsDir() {
			add(root)
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || (!strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".cfg")) {
				continue
			}
			add(filepath.Join(root, name))
		}
	}
	return out
}

func fimFiles() []FimFile {
	var out []FimFile
	for _, p := range ExpandFimPaths(FimPaths()) {
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
