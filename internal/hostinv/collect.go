package hostinv

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/posture"
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
	// Posture is the Windows posture report (roadmap 5.1, 5.2),
	// handed to the SCA engine's posture checks. Nil on Linux.
	Posture posture.Report
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
	if runtime.GOOS == "windows" {
		applyPlatformInventory(&snap)
	}
	return snap
}

// applyPlatformInventory overlays what the Windows collectors found.
// The Linux-shaped collectors above return zero values on these platforms, so
// a value here only ever replaces an absence.
func applyPlatformInventory(snap *Snapshot) {
	ctx := context.Background()
	rep, facts, err := posture.Collect(ctx)
	if err == nil {
		snap.Posture = rep
		if facts.OSName != "" {
			snap.OSName = facts.OSName
		}
		if facts.OSVersion != "" {
			snap.OSVersion = facts.OSVersion
		}
		if facts.MemoryMb > 0 {
			snap.MemoryMb = facts.MemoryMb
		}
		if facts.UptimeSeconds > 0 {
			snap.UptimeSeconds = facts.UptimeSeconds
		}
		if facts.Serial != "" {
			snap.Serial = facts.Serial
		}
		if facts.HardwareModel != "" {
			snap.HardwareModel = facts.HardwareModel
		}
		snap.DiskEncryption = facts.DiskEncryption
		snap.Firewall = facts.Firewall
		for _, sw := range facts.Software {
			snap.Software = append(snap.Software, Software{Name: sw.Name, Version: sw.Version})
		}
	}
	inv := posture.CollectInventory(ctx)
	for _, sw := range inv.Software {
		snap.Software = append(snap.Software, Software{Name: sw.Name, Version: sw.Version})
	}
	snap.PendingUpdates = nil
	for _, u := range inv.Updates {
		snap.PendingUpdates = append(snap.PendingUpdates, Update{Name: u.Name, Available: u.Available})
	}
	snap.PatchInventory = inv.UpdateStatus
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
		// firewalld is installed but stopped; nftables rules may still be
		// loaded some other way, so fall through rather than answer "off".
		if v, ok := nftFirewall(); ok {
			return &v
		}
		v := false
		return &v
	}
	// Neither ufw nor firewalld: Debian and minimal installs often manage
	// nftables directly, or have no firewall at all.
	if v, ok := nftFirewall(); ok {
		return &v
	}
	return nil
}

func nftFirewall() (bool, bool) {
	if _, err := exec.LookPath("nft"); err != nil {
		return false, false
	}
	raw := run("nft", "-j", "list", "ruleset")
	if raw == "" {
		return false, false
	}
	return NftFirewallActive([]byte(raw))
}

// NftFirewallActive reports whether an nftables ruleset (`nft -j list
// ruleset`) filters inbound traffic: an input-hook chain whose policy is
// drop, or that contains a drop or reject rule. ok is false when the output
// cannot be read. A ruleset with no such chain is a host with no inbound
// firewall — true of many Docker hosts, whose chains only forward.
func NftFirewallActive(raw []byte) (active, ok bool) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Nftables == nil {
		return false, false
	}
	type chainKey struct{ family, table, name string }
	inputChains := map[chainKey]bool{}
	for _, item := range doc.Nftables {
		c, ok := item["chain"]
		if !ok {
			continue
		}
		var ch struct {
			Family, Table, Name, Hook, Policy string
		}
		if json.Unmarshal(c, &ch) != nil || ch.Hook != "input" {
			continue
		}
		if ch.Policy == "drop" {
			return true, true
		}
		inputChains[chainKey{ch.Family, ch.Table, ch.Name}] = true
	}
	for _, item := range doc.Nftables {
		r, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Family, Table, Chain string
			Expr                 []map[string]json.RawMessage
		}
		if json.Unmarshal(r, &rule) != nil || !inputChains[chainKey{rule.Family, rule.Table, rule.Chain}] {
			continue
		}
		for _, e := range rule.Expr {
			if _, drop := e["drop"]; drop {
				return true, true
			}
			if _, reject := e["reject"]; reject {
				return true, true
			}
		}
	}
	return false, true
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
	if _, err := exec.LookPath("zypper"); err == nil {
		return pendingZypper()
	}
	return nil, "unsupported"
}

// pendingZypper lists openSUSE updates. Exit 7 is another process holding
// the zypper lock, which is reported as an error rather than as "no updates".
func pendingZypper() ([]Update, string) {
	raw, code := runAllowExit("zypper", []int{7}, "--non-interactive", "--quiet", "list-updates")
	if code != 0 {
		return nil, "error"
	}
	return ParseZypperUpdates(raw), "ok"
}

// ParseZypperUpdates reads the table `zypper list-updates` prints:
//
//	S | Repository | Name | Current Version | Available Version | Arch
//	--+------------+------+-----------------+-------------------+-------
//	v | repo-oss   | curl | 8.6.0-1.1       | 8.6.0-2.1         | x86_64
//
// Columns are found from the header rather than by position, because
// zypper versions differ in which columns they print.
func ParseZypperUpdates(raw string) []Update {
	var updates []Update
	col := map[string]int{}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(col) == 0 {
			for i, c := range cells {
				col[strings.ToLower(c)] = i
			}
			if _, ok := col["name"]; !ok {
				col = map[string]int{}
			}
			continue
		}
		if strings.HasPrefix(cells[0], "--") {
			continue
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(cells) {
				return cells[i]
			}
			return ""
		}
		name := get("name")
		if name == "" {
			continue
		}
		updates = append(updates, Update{Name: name, Current: get("current version"), Available: get("available version")})
		if len(updates) >= 40 {
			break
		}
	}
	return updates
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
	case "windows":
		// Files an attacker edits to redirect or persist, readable without
		// taking locks on system hives.
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		paths = []string{
			filepath.Join(root, "System32", "drivers", "etc", "hosts"),
			filepath.Join(root, "System32", "drivers", "etc", "services"),
			filepath.Join(root, "System32", "GroupPolicy", "Machine", "Scripts"),
			filepath.Join(root, "System32", "Tasks"),
		}
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
