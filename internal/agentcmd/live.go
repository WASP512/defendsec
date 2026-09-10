package agentcmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	TypeLiveQuery   = "live_query"
	TypeAgentUpdate = "agent_update"
)

var allowedLiveQueries = []string{
	"processes",
	"listening_ports",
	"users",
	"logged_in_users",
	"crontab",
	"systemd_units",
	"mounts",
	"os_info",
}

type LiveQueryPayload struct {
	Query string `json:"query"`
}

type AgentUpdatePayload struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Notes   string `json:"notes"`
}

func ParseLiveQueryPayload(raw []byte) (LiveQueryPayload, error) {
	var p LiveQueryPayload
	if len(raw) == 0 {
		return p, fmt.Errorf("live_query payload requires query")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	p.Query = strings.TrimSpace(strings.ToLower(p.Query))
	for _, allowed := range allowedLiveQueries {
		if p.Query == allowed {
			return p, nil
		}
	}
	return p, fmt.Errorf("unsupported live_query %q (allowed: %s)", p.Query, strings.Join(allowedLiveQueries, ", "))
}

func ParseAgentUpdatePayload(raw []byte) (AgentUpdatePayload, error) {
	var p AgentUpdatePayload
	if len(raw) == 0 {
		return p, fmt.Errorf("agent_update payload requires version/url/sha256")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.Version) == "" || strings.TrimSpace(p.URL) == "" || strings.TrimSpace(p.SHA256) == "" {
		return p, fmt.Errorf("agent_update payload requires version, url, and sha256")
	}
	return p, nil
}

func RunLiveQuery(query string) (string, error) {
	switch query {
	case "processes":
		return listProcesses()
	case "listening_ports":
		return listListeningPorts()
	case "users":
		return listUsers()
	case "logged_in_users":
		return listLoggedInUsers()
	case "crontab":
		return listCrontab()
	case "systemd_units":
		return listSystemdUnits()
	case "mounts":
		return listMounts()
	case "os_info":
		return fmt.Sprintf("goos=%s goarch=%s hostname=%s", runtime.GOOS, runtime.GOARCH, hostname()), nil
	default:
		return "", fmt.Errorf("unsupported query")
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func passwdByUID() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 3 {
			out[parts[2]] = parts[0]
		}
	}
	return out
}

func listProcesses() (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("processes query not implemented on windows")
	}
	users := passwdByUID()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("pid\tuid\tuser\tcomm\tcmdline\n")
	count := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		procDir := filepath.Join("/proc", entry.Name())
		comm, err := os.ReadFile(filepath.Join(procDir, "comm"))
		if err != nil {
			continue
		}
		uid := readProcUID(procDir)
		user := users[uid]
		if user == "" {
			user = uid
		}
		cmdline := truncate(readProcCmdline(procDir), 120)
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%s\n", pid, uid, user, strings.TrimSpace(string(comm)), cmdline)
		count++
		if count >= 200 {
			break
		}
	}
	return b.String(), nil
}

func readProcUID(procDir string) string {
	raw, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
}

func readProcCmdline(procDir string) string {
	raw, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err != nil || len(raw) == 0 {
		return ""
	}
	parts := strings.Split(string(raw), "\x00")
	return strings.Join(parts, " ")
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func listListeningPorts() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("listening_ports query only implemented on linux")
	}
	inodePID := buildInodePIDMap()
	var b strings.Builder
	b.WriteString("port\tstate\tpid\n")
	n := 0
	for _, proto := range []string{"tcp", "tcp6"} {
		path := filepath.Join("/proc/net", proto)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		n += appendListeningPorts(&b, string(raw), inodePID, 100-n)
		if n >= 100 {
			break
		}
	}
	if n == 0 {
		return "(no listening ports found)", nil
	}
	return b.String(), nil
}

func appendListeningPorts(b *strings.Builder, raw string, inodePID map[string]int, limit int) int {
	sc := bufio.NewScanner(strings.NewReader(raw))
	first := true
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}
		port64, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil {
			continue
		}
		inode := fields[9]
		pid := 0
		if p, ok := inodePID[inode]; ok {
			pid = p
		}
		fmt.Fprintf(b, "%d\tLISTEN\t%d\n", port64, pid)
		n++
		if n >= limit {
			break
		}
	}
	return n
}

func buildInodePIDMap() map[string]int {
	out := map[string]int{}
	if runtime.GOOS != "linux" {
		return out
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if inode != "" {
				out[inode] = pid
			}
		}
	}
	return out
}

func listUsers() (string, error) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("user\tuid\tshell\n")
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\n", parts[0], parts[2], parts[6])
		n++
		if n >= 100 {
			break
		}
	}
	return b.String(), nil
}

func listLoggedInUsers() (string, error) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if out, err := exec.Command("who").CombinedOutput(); err == nil {
			text := strings.TrimSpace(string(out))
			if text != "" {
				return text, nil
			}
		}
	}
	return "", fmt.Errorf("logged_in_users not available")
}

func listCrontab() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("crontab query only implemented on linux")
	}
	var b strings.Builder
	appendFileLines(&b, "/etc/crontab", "system")
	cronD, err := os.ReadDir("/etc/cron.d")
	if err == nil {
		for _, entry := range cronD {
			if entry.IsDir() {
				continue
			}
			appendFileLines(&b, filepath.Join("/etc/cron.d", entry.Name()), entry.Name())
		}
	}
	spool := "/var/spool/cron/crontabs"
	users, err := os.ReadDir(spool)
	if err == nil {
		for _, entry := range users {
			if entry.IsDir() {
				continue
			}
			appendFileLines(&b, filepath.Join(spool, entry.Name()), entry.Name())
		}
	}
	text := strings.TrimSpace(b.String())
	if text == "" {
		return "(no crontab entries readable)", nil
	}
	return text, nil
}

func appendFileLines(b *strings.Builder, path, label string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Fprintf(b, "[%s] %s\n", label, line)
	}
}

func listSystemdUnits() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("systemd_units query only implemented on linux")
	}
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running,enabled", "--no-pager", "--no-legend").CombinedOutput()
	if err == nil {
		text := strings.TrimSpace(string(out))
		if text != "" {
			return text, nil
		}
	}
	var b strings.Builder
	b.WriteString("unit\tenabled\n")
	dirs := []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}
	n := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".service") {
				continue
			}
			enabled := "unknown"
			if st, err := os.Stat(filepath.Join("/etc/systemd/system", name)); err == nil && !st.IsDir() {
				enabled = "enabled"
			}
			fmt.Fprintf(&b, "%s\t%s\n", name, enabled)
			n++
			if n >= 100 {
				return b.String(), nil
			}
		}
	}
	if n == 0 {
		return "(no systemd units found)", nil
	}
	return b.String(), nil
}

func listMounts() (string, error) {
	if runtime.GOOS == "linux" {
		raw, err := os.ReadFile("/proc/mounts")
		if err == nil {
			return string(raw), nil
		}
	}
	return "", fmt.Errorf("mounts query not available")
}

// StageAgentUpdate records an update request for an external updater/packaging unit.
func StageAgentUpdate(stateDir string, p AgentUpdatePayload) (string, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, "pending-update.json")
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("staged agent update %s to %s (sha256=%s)", p.Version, path, p.SHA256), nil
}
