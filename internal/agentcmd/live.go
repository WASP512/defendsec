package agentcmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	TypeLiveQuery   = "live_query"
	TypeAgentUpdate = "agent_update"
)

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
	switch p.Query {
	case "processes", "listening_ports", "users", "os_info":
		return p, nil
	default:
		return p, fmt.Errorf("unsupported live_query %q (allowed: processes, listening_ports, users, os_info)", p.Query)
	}
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

func listProcesses() (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("processes query not implemented on windows")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("pid\tcomm\n")
	count := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%d\t%s\n", pid, strings.TrimSpace(string(comm)))
		count++
		if count >= 200 {
			break
		}
	}
	return b.String(), nil
}

func listListeningPorts() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("listening_ports query only implemented on linux")
	}
	raw, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("port\tstate\n")
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	first := true
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[3] != "0A" { // LISTEN
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
		fmt.Fprintf(&b, "%d\tLISTEN\n", port64)
		n++
		if n >= 100 {
			break
		}
	}
	return b.String(), nil
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

// StageAgentUpdate records an update request for an external updater/packaging unit.
// DefendSec does not self-replace the running binary in-process.
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
