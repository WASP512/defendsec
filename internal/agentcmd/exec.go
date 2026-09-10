package agentcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	TypeIsolate     = "isolate"
	TypeRelease     = "release"
	TypeKillProcess = "kill_process"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var protected = map[string]struct{}{
	"defendsec-agentd": {},
	"defendsec-agent":  {}, // Linux /proc/pid/comm truncates to 15 bytes
	"defendsec-apid":   {},
	"systemd":          {},
	"init":             {},
	"sshd":             {},
	"ssh":              {},
	"next-server":      {},
}

type State struct {
	Isolated bool   `json:"isolated"`
	Mode     string `json:"mode"`
	Message  string `json:"message"`
}

type KillPayload struct {
	Name string `json:"name"`
}

func StatePath(dir string) string {
	return filepath.Join(dir, "isolate-state.json")
}

func LoadState(dir string) State {
	raw, err := os.ReadFile(StatePath(dir))
	if err != nil {
		return State{}
	}
	var st State
	if json.Unmarshal(raw, &st) != nil {
		return State{}
	}
	return st
}

func SaveState(dir string, st State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StatePath(dir), raw, 0o600)
}

func Isolate(dir string) (State, error) {
	st := State{Isolated: true, Mode: "flag", Message: "host marked isolated; network drop requires root and DEFENDSEC_ISOLATE_NET=1"}
	if os.Geteuid() == 0 && os.Getenv("DEFENDSEC_ISOLATE_NET") == "1" {
		if err := applyNetIsolate(); err != nil {
			st.Mode = "flag"
			st.Message = "isolated flag set; network drop failed: " + err.Error()
		} else {
			st.Mode = "net"
			st.Message = "network isolated via iptables chain DEFENDSEC_ISOLATE (loopback + established allowed)"
		}
	}
	return st, SaveState(dir, st)
}

func Release(dir string) (State, error) {
	_ = clearNetIsolate()
	st := State{Isolated: false, Mode: "flag", Message: "isolation cleared"}
	return st, SaveState(dir, st)
}

func KillByName(name string) (int, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return 0, fmt.Errorf("process name must be 1-64 letters, digits, dot, underscore, or hyphen")
	}
	if _, ok := protected[name]; ok {
		return 0, fmt.Errorf("refusing to signal protected process %q", name)
	}
	if runtime.GOOS == "windows" {
		return 0, fmt.Errorf("kill_process is not implemented on windows in phase 2")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	self := os.Getpid()
	signaled := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) != name {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			return signaled, fmt.Errorf("signal %d: %w", pid, err)
		}
		signaled++
	}
	if signaled == 0 {
		return 0, fmt.Errorf("no process named %q", name)
	}
	return signaled, nil
}

func ParseKillPayload(raw []byte) (KillPayload, error) {
	var p KillPayload
	if len(raw) == 0 {
		return p, fmt.Errorf("kill_process payload requires name")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if strings.TrimSpace(p.Name) == "" {
		return p, fmt.Errorf("kill_process payload requires name")
	}
	return p, nil
}
