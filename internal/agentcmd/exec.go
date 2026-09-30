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

	"defendsec/internal/proclist"
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
	// Windows: killing any of these crashes or logs out the machine.
	"csrss": {}, "lsass": {}, "wininit": {}, "winlogon": {}, "services": {},
	"smss": {}, "svchost": {}, "system": {}, "msmpeng": {},
}

// isProtected compares without case or an .exe suffix, so "LSASS.EXE" is
// refused on Windows as surely as "lsass".
func isProtected(name string) bool {
	_, ok := protected[strings.TrimSuffix(strings.ToLower(name), ".exe")]
	return ok
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
	if privileged() && os.Getenv("DEFENDSEC_ISOLATE_NET") == "1" {
		if err := applyNetIsolate(dir); err != nil {
			st.Mode = "flag"
			st.Message = "isolated flag set; network drop failed: " + err.Error()
		} else {
			st.Mode = "net"
			st.Message = isolateDescription()
		}
	}
	return st, SaveState(dir, st)
}

// ReapplyIsolation restores network isolation at agent start. Linux
// firewall rules do not survive a reboot, so without this a rebooted host
// was quietly un-isolated while the console still showed it isolated.
// Windows Firewall rules persist, and re-applying there would record the
// isolated profiles as the ones to restore, so it is Linux only.
func ReapplyIsolation(dir string) (State, bool, error) {
	st := LoadState(dir)
	if runtime.GOOS != "linux" || !st.Isolated || st.Mode != "net" {
		return st, false, nil
	}
	if err := applyNetIsolate(dir); err != nil {
		st.Message = "isolation could not be re-applied after restart: " + err.Error()
		st.Mode = "flag"
		return st, true, SaveState(dir, st)
	}
	st.Message = isolateDescription() + " (re-applied at agent start)"
	return st, true, SaveState(dir, st)
}

func Release(dir string) (State, error) {
	if err := clearNetIsolate(dir); err != nil {
		st := State{Isolated: true, Mode: "net", Message: "release failed; the host may still be isolated: " + err.Error()}
		return st, SaveState(dir, st)
	}
	st := State{Isolated: false, Mode: "flag", Message: "isolation cleared"}
	return st, SaveState(dir, st)
}

func KillByName(name string) (int, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return 0, fmt.Errorf("process name must be 1-64 letters, digits, dot, underscore, or hyphen")
	}
	if isProtected(name) {
		return 0, fmt.Errorf("refusing to signal protected process %q", name)
	}
	if runtime.GOOS == "windows" {
		return killByList(name)
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
		if err := terminate(int32(pid)); err != nil {
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

// killByList is kill_process on platforms without /proc. Names compare
// case-insensitively on Windows, where "Notepad.exe" and "notepad.exe" are
// the same file, and with or without the .exe suffix.
func killByList(name string) (int, error) {
	procs, err := proclist.List()
	if err != nil {
		return 0, err
	}
	self := int32(os.Getpid())
	signaled := 0
	for _, p := range procs {
		if p.PID <= 4 || p.PID == self || !sameProcessName(p.Name, name) {
			continue
		}
		if err := proclist.Terminate(p.PID); err != nil {
			return signaled, fmt.Errorf("terminate %d: %w", p.PID, err)
		}
		signaled++
	}
	if signaled == 0 {
		return 0, fmt.Errorf("no process named %q", name)
	}
	return signaled, nil
}

func sameProcessName(have, want string) bool {
	if runtime.GOOS != "windows" {
		return have == want
	}
	trim := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".exe") }
	return trim(have) == trim(want)
}
