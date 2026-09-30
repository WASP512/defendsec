package agentcmd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"defendsec/internal/proclist"
)

// runWindowsLiveQuery answers a live query on Windows. ok is false for a
// query with no Windows implementation.
func runWindowsLiveQuery(query string) (string, bool, error) {
	switch query {
	case "processes":
		out, err := windowsProcesses()
		return out, true, err
	case "logged_in_users":
		out, err := runExe(20*time.Second, "quser")
		text, rerr := renderQuser(out, err)
		return text, true, rerr
	}
	q, ok := windowsLiveQueries[query]
	if !ok {
		return "", false, nil
	}
	out, err := runExe(60*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", q.Script)
	if err != nil {
		return "", true, fmt.Errorf("%s: %w: %s", query, err, firstLine(out))
	}
	text, err := renderJSONTable([]byte(out), q.Columns, q.Limit)
	return text, true, err
}

func runExe(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func windowsProcesses() (string, error) {
	procs, err := proclist.List()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("pid\tppid\timage\tcmdline\n")
	for i, p := range procs {
		if i >= 300 {
			fmt.Fprintf(&b, "… %d more\n", len(procs)-300)
			break
		}
		fmt.Fprintf(&b, "%d\t%d\t%s\t%s\n", p.PID, p.PPID, p.Image, truncate(cellString(proclist.CommandLine(p.PID)), 160))
	}
	return b.String(), nil
}
