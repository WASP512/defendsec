package agentcmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderJSONTable(t *testing.T) {
	arr := `[{"service":"WinDefend","state":"Running","start":"Auto","account":"LocalSystem","path":"\"C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe\""},
{"service":"evil","state":"Running","start":"Auto","account":"LocalSystem","path":"C:\\Users\\Public\\x.exe\t-k"}]`
	out, err := renderJSONTable([]byte(arr), []string{"service", "state", "start", "account", "path"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || lines[0] != "service\tstate\tstart\taccount\tpath" {
		t.Fatalf("%q", out)
	}
	if strings.Count(lines[2], "\t") != 4 {
		t.Errorf("a tab inside a value broke the columns: %q", lines[2])
	}
	// PowerShell emits a single result as an object, and nothing at all for none.
	one, _ := renderJSONTable([]byte("\uFEFF"+`{"proto":"tcp","address":"0.0.0.0","port":445,"pid":4,"process":"System"}`), []string{"proto", "address", "port", "pid", "process"}, 10)
	if !strings.Contains(one, "tcp\t0.0.0.0\t445\t4\tSystem") {
		t.Errorf("single object / integers: %q", one)
	}
	none, _ := renderJSONTable([]byte(""), []string{"task"}, 10)
	if !strings.Contains(none, "(none)") {
		t.Errorf("empty: %q", none)
	}
	capped, _ := renderJSONTable([]byte(`[{"a":1},{"a":2},{"a":3}]`), []string{"a"}, 2)
	if !strings.Contains(capped, "… 1 more") {
		t.Errorf("limit: %q", capped)
	}
	if _, err := renderJSONTable([]byte("Get-ScheduledTask : Access denied"), []string{"a"}, 1); err == nil {
		t.Error("garbage must be an error")
	}
}

func TestRenderQuser(t *testing.T) {
	if s, err := renderQuser("No User exists for *\r\n", &exec.ExitError{}); err != nil || s != "(no logged-in users)" {
		t.Errorf("%q %v", s, err)
	}
	table := " USERNAME   SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME\n>alice      console        1  Active      none   9/30/2026 8:01 AM"
	if s, err := renderQuser(table, nil); err != nil || !strings.Contains(s, "alice") {
		t.Errorf("%q %v", s, err)
	}
}

// Every Windows query script must at least parse as PowerShell. Runs when
// pwsh is installed (CI's provisioning job has it); the cmdlets themselves
// exist only on Windows.
func TestWindowsQueryScriptsParse(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	for name, q := range windowsLiveQueries {
		f := filepath.Join(t.TempDir(), name+".ps1")
		if err := os.WriteFile(f, []byte(q.Script), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(pwsh, "-NoProfile", "-Command",
			"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('"+f+"',[ref]$null,[ref]$e); if($e){$e | % { $_.ToString() }; exit 1}")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %s", name, out)
		}
	}
}
