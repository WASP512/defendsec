package agentcmd

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// Windows live queries (roadmap 5.1). Each is one PowerShell pipeline that
// casts every field to a plain type before ConvertTo-Json — Windows
// PowerShell 5.1 serialises enums as bare integers, so a service's state
// would otherwise arrive as "4" — and is rendered here, by code that is
// tested without Windows. Output is the same tab-separated form the Linux
// queries produce.

// windowsLiveQuery describes one query.
type windowsLiveQuery struct {
	Script  string
	Columns []string
	Limit   int
}

// windowsLiveQueries maps the console's query names onto their Windows
// equivalents. crontab and systemd_units keep their names so saved queries
// and the console work unchanged; on Windows they answer the same question
// — what runs on a schedule, what runs as a service.
var windowsLiveQueries = map[string]windowsLiveQuery{
	"listening_ports": {
		Script: `$p = @{}; Get-Process | ForEach-Object { $p[[int]$_.Id] = [string]$_.ProcessName }
$t = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ proto = 'tcp'; address = [string]$_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $p[[int]$_.OwningProcess] } })
$u = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ proto = 'udp'; address = [string]$_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $p[[int]$_.OwningProcess] } })
@($t + $u) | ConvertTo-Json -Compress`,
		Columns: []string{"proto", "address", "port", "pid", "process"},
		Limit:   200,
	},
	"users": {
		Script:  `@(Get-LocalUser | ForEach-Object { [ordered]@{ user = [string]$_.Name; enabled = [bool]$_.Enabled; lastLogon = [string]$_.LastLogon; sid = [string]$_.SID } }) | ConvertTo-Json -Compress`,
		Columns: []string{"user", "enabled", "lastLogon", "sid"},
		Limit:   200,
	},
	"crontab": {
		Script:  `@(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { [ordered]@{ task = ([string]$_.TaskPath + [string]$_.TaskName); state = [string]$_.State; runAs = [string]$_.Principal.UserId; actions = ((@($_.Actions) | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join '; ') } }) | ConvertTo-Json -Compress`,
		Columns: []string{"task", "state", "runAs", "actions"},
		Limit:   300,
	},
	"systemd_units": {
		Script:  `@(Get-CimInstance Win32_Service | ForEach-Object { [ordered]@{ service = [string]$_.Name; state = [string]$_.State; start = [string]$_.StartMode; account = [string]$_.StartName; path = [string]$_.PathName } }) | ConvertTo-Json -Compress`,
		Columns: []string{"service", "state", "start", "account", "path"},
		Limit:   400,
	},
	"mounts": {
		Script:  `@(Get-CimInstance Win32_LogicalDisk | ForEach-Object { [ordered]@{ drive = [string]$_.DeviceID; type = [int]$_.DriveType; filesystem = [string]$_.FileSystem; sizeGB = [math]::Round([double]$_.Size / 1GB, 1); freeGB = [math]::Round([double]$_.FreeSpace / 1GB, 1); } }) | ConvertTo-Json -Compress`,
		Columns: []string{"drive", "type", "filesystem", "sizeGB", "freeGB"},
		Limit:   50,
	},
}

// renderJSONTable turns the script's JSON (an array, a single object, or
// nothing at all for an empty result) into a tab-separated table.
func renderJSONTable(raw []byte, cols []string, limit int) (string, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(raw), "\uFEFF"))
	var rows []map[string]any
	switch {
	case s == "" || s == "null":
	case strings.HasPrefix(s, "["):
		if err := json.Unmarshal([]byte(s), &rows); err != nil {
			return "", fmt.Errorf("parse query output: %w", err)
		}
	default:
		var one map[string]any
		if err := json.Unmarshal([]byte(s), &one); err != nil {
			return "", fmt.Errorf("parse query output: %w", err)
		}
		rows = []map[string]any{one}
	}
	var b strings.Builder
	b.WriteString(strings.Join(cols, "\t"))
	b.WriteByte('\n')
	for i, row := range rows {
		if limit > 0 && i >= limit {
			fmt.Fprintf(&b, "… %d more\n", len(rows)-limit)
			break
		}
		cells := make([]string, len(cols))
		for j, c := range cols {
			cells[j] = truncate(cellString(row[c]), 160)
		}
		b.WriteString(strings.Join(cells, "\t"))
		b.WriteByte('\n')
	}
	if len(rows) == 0 {
		b.WriteString("(none)\n")
	}
	return b.String(), nil
}

func cellString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		// Tabs and newlines would break the table.
		return strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(x)
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case bool:
		return fmt.Sprintf("%t", x)
	default:
		return fmt.Sprint(x)
	}
}

// renderQuser tidies `quser` output. quser exits 1 with "No User exists"
// when nobody is logged on, which is an answer, not an error.
func renderQuser(out string, exitErr error) (string, error) {
	text := strings.TrimSpace(out)
	if text == "" || strings.Contains(strings.ToLower(text), "no user exists") {
		return "(no logged-in users)", nil
	}
	if exitErr != nil && !strings.Contains(strings.ToUpper(text), "USERNAME") {
		return "", fmt.Errorf("quser: %v: %s", exitErr, firstLine(text))
	}
	return text, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
