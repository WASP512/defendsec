package posture

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Update is one pending operating-system update.
type Update struct {
	Name      string
	Available string
}

// maxUpdates matches the cap the Linux collector applies.
const maxUpdates = 40

// WindowsUpdateScript lists pending updates through the Windows Update Agent.
// It is separate from WindowsScript because a search contacts Microsoft (or
// the WSUS server) and can take minutes; posture must not wait behind it.
const WindowsUpdateScript = `$ErrorActionPreference = 'Stop'
$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$res = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
@($res.Updates | ForEach-Object { [ordered]@{ title = [string]$_.Title; kb = [string](($_.KBArticleIDs | Select-Object -First 1)) } }) | ConvertTo-Json -Depth 3 -Compress`

// ParseWindowsUpdates reads WindowsUpdateScript's output.
func ParseWindowsUpdates(raw []byte) ([]Update, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(raw), "\uFEFF"))
	if s == "" {
		// ConvertTo-Json of an empty array prints nothing on 5.1.
		return nil, nil
	}
	type item struct {
		Title string `json:"title"`
		KB    string `json:"kb"`
	}
	items, err := oneOrMany[item](json.RawMessage(s))
	if err != nil {
		return nil, fmt.Errorf("parse update search output: %w", err)
	}
	var out []Update
	for _, it := range items {
		avail := ""
		if it.KB != "" {
			avail = "KB" + it.KB
		}
		out = append(out, Update{Name: strings.TrimSpace(it.Title), Available: avail})
		if len(out) >= maxUpdates {
			break
		}
	}
	return out, nil
}

var (
	macLabelRe   = regexp.MustCompile(`^\s*\* Label: (.+)$`)
	macTitleRe   = regexp.MustCompile(`Title: ([^,]+), Version: ([^,]+)`)
	macLegacyRe  = regexp.MustCompile(`^\s*\* (\S.*)$`)
	macNoUpdates = "No new software available"
)

// ParseMacUpdates reads `softwareupdate -l`. Both the macOS 10.15+ format
// ("* Label: ..." followed by "Title: ..., Version: ...") and the older
// one ("* name" followed by "\tTitle (version)") are accepted.
func ParseMacUpdates(out string) []Update {
	if strings.Contains(out, macNoUpdates) {
		return nil
	}
	var ups []Update
	lines := strings.Split(out, "\n")
	for i := 0; i < len(lines); i++ {
		name := ""
		if m := macLabelRe.FindStringSubmatch(lines[i]); m != nil {
			name = strings.TrimSpace(m[1])
		} else if m := macLegacyRe.FindStringSubmatch(lines[i]); m != nil {
			name = strings.TrimSpace(m[1])
		} else {
			continue
		}
		u := Update{Name: name}
		if i+1 < len(lines) {
			if m := macTitleRe.FindStringSubmatch(lines[i+1]); m != nil {
				u.Name, u.Available = strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
				i++
			}
		}
		ups = append(ups, u)
		if len(ups) >= maxUpdates {
			break
		}
	}
	return ups
}

// ParseMacApps reads `system_profiler -json SPApplicationsDataType`.
func ParseMacApps(raw []byte) ([]Software, error) {
	var doc struct {
		Apps []struct {
			Name    string `json:"_name"`
			Version string `json:"version"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse system_profiler output: %w", err)
	}
	seen := map[string]bool{}
	var out []Software
	for _, a := range doc.Apps {
		name := strings.TrimSpace(a.Name)
		key := name + "\x00" + a.Version
		if name == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Software{Name: name, Version: strings.TrimSpace(a.Version)})
	}
	return out, nil
}
