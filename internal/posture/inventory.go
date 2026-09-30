package posture

import (
	"encoding/json"
	"fmt"
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
