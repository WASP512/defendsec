package forward

import (
	"fmt"
	"sort"
	"strings"
)

// CEF renders a record as ArcSight Common Event Format (roadmap 5.6):
//
//	CEF:0|DefendSec|DefendSec|1|<signature>|<name>|<severity>|<extensions>
//
// The escaping rules differ between the header and the extensions, and
// getting them wrong is the classic CEF bug: a pipe in a hostname shifts
// every header field after it, and an unescaped '=' in a value splits it
// into a phantom key.
func CEF(r Record) string {
	sig := r.Kind
	if v, ok := r.Body["rule"].(string); ok && v != "" {
		sig = v
	} else if v, ok := r.Body["sourceId"].(string); ok && v != "" {
		sig = r.Kind + ":" + v
	}
	name := r.Summary
	if name == "" {
		name = r.Kind
	}
	ext := [][2]string{
		{"rt", fmt.Sprint(r.At.UnixMilli())},
		{"cat", r.Kind},
		{"msg", r.Summary},
	}
	if r.Hostname != "" {
		ext = append(ext, [2]string{"dvchost", r.Hostname})
	}
	if r.DeviceID != "" {
		ext = append(ext, [2]string{"deviceExternalId", r.DeviceID})
	}
	// Remaining scalar body fields as custom strings, in a stable order so
	// the same record always renders the same line. CEF defines cs1..cs6.
	var keys []string
	for k, v := range r.Body {
		switch v.(type) {
		case string, bool, int, int64, float64:
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= 6 {
			break
		}
		n := fmt.Sprint(i + 1)
		ext = append(ext, [2]string{"cs" + n + "Label", k}, [2]string{"cs" + n, fmt.Sprint(r.Body[k])})
	}
	parts := make([]string, 0, len(ext))
	for _, kv := range ext {
		parts = append(parts, kv[0]+"="+cefExtValue(kv[1]))
	}
	return strings.Join([]string{
		"CEF:0", "DefendSec", "DefendSec", "1",
		cefHeader(sig), cefHeader(name), fmt.Sprint(cefSeverity(r.Severity)),
		strings.Join(parts, " "),
	}, "|")
}

// cefHeader escapes backslash and pipe; newlines are not allowed.
func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// cefExtValue escapes backslash, equals and line breaks.
func cefExtValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	return strings.NewReplacer("\r\n", `\n`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// cefSeverity maps onto CEF's 0–10 scale.
func cefSeverity(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}
