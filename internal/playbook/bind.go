package playbook

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Binding a triggering finding into a step's payload.
//
// # Why this is structured rather than textual
//
// The obvious implementation is string templating: replace "{{alert.path}}"
// inside the rendered JSON. That is an injection hole. A file path containing
// a quote or a brace — which an attacker can create deliberately, since these
// paths come from files on a compromised host — would break out of its JSON
// string and rewrite the rest of the payload. The playbook would then issue a
// command nobody wrote, correctly signed, with full authority.
//
// So substitution happens on the *decoded* value, never on serialised text. A
// payload value that is exactly a placeholder is replaced with the bound value
// as a Go value, and the payload is marshalled afterwards. A path containing a
// quote ends up as a quoted string containing a quote, which is what it is.
// Placeholders embedded in longer strings are rejected rather than
// interpolated, because that is the case where the distinction gets lost.

// Alert is what a triggering finding contributes.
type Alert struct {
	ID       string
	Kind     string
	Severity string
	DeviceID string
	Hostname string
	Title    string
	// Path is the file a FIM finding concerns, where there is one.
	Path string
}

// placeholders maps the accepted references to their values.
func (a Alert) placeholders() map[string]string {
	return map[string]string{
		"{{alert.id}}":       a.ID,
		"{{alert.kind}}":     a.Kind,
		"{{alert.severity}}": a.Severity,
		"{{alert.deviceId}}": a.DeviceID,
		"{{alert.hostname}}": a.Hostname,
		"{{alert.title}}":    a.Title,
		"{{alert.path}}":     a.Path,
	}
}

// Bind substitutes alert values into a step payload.
//
// A placeholder that has no value — "{{alert.path}}" on a finding with no
// path — is an error rather than an empty string. Quarantining "" or killing a
// process named "" is a command nobody intended, and it would be signed.
func Bind(payload map[string]any, a Alert) (map[string]any, error) {
	values := a.placeholders()
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		bound, err := bindValue(v, values, k)
		if err != nil {
			return nil, err
		}
		out[k] = bound
	}
	return out, nil
}

func bindValue(v any, values map[string]string, field string) (any, error) {
	switch typed := v.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if replacement, ok := values[trimmed]; ok {
			if replacement == "" {
				return nil, fmt.Errorf(
					"field %q references %s, but the finding has no such value; the step would run against nothing",
					field, trimmed)
			}
			return replacement, nil
		}
		// A placeholder embedded in a longer string is refused rather than
		// interpolated. Interpolation is where a value stops being a value
		// and becomes part of the surrounding syntax.
		if strings.Contains(typed, "{{") {
			return nil, fmt.Errorf(
				"field %q embeds a placeholder inside a longer string (%q); a placeholder must be the whole value",
				field, typed)
		}
		return typed, nil

	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, inner := range typed {
			bound, err := bindValue(inner, values, field+"."+k)
			if err != nil {
				return nil, err
			}
			out[k] = bound
		}
		return out, nil

	case []any:
		out := make([]any, len(typed))
		for i, inner := range typed {
			bound, err := bindValue(inner, values, fmt.Sprintf("%s[%d]", field, i))
			if err != nil {
				return nil, err
			}
			out[i] = bound
		}
		return out, nil

	default:
		return v, nil
	}
}

// Matches reports whether a finding triggers this playbook.
func (p *Playbook) Matches(a Alert, hostClasses []string) bool {
	t := p.Trigger
	if t == nil {
		return false
	}
	if !contains(t.AlertKinds, a.Kind) {
		return false
	}
	if len(t.Severities) > 0 && !contains(t.Severities, a.Severity) {
		return false
	}
	if t.PathPrefix != "" {
		if a.Path == "" || !strings.HasPrefix(a.Path, t.PathPrefix) {
			return false
		}
	}
	if len(t.HostClasses) > 0 {
		var found bool
		for _, want := range t.HostClasses {
			if contains(hostClasses, want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func hashOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
