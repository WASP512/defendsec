package sca

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"defendsec/internal/presence"
)

type Check struct {
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	Severity  string `yaml:"severity"`
	Type      string `yaml:"type"`
	Path      string `yaml:"path"`
	MustMatch string `yaml:"must_match"`
	Field     string `yaml:"field"`
	Expect    string `yaml:"expect"`
}

type Pack struct {
	ID       string  `yaml:"id"`
	Name     string  `yaml:"name"`
	Platform string  `yaml:"platform"`
	Checks   []Check `yaml:"checks"`
}

type Result struct {
	PackID   string `json:"packId"`
	CheckID  string `json:"checkId"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail"`
}

func LoadPack(path string) (*Pack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pack Pack
	if err := yaml.Unmarshal(raw, &pack); err != nil {
		return nil, err
	}
	if pack.ID == "" {
		return nil, fmt.Errorf("sca pack missing id")
	}
	return &pack, nil
}

func DefaultLinuxSSHPath() string {
	return firstExisting(
		"packs/sca/linux-ssh-v1.yaml",
		filepath.Join("..", "packs", "sca", "linux-ssh-v1.yaml"),
		filepath.Join("..", "..", "packs", "sca", "linux-ssh-v1.yaml"),
	)
}

func DefaultLinuxHostPath() string {
	return firstExisting(
		"packs/sca/linux-host-v1.yaml",
		filepath.Join("..", "packs", "sca", "linux-host-v1.yaml"),
		filepath.Join("..", "..", "packs", "sca", "linux-host-v1.yaml"),
	)
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}

func LoadDefaultLinuxSSH() (*Pack, error) {
	return LoadPack(DefaultLinuxSSHPath())
}

func LoadDefaultLinuxHost() (*Pack, error) {
	return LoadPack(DefaultLinuxHostPath())
}

func EvalFileRegex(check Check) Result {
	res := Result{
		PackID:   "",
		CheckID:  check.ID,
		Title:    check.Title,
		Severity: check.Severity,
		Pass:     false,
	}
	if check.MustMatch == "" || check.Path == "" {
		res.Detail = "check missing path or must_match"
		return res
	}
	content, sources, err := readConfigWithDropIns(check.Path)
	if err != nil {
		// Missing sshd_config is common on workstations without openssh-server.
		if os.IsNotExist(err) {
			res.Pass = true
			res.Detail = fmt.Sprintf("skipped: %s not present", check.Path)
			return res
		}
		res.Detail = fmt.Sprintf("read %s: %v", check.Path, err)
		return res
	}
	re, err := regexp.Compile(check.MustMatch)
	if err != nil {
		res.Detail = fmt.Sprintf("invalid regex: %v", err)
		return res
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if re.MatchString(trimmed) {
			res.Pass = true
			res.Detail = "matched " + strings.Join(sources, ", ")
			return res
		}
	}
	res.Detail = fmt.Sprintf("no line in %s matched %q", strings.Join(sources, ", "), check.MustMatch)
	return res
}

// readConfigWithDropIns loads path plus sibling path.d/*.conf (Fedora/RHEL sshd drop-ins).
func readConfigWithDropIns(path string) (string, []string, error) {
	var b strings.Builder
	sources := []string{}
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", nil, err
	}
	if err == nil {
		b.Write(raw)
		b.WriteByte('\n')
		sources = append(sources, path)
	}
	dropDir := path + ".d"
	entries, dirErr := os.ReadDir(dropDir)
	if dirErr == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || (!strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".cfg")) {
				continue
			}
			p := filepath.Join(dropDir, name)
			dropRaw, readErr := os.ReadFile(p)
			if readErr != nil {
				continue
			}
			b.Write(dropRaw)
			b.WriteByte('\n')
			sources = append(sources, p)
		}
	}
	if len(sources) == 0 {
		if err != nil {
			return "", nil, err
		}
		return "", nil, os.ErrNotExist
	}
	return b.String(), sources, nil
}

func EvalInventoryField(check Check, dev presence.Device) Result {
	res := Result{
		CheckID:  check.ID,
		Title:    check.Title,
		Severity: check.Severity,
		Pass:     false,
	}
	expect, err := parseExpect(check.Expect)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	got, ok := inventoryValue(dev, check.Field)
	if !ok {
		res.Detail = fmt.Sprintf("unknown inventory field %q", check.Field)
		return res
	}
	res.Pass = valuesEqual(got, expect)
	if res.Pass {
		res.Detail = fmt.Sprintf("%s=%v matches expect", check.Field, got)
	} else {
		res.Detail = fmt.Sprintf("%s=%v expected %v", check.Field, got, expect)
	}
	return res
}

func EvalFileRegexChecks(pack *Pack) []Result {
	var out []Result
	for _, check := range pack.Checks {
		if check.Type != "file_regex" {
			continue
		}
		r := EvalFileRegex(check)
		r.PackID = pack.ID
		out = append(out, r)
	}
	return out
}

func EvalInventoryFieldChecks(pack *Pack, dev presence.Device) []Result {
	var out []Result
	for _, check := range pack.Checks {
		if check.Type != "inventory_field" {
			continue
		}
		r := EvalInventoryField(check, dev)
		r.PackID = pack.ID
		out = append(out, r)
	}
	return out
}

func parseExpect(raw string) (any, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	switch s {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	case "":
		return nil, fmt.Errorf("expect value required")
	default:
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n, nil
		}
		return raw, nil
	}
}

func inventoryValue(dev presence.Device, field string) (any, bool) {
	switch strings.ToLower(field) {
	case "firewall":
		if dev.Firewall == nil {
			return nil, true
		}
		return *dev.Firewall, true
	case "diskencryption", "disk_encryption":
		if dev.DiskEncryption == nil {
			return nil, true
		}
		return *dev.DiskEncryption, true
	case "isolated":
		return dev.Isolated, true
	case "platform":
		return dev.Platform, true
	case "hostname":
		return dev.Hostname, true
	default:
		return nil, false
	}
}

func valuesEqual(got, expect any) bool {
	if got == nil && expect == nil {
		return true
	}
	if b, ok := expect.(bool); ok {
		if g, ok := got.(bool); ok {
			return g == b
		}
		return false
	}
	return fmt.Sprint(got) == fmt.Sprint(expect)
}
