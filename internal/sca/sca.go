package sca

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"defendsec/internal/controls"
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
	// Controls are framework control identifiers this check speaks to
	// (roadmap 1.7). They are carried in the pack rather than inferred,
	// because only the person writing the check knows which control it is
	// actually testing. A pack-level default applies where a check is silent.
	Controls []string `yaml:"controls"`

	// --- file_mode (roadmap 3.7) ---
	// MaxMode is the most permissive permission the file may carry, in octal:
	// "0644" passes a file that is 0600 and fails one that is 0666. Expressed
	// as a maximum rather than an exact value because benchmarks say "no more
	// permissive than", and an exact match would fail a correctly-hardened
	// host that is stricter than the baseline.
	MaxMode string `yaml:"max_mode"`
	// Owner and Group are the required owner, by name or numeric id.
	Owner string `yaml:"owner"`
	Group string `yaml:"group"`

	// --- mount_option ---
	// MountPoint is the directory to inspect, e.g. "/tmp".
	MountPoint string `yaml:"mount_point"`
	// RequireOptions must all be present; ForbidOptions must all be absent.
	RequireOptions []string `yaml:"require_options"`
	ForbidOptions  []string `yaml:"forbid_options"`

	// --- sysctl ---
	// Key is a kernel parameter in dotted form, e.g.
	// "net.ipv4.conf.all.rp_filter".
	Key string `yaml:"key"`

	// --- package ---
	// Package is the package name; Present says whether it must be installed.
	// A pointer so "absent" is expressible: a plain bool would make the
	// common case of checking for an unwanted package the same as omitting
	// the field.
	Package string `yaml:"package"`
	Present *bool  `yaml:"present"`

	// --- systemd_unit ---
	// Unit is the unit name, e.g. "sshd.service".
	Unit string `yaml:"unit"`
	// Enabled and Active are the required states; nil means "do not care".
	Enabled *bool `yaml:"enabled"`
	Active  *bool `yaml:"active"`

	// --- command ---
	// Command is an argv list, never a shell string. See command.go for why
	// that distinction is load-bearing rather than stylistic.
	Command []string `yaml:"command"`
	// OutputMatches is a regular expression the combined output must match.
	OutputMatches string `yaml:"output_matches"`
	// OutputNotMatches is one it must not match.
	OutputNotMatches string `yaml:"output_not_matches"`
	// ExitCode, when set, is the exit status the command must return. A
	// pointer so requiring zero is distinguishable from not caring.
	ExitCode *int `yaml:"exit_code"`
}

type Pack struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Platform string `yaml:"platform"`
	// Controls apply to every check in the pack that does not name its own.
	Controls []string `yaml:"controls"`
	Checks   []Check  `yaml:"checks"`
}

type Result struct {
	PackID   string `json:"packId"`
	CheckID  string `json:"checkId"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail"`
	// Controls travels with the result so an alert raised from it is tagged
	// without the alerting code needing to reload the pack.
	Controls []string `json:"controls,omitempty"`
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
	if err := pack.resolveControls(); err != nil {
		return nil, fmt.Errorf("sca pack %s: %w", pack.ID, err)
	}
	if err := pack.validateChecks(); err != nil {
		return nil, fmt.Errorf("sca pack %s: %w", pack.ID, err)
	}
	return &pack, nil
}

// validateChecks refuses a pack the engine cannot run.
//
// Caught at load rather than at evaluation: a check with a typo'd type would
// otherwise fail silently on every host in the fleet, and the pack would still
// look like it was running. An unusable check is a missing check, and a
// missing check reads as a passing one.
func (p *Pack) validateChecks() error {
	seen := map[string]bool{}
	for i := range p.Checks {
		c := &p.Checks[i]
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("check %d has no id", i+1)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate check id %q", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Type) == "" {
			return fmt.Errorf("check %q has no type", c.ID)
		}

		var known bool
		for _, t := range KnownCheckTypes() {
			if c.Type == t {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("check %q has unknown type %q; the engine understands %s",
				c.ID, c.Type, strings.Join(KnownCheckTypes(), ", "))
		}

		if err := c.validate(); err != nil {
			return fmt.Errorf("check %q: %w", c.ID, err)
		}
	}
	return nil
}

// validate checks that a check carries the fields its type needs.
func (c *Check) validate() error {
	switch c.Type {
	case "file_regex":
		if c.Path == "" || c.MustMatch == "" {
			return fmt.Errorf("file_regex needs path and must_match")
		}
		if _, err := regexp.Compile(c.MustMatch); err != nil {
			return fmt.Errorf("must_match is not a valid regular expression: %w", err)
		}
	case "inventory_field":
		if c.Field == "" || c.Expect == "" {
			return fmt.Errorf("inventory_field needs field and expect")
		}
	case "file_mode":
		if c.Path == "" {
			return fmt.Errorf("file_mode needs path")
		}
		if c.MaxMode == "" && c.Owner == "" && c.Group == "" {
			return fmt.Errorf("file_mode needs at least one of max_mode, owner or group")
		}
		if c.MaxMode != "" {
			if _, err := strconv.ParseUint(strings.TrimPrefix(c.MaxMode, "0o"), 8, 32); err != nil {
				return fmt.Errorf("max_mode %q is not octal", c.MaxMode)
			}
		}
	case "mount_option":
		if c.MountPoint == "" {
			return fmt.Errorf("mount_option needs mount_point")
		}
		if len(c.RequireOptions) == 0 && len(c.ForbidOptions) == 0 {
			return fmt.Errorf("mount_option needs require_options or forbid_options")
		}
	case "sysctl":
		if c.Key == "" || c.Expect == "" {
			return fmt.Errorf("sysctl needs key and expect")
		}
	case "package":
		if c.Package == "" {
			return fmt.Errorf("package needs a package name")
		}
	case "systemd_unit":
		if c.Unit == "" {
			return fmt.Errorf("systemd_unit needs unit")
		}
		if c.Enabled == nil && c.Active == nil {
			return fmt.Errorf("systemd_unit needs enabled or active")
		}
	case "command":
		if len(c.Command) == 0 {
			return fmt.Errorf("command needs an argv list")
		}
		// Rejected at load, not at run: a pack naming an executable this
		// host will refuse should fail where somebody is looking at it.
		if err := checkAllowed(c.Command[0]); err != nil {
			return err
		}
		if c.OutputMatches == "" && c.OutputNotMatches == "" && c.ExitCode == nil {
			return fmt.Errorf("command needs output_matches, output_not_matches or exit_code")
		}
		for _, expr := range []string{c.OutputMatches, c.OutputNotMatches} {
			if expr == "" {
				continue
			}
			if _, err := regexp.Compile(expr); err != nil {
				return fmt.Errorf("%q is not a valid regular expression: %w", expr, err)
			}
		}
	}
	return nil
}

// resolveControls validates every control tag and pushes the pack-level
// default down onto the checks that do not name their own, so a Check is
// self-describing everywhere it is used afterwards.
//
// A bad identifier fails the load. The alternative — dropping it quietly —
// produces a pack that looks tagged and evidences nothing, which is the
// failure mode hardest to notice and most damaging to find during an audit.
func (p *Pack) resolveControls() error {
	defaults, err := controls.ParseIDs(p.Controls)
	if err != nil {
		return fmt.Errorf("pack-level controls: %w", err)
	}
	if err := knownControls(defaults); err != nil {
		return fmt.Errorf("pack-level controls: %w", err)
	}
	p.Controls = controls.Strings(defaults)

	for i := range p.Checks {
		c := &p.Checks[i]
		if len(c.Controls) == 0 {
			c.Controls = append([]string(nil), p.Controls...)
			continue
		}
		ids, err := controls.ParseIDs(c.Controls)
		if err != nil {
			return fmt.Errorf("check %s: %w", c.ID, err)
		}
		if err := knownControls(ids); err != nil {
			return fmt.Errorf("check %s: %w", c.ID, err)
		}
		c.Controls = controls.Strings(ids)
	}
	return nil
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
		Controls: check.Controls,
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
		Controls: check.Controls,
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

// knownControls rejects identifiers the catalog does not hold.
//
// A well-formed identifier for a control that does not exist is the failure
// mode hardest to notice: the pack looks tagged, the finding carries the tag,
// and the compliance view never shows it because there is nothing to show it
// against. Caught at load, where somebody is reading the file.
func knownControls(ids []controls.ID) error {
	var missing []string
	for _, id := range ids {
		if _, ok := controls.Lookup(id); !ok {
			missing = append(missing, string(id))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("control(s) not in the catalog: %s", strings.Join(missing, ", "))
	}
	return nil
}

// PacksDir returns the shipped pack directory, searching the same relative
// locations the individual loaders do.
func PacksDir() string {
	return firstExistingDir("packs/sca",
		filepath.Join("..", "packs", "sca"),
		filepath.Join("..", "..", "packs", "sca"))
}

func firstExistingDir(paths ...string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

// LoadDir reads every pack in a directory.
//
// One bad pack fails the load, as with policy and playbooks: a partially
// loaded set means the operator believes checks are running that are not, and
// the console reports a clean result for a benchmark half of which never ran.
func LoadDir(dir string) ([]*Pack, error) {
	if dir == "" {
		return nil, fmt.Errorf("no pack directory")
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	seen := map[string]string{}
	out := make([]*Pack, 0, len(matches))
	for _, path := range matches {
		pack, err := LoadPack(path)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[pack.ID]; dup {
			return nil, fmt.Errorf("duplicate pack id %q in %s and %s", pack.ID, prev, path)
		}
		seen[pack.ID] = path
		out = append(out, pack)
	}
	return out, nil
}
