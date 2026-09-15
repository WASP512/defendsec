package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The policy document, in the same declarative YAML style as packs/sca/.
//
// It is a file so it can live in version control, be reviewed like code, and
// be diffed after an incident. A policy editable only through a web form has
// no history anyone can audit, and "who changed this rule and when" is the
// first question asked after a command that should not have been permitted.

// Scope is what a limit counts across.
type Scope string

const (
	// ScopeFleet counts every host. This is the one that stops a runaway
	// playbook: a per-host limit would happily isolate the whole estate one
	// host at a time.
	ScopeFleet Scope = "fleet"
	// ScopeHost counts one host.
	ScopeHost Scope = "host"
)

// Rule permits or denies a set of commands.
type Rule struct {
	ID     string `yaml:"id"`
	Effect Effect `yaml:"effect"`
	// Commands the rule covers. "*" matches every command type.
	Commands []string `yaml:"commands"`
	// Roles the rule applies to. Empty means every role.
	Roles []string `yaml:"roles"`
	// Actors the rule applies to, by ledger identity. Empty means every
	// actor. Useful for narrowing a capability to named people.
	Actors []string `yaml:"actors"`
	// HostClasses the target must carry. Empty means any host. "*" is the
	// same as empty and is accepted because people write it.
	HostClasses []string `yaml:"host_classes"`
	// ExcludeHostClasses excludes hosts carrying any of these, so a broad
	// allow can be written without a second deny rule.
	ExcludeHostClasses []string `yaml:"exclude_host_classes"`
	// RequireApprovals is the number of distinct approvers needed. 0 and 1
	// both mean the issuer alone.
	RequireApprovals int `yaml:"require_approvals"`
	// Window restricts when the rule applies.
	Window *TimeWindow `yaml:"window"`
	// Reason is shown when a deny rule fires. Required on deny rules: a
	// denial an operator cannot understand becomes a ticket, then a bypass.
	Reason string `yaml:"reason"`
}

// TimeWindow restricts a rule to certain hours and days.
type TimeWindow struct {
	// Hours is "HH:MM-HH:MM" in the document's timezone. A window that wraps
	// past midnight is supported, because change freezes usually do.
	Hours string `yaml:"hours"`
	// Days are three-letter names: mon, tue, wed, thu, fri, sat, sun.
	Days []string `yaml:"days"`

	start, end int // minutes from midnight
	wraps      bool
	days       map[time.Weekday]bool
	location   *time.Location
}

// Limit caps how many commands of a kind may be issued in a window.
type Limit struct {
	ID       string   `yaml:"id"`
	Commands []string `yaml:"commands"`
	Scope    Scope    `yaml:"scope"`
	Max      int      `yaml:"max"`
	// Per is a duration: "1h", "15m", "24h".
	Per string `yaml:"per"`

	window time.Duration
}

// Document is a whole policy.
type Document struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`
	// Timezone the time windows are expressed in, IANA form. Defaults to UTC
	// rather than the server's local zone: a policy whose meaning depends on
	// where the server happens to sit is a policy nobody can review.
	Timezone string  `yaml:"timezone"`
	Rules    []Rule  `yaml:"rules"`
	Limits   []Limit `yaml:"limits"`

	// Hash is the SHA-256 of the document as loaded, recorded with every
	// decision so the ledger says which policy text permitted a command
	// rather than which text happens to be on disk today.
	Hash string `yaml:"-"`
	// Source is where it was loaded from.
	Source string `yaml:"-"`
}

// Load reads and validates a policy file.
func Load(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	doc, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	doc.Source = path
	return doc, nil
}

// Parse validates a policy document.
//
// Validation is strict and refuses on any problem. A policy that half-loads is
// worse than none: the operator believes the rules are in force, and the ones
// that failed to parse are exactly the ones nobody notices are missing.
func Parse(raw []byte) (*Document, error) {
	var doc Document
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a misspelled key must fail, not be ignored
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("policy version %d is not supported, want 1", doc.Version)
	}
	if strings.TrimSpace(doc.Name) == "" {
		return nil, fmt.Errorf("policy needs a name")
	}

	loc := time.UTC
	if tz := strings.TrimSpace(doc.Timezone); tz != "" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("unknown timezone %q: %w", tz, err)
		}
		loc = l
	}

	seen := map[string]bool{}
	for i := range doc.Rules {
		r := &doc.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("rule %d has no id; ids appear in the ledger and must be stable", i+1)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true

		switch r.Effect {
		case EffectPermit, EffectDeny:
		case "":
			return nil, fmt.Errorf("rule %q has no effect; write permit or deny explicitly", r.ID)
		default:
			return nil, fmt.Errorf("rule %q has effect %q, want permit or deny", r.ID, r.Effect)
		}
		if len(r.Commands) == 0 {
			return nil, fmt.Errorf("rule %q names no commands", r.ID)
		}
		if r.Effect == EffectDeny && strings.TrimSpace(r.Reason) == "" {
			// A denial an operator cannot understand becomes a support
			// ticket, and then a bypass.
			return nil, fmt.Errorf("deny rule %q must give a reason, which is shown to whoever it stops", r.ID)
		}
		if r.Effect == EffectDeny && r.RequireApprovals > 0 {
			return nil, fmt.Errorf("rule %q denies and also sets require_approvals, which cannot both be meant", r.ID)
		}
		if r.RequireApprovals < 0 {
			return nil, fmt.Errorf("rule %q has a negative require_approvals", r.ID)
		}
		if r.Window != nil {
			if err := r.Window.compile(loc); err != nil {
				return nil, fmt.Errorf("rule %q: %w", r.ID, err)
			}
		}
	}

	seenLimits := map[string]bool{}
	for i := range doc.Limits {
		l := &doc.Limits[i]
		if strings.TrimSpace(l.ID) == "" {
			return nil, fmt.Errorf("limit %d has no id", i+1)
		}
		if seenLimits[l.ID] {
			return nil, fmt.Errorf("duplicate limit id %q", l.ID)
		}
		seenLimits[l.ID] = true
		if len(l.Commands) == 0 {
			return nil, fmt.Errorf("limit %q names no commands", l.ID)
		}
		if l.Max < 0 {
			return nil, fmt.Errorf("limit %q has a negative max", l.ID)
		}
		switch l.Scope {
		case ScopeFleet, ScopeHost:
		case "":
			l.Scope = ScopeFleet
		default:
			return nil, fmt.Errorf("limit %q has scope %q, want fleet or host", l.ID, l.Scope)
		}
		d, err := time.ParseDuration(strings.TrimSpace(l.Per))
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("limit %q needs a positive duration in per, for example 1h", l.ID)
		}
		l.window = d
	}

	sum := sha256.Sum256(raw)
	doc.Hash = hex.EncodeToString(sum[:])
	return &doc, nil
}

func (w *TimeWindow) compile(loc *time.Location) error {
	w.location = loc
	w.days = map[time.Weekday]bool{}
	for _, d := range w.Days {
		wd, ok := weekdays[strings.ToLower(strings.TrimSpace(d))]
		if !ok {
			return fmt.Errorf("unknown day %q, want mon tue wed thu fri sat or sun", d)
		}
		w.days[wd] = true
	}

	hours := strings.TrimSpace(w.Hours)
	if hours == "" {
		w.start, w.end = 0, 24*60
		return nil
	}
	from, to, ok := strings.Cut(hours, "-")
	if !ok {
		return fmt.Errorf("hours %q is not in HH:MM-HH:MM form", w.Hours)
	}
	start, err := parseMinutes(from)
	if err != nil {
		return fmt.Errorf("hours %q: %w", w.Hours, err)
	}
	end, err := parseMinutes(to)
	if err != nil {
		return fmt.Errorf("hours %q: %w", w.Hours, err)
	}
	if start == end {
		return fmt.Errorf("hours %q covers no time at all", w.Hours)
	}
	// A window that wraps past midnight is supported, because change freezes
	// usually do: "22:00-06:00" is a night, not a mistake.
	w.start, w.end, w.wraps = start, end, end < start
	return nil
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday,
	"sat": time.Saturday,
}

func parseMinutes(s string) (int, error) {
	s = strings.TrimSpace(s)
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	var hh, mm int
	if _, err := fmt.Sscanf(h, "%d", &hh); err != nil || hh < 0 || hh > 24 {
		return 0, fmt.Errorf("%q has an unusable hour", s)
	}
	if _, err := fmt.Sscanf(m, "%d", &mm); err != nil || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("%q has an unusable minute", s)
	}
	return hh*60 + mm, nil
}

// contains reports whether t falls inside the window.
func (w *TimeWindow) contains(t time.Time) bool {
	if w == nil {
		return true
	}
	loc := w.location
	if loc == nil {
		loc = time.UTC
	}
	local := t.In(loc)
	if len(w.days) > 0 && !w.days[local.Weekday()] {
		return false
	}
	mins := local.Hour()*60 + local.Minute()
	if w.wraps {
		return mins >= w.start || mins < w.end
	}
	return mins >= w.start && mins < w.end
}

// matches reports whether a rule applies to a request.
func (r *Rule) matches(req Request) bool {
	if !matchesList(r.Commands, req.CommandType) {
		return false
	}
	if len(r.Roles) > 0 && !matchesList(r.Roles, req.Role) {
		return false
	}
	if len(r.Actors) > 0 && !matchesList(r.Actors, req.Actor) {
		return false
	}
	for _, exclude := range r.ExcludeHostClasses {
		if hasClass(req.HostClasses, exclude) {
			return false
		}
	}
	if len(r.HostClasses) > 0 && !hasAnyClass(req.HostClasses, r.HostClasses) {
		return false
	}
	return r.Window.contains(req.At)
}

func (r *Rule) denyReason(req Request) string {
	return fmt.Sprintf("Rule %q denies %s here: %s", r.ID, req.CommandType, strings.TrimSpace(r.Reason))
}

func (l *Limit) covers(commandType string) bool {
	return matchesList(l.Commands, commandType)
}

func matchesList(list []string, want string) bool {
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "*" || strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

// hasClass reports whether classes contains want. "*" matches any host,
// including one with no classes at all — the plain reading of a wildcard, and
// the same meaning it has in commands and roles. A rule that should only touch
// deliberately-tagged hosts names the tags.
func hasClass(classes []string, want string) bool {
	if strings.TrimSpace(want) == "*" {
		return true
	}
	for _, c := range classes {
		if strings.EqualFold(strings.TrimSpace(c), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func hasAnyClass(classes, want []string) bool {
	for _, w := range want {
		if hasClass(classes, w) {
			return true
		}
	}
	return false
}

// RuleIDs lists the rule ids, for reporting.
func (d *Document) RuleIDs() []string {
	out := make([]string, 0, len(d.Rules))
	for _, r := range d.Rules {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}
