// Package sigma evaluates Sigma detection rules over DefendSec's event stream
// (roadmap 3.3).
//
// Sigma rather than a DefendSec DSL, deliberately. Thousands of
// community-maintained rules already exist, operators already know the format,
// and a rule an analyst can read from another tool's repository and drop into
// a directory is worth more than a better language nobody writes rules in.
// Inventing a DSL would mean owning the content problem forever, which is the
// same trap benchmark scanning is (§3.1).
//
// # What this implements, and what it does not
//
// The subset here covers what community Linux rules actually use: detection
// blocks with named selections, field modifiers (contains, startswith,
// endswith, re, all, cidr, base64offset), value lists as OR, null tests, and
// condition expressions with and/or/not, parentheses, "all of"/"1 of" and
// wildcard selection references.
//
// Not implemented: aggregation conditions ("| count() > 5"), near/temporal
// correlation, and the correlation rule type. Those need state across events
// and a windowing model, and a half-implementation that silently matched
// nothing would be worse than a rule that refuses to load — so a rule using
// them is rejected at load time with the reason, rather than quietly never
// firing.
package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Level is a rule's severity.
type Level string

const (
	LevelInformational Level = "informational"
	LevelLow           Level = "low"
	LevelMedium        Level = "medium"
	LevelHigh          Level = "high"
	LevelCritical      Level = "critical"
)

// Status is a rule's maturity.
type Status string

// Rule is one Sigma rule.
type Rule struct {
	// Title and ID identify it; ID is the upstream UUID where there is one.
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Status      Status   `yaml:"status"`
	Description string   `yaml:"description"`
	Author      string   `yaml:"author"`
	Date        string   `yaml:"date"`
	Modified    string   `yaml:"modified"`
	References  []string `yaml:"references"`
	// Tags carry ATT&CK techniques as "attack.t1059.004" (roadmap 3.4).
	Tags []string `yaml:"tags"`

	Logsource Logsource `yaml:"logsource"`
	// Detection is the raw block: named selections plus a condition.
	Detection map[string]any `yaml:"detection"`
	// Fields are the attributes a rule wants shown with a match.
	Fields []string `yaml:"fields"`
	// FalsePositives is what the author expects to trip it, which an analyst
	// reads before deciding whether a match matters.
	FalsePositives []string `yaml:"falsepositives"`
	Level          Level    `yaml:"level"`

	// Compiled state.
	selections map[string]matcher
	condition  expr
	source     string
	hash       string
}

// Logsource narrows which events a rule applies to.
type Logsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// Source is where the rule was loaded from.
func (r *Rule) Source() string { return r.source }

// Hash identifies this rule text, recorded on every match so an alert says
// which version of a rule fired rather than which version is on disk now.
func (r *Rule) Hash() string { return r.hash }

// Techniques returns the ATT&CK technique ids from the rule's tags, upper-cased
// in the form ATT&CK publishes them.
func (r *Rule) Techniques() []string {
	var out []string
	seen := map[string]bool{}
	for _, tag := range r.Tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		rest, ok := strings.CutPrefix(tag, "attack.")
		if !ok {
			continue
		}
		// Technique tags look like t1059 or t1059.004. Tactic tags
		// (execution, persistence) and everything else are not techniques.
		if !strings.HasPrefix(rest, "t") || len(rest) < 5 {
			continue
		}
		if _, err := fmt.Sscanf(rest[1:5], "%4d", new(int)); err != nil {
			continue
		}
		id := strings.ToUpper(rest)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Tactics returns the ATT&CK tactic names from the rule's tags.
func (r *Rule) Tactics() []string {
	var out []string
	seen := map[string]bool{}
	for _, tag := range r.Tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		rest, ok := strings.CutPrefix(tag, "attack.")
		if !ok || strings.HasPrefix(rest, "t") && len(rest) >= 5 {
			continue
		}
		if rest == "" || seen[rest] {
			continue
		}
		seen[rest] = true
		out = append(out, rest)
	}
	sort.Strings(out)
	return out
}

// Parse compiles a rule.
//
// Compilation happens once at load. A rule whose condition or modifiers cannot
// be understood fails here rather than at match time: a rule that silently
// matches nothing is indistinguishable from a quiet network, and an operator
// who believes a detection is running is worse off than one who knows it is
// not.
func Parse(raw []byte) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse rule: %w", err)
	}
	if strings.TrimSpace(r.Title) == "" {
		return nil, fmt.Errorf("rule has no title")
	}
	if len(r.Detection) == 0 {
		return nil, fmt.Errorf("rule %q has no detection block", r.Title)
	}

	rawCondition, ok := r.Detection["condition"]
	if !ok {
		return nil, fmt.Errorf("rule %q has no condition", r.Title)
	}
	condition, err := conditionString(rawCondition)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.Title, err)
	}
	// Aggregations need state across events and a windowing model. Refused
	// rather than ignored: silently dropping the aggregation would turn
	// "more than five failures in a minute" into "any failure".
	if strings.Contains(condition, "|") {
		return nil, fmt.Errorf(
			"rule %q uses an aggregation condition (%q), which this engine does not implement; it would otherwise fire on every single event",
			r.Title, condition)
	}

	r.selections = map[string]matcher{}
	names := make([]string, 0, len(r.Detection))
	for name := range r.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m, err := compileSelection(r.Detection[name])
		if err != nil {
			return nil, fmt.Errorf("rule %q, selection %q: %w", r.Title, name, err)
		}
		r.selections[name] = m
	}

	parsed, err := parseCondition(condition, r.selectionNames())
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.Title, err)
	}
	r.condition = parsed

	if r.Level == "" {
		r.Level = LevelMedium
	}
	r.hash = hashOf(raw)
	return &r, nil
}

func (r *Rule) selectionNames() []string {
	out := make([]string, 0, len(r.selections))
	for name := range r.selections {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// conditionString normalises the condition, which Sigma allows as a string or
// a list of strings meaning OR.
func conditionString(raw any) (string, error) {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed), nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("condition list contains a non-string entry")
			}
			parts = append(parts, "("+strings.TrimSpace(s)+")")
		}
		return strings.Join(parts, " or "), nil
	default:
		return "", fmt.Errorf("condition must be a string or a list of strings")
	}
}

// Load reads a rule from disk.
func Load(path string) (*Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r.source = path
	return r, nil
}

// RuleSet is a loaded collection.
type RuleSet struct {
	rules []*Rule
	// skipped records rules that would not compile, with the reason. They are
	// reported rather than dropped: an operator needs to know a detection is
	// not running, and the usual cause is an unimplemented feature rather
	// than a broken file.
	skipped []SkippedRule
}

// SkippedRule is a rule that failed to load.
type SkippedRule struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// LoadDir reads every .yml and .yaml rule in a directory tree.
//
// Unlike SCA packs and policy, one bad rule does not fail the load. Rule
// directories are routinely populated by syncing a community repository of
// thousands of rules, a fraction of which use features no single engine
// implements; refusing to start would mean refusing every rule because of an
// unrelated one. The skipped ones are counted and surfaced instead, which is
// the honest middle: the operator sees exactly what is not running.
func LoadDir(dir string) (*RuleSet, error) {
	set := &RuleSet{}
	if dir == "" {
		return set, nil
	}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		rule, loadErr := Load(path)
		if loadErr != nil {
			set.skipped = append(set.skipped, SkippedRule{Source: path, Reason: loadErr.Error()})
			return nil
		}
		set.rules = append(set.rules, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(set.rules, func(i, j int) bool { return set.rules[i].Title < set.rules[j].Title })
	sort.Slice(set.skipped, func(i, j int) bool { return set.skipped[i].Source < set.skipped[j].Source })
	return set, nil
}

// Rules returns the compiled rules.
func (s *RuleSet) Rules() []*Rule {
	if s == nil {
		return nil
	}
	return s.rules
}

// Skipped returns the rules that would not compile, with reasons.
func (s *RuleSet) Skipped() []SkippedRule {
	if s == nil {
		return nil
	}
	return s.skipped
}

// Len reports how many rules are active.
func (s *RuleSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}
