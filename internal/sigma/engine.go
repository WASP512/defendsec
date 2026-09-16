package sigma

import (
	"sort"
	"strings"
	"time"

	"defendsec/internal/events"
)

// Matching events against rules.

// Match is one rule firing on one event.
type Match struct {
	RuleID     string   `json:"ruleId,omitempty"`
	RuleTitle  string   `json:"ruleTitle"`
	RuleHash   string   `json:"ruleHash"`
	RuleSource string   `json:"ruleSource,omitempty"`
	Level      Level    `json:"level"`
	Techniques []string `json:"techniques,omitempty"`
	Tactics    []string `json:"tactics,omitempty"`
	// Description and FalsePositives travel with the match, because an
	// analyst deciding whether this matters reads them at that moment and
	// should not have to go and find the rule file.
	Description    string        `json:"description,omitempty"`
	FalsePositives []string      `json:"falsePositives,omitempty"`
	Event          *events.Event `json:"event"`
	At             time.Time     `json:"at"`
}

// Engine evaluates a rule set.
type Engine struct {
	set *RuleSet
	// byCategory indexes rules by logsource category, so an event is only
	// compared against rules that could apply to it. With thousands of rules
	// and thousands of events per second, evaluating every rule against every
	// event is the difference between a sensor and an outage.
	byCategory  map[string][]*Rule
	anyCategory []*Rule
}

// NewEngine indexes a rule set for matching.
func NewEngine(set *RuleSet) *Engine {
	e := &Engine{set: set, byCategory: map[string][]*Rule{}}
	for _, r := range set.Rules() {
		category := strings.ToLower(strings.TrimSpace(r.Logsource.Category))
		if category == "" {
			// A rule with no category is compared against everything, which
			// is what its author asked for.
			e.anyCategory = append(e.anyCategory, r)
			continue
		}
		e.byCategory[category] = append(e.byCategory[category], r)
	}
	return e
}

// RuleSet returns the loaded rules.
func (e *Engine) RuleSet() *RuleSet {
	if e == nil {
		return nil
	}
	return e.set
}

// categoryFor maps an event kind onto the Sigma logsource categories that
// describe it.
//
// The mapping is one-to-many because Sigma's Linux categories and DefendSec's
// event kinds were not designed together: process_creation is the near-
// universal category for an exec, but rules also use "process_creation" with
// product: linux and service names. Matching on category alone, generously, is
// the reading that lets community rules work.
func categoryFor(kind events.Kind) []string {
	switch kind {
	case events.KindProcess:
		return []string{"process_creation"}
	case events.KindNetwork:
		return []string{"network_connection", "firewall"}
	case events.KindFile:
		return []string{"file_event", "file_change", "file_create", "file_delete"}
	case events.KindPrivilege:
		return []string{"process_creation", "auth"}
	case events.KindModule:
		return []string{"driver_load", "kernel_module"}
	default:
		return nil
	}
}

// Match returns every rule that fires on an event.
func (e *Engine) Match(ev *events.Event) []Match {
	if e == nil || ev == nil {
		return nil
	}

	candidates := append([]*Rule(nil), e.anyCategory...)
	for _, category := range categoryFor(ev.Kind) {
		candidates = append(candidates, e.byCategory[category]...)
	}

	seen := map[*Rule]bool{}
	var out []Match
	for _, r := range candidates {
		if seen[r] {
			continue
		}
		seen[r] = true
		if !r.condition.eval(ev, r.selections) {
			continue
		}
		out = append(out, Match{
			RuleID: r.ID, RuleTitle: r.Title, RuleHash: r.hash, RuleSource: r.source,
			Level: r.Level, Techniques: r.Techniques(), Tactics: r.Tactics(),
			Description: r.Description, FalsePositives: r.FalsePositives,
			Event: ev, At: ev.At,
		})
	}

	// Most severe first: an analyst reading a burst of matches should see the
	// one that matters at the top.
	sort.SliceStable(out, func(i, j int) bool {
		return levelRank(out[i].Level) > levelRank(out[j].Level)
	})
	return out
}

func levelRank(l Level) int {
	switch l {
	case LevelCritical:
		return 4
	case LevelHigh:
		return 3
	case LevelMedium:
		return 2
	case LevelLow:
		return 1
	default:
		return 0
	}
}

// Coverage summarises what the loaded rules can and cannot see (roadmap 3.4).
type Coverage struct {
	Rules   int            `json:"rules"`
	Skipped []SkippedRule  `json:"skipped,omitempty"`
	ByLevel map[string]int `json:"byLevel"`
	// Techniques are the ATT&CK ids the loaded rules cover.
	Techniques []string `json:"techniques"`
	Tactics    []string `json:"tactics"`
	// ByCategory shows which event kinds have rules at all. A category with
	// no rules is a blind spot, and it is the number an honest coverage map
	// has to show.
	ByCategory map[string]int `json:"byCategory"`
}

// Describe summarises the rule set.
func (e *Engine) Describe() Coverage {
	c := Coverage{
		ByLevel:    map[string]int{},
		ByCategory: map[string]int{},
	}
	if e == nil {
		return c
	}
	c.Skipped = e.set.Skipped()

	techniques := map[string]bool{}
	tactics := map[string]bool{}
	for _, r := range e.set.Rules() {
		c.Rules++
		c.ByLevel[string(r.Level)]++
		category := strings.ToLower(strings.TrimSpace(r.Logsource.Category))
		if category == "" {
			category = "(any)"
		}
		c.ByCategory[category]++
		for _, t := range r.Techniques() {
			techniques[t] = true
		}
		for _, t := range r.Tactics() {
			tactics[t] = true
		}
	}

	for t := range techniques {
		c.Techniques = append(c.Techniques, t)
	}
	for t := range tactics {
		c.Tactics = append(c.Tactics, t)
	}
	sort.Strings(c.Techniques)
	sort.Strings(c.Tactics)
	return c
}
