package triage

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Alert summarisation and follow-up suggestions (roadmap 4.3).
//
// Both are deterministic. Summarisation here means grouping and counting, not
// prose generation: an operator opening a queue of two hundred alerts needs to
// know that a hundred and ninety of them are one upgrade rolling across the
// fleet, and that is a fact about the data rather than a judgement about it.

// Alert is the subset of an alert this package needs.
type Alert struct {
	ID         string
	DeviceID   string
	Hostname   string
	Kind       string
	Severity   string
	Title      string
	Status     string
	SourceID   string
	DetectedAt time.Time
}

// Cluster is a group of alerts that look like one event.
type Cluster struct {
	// Reason is why these were grouped, written for a reader.
	Reason string `json:"reason"`
	Kind   string `json:"kind,omitempty"`
	// Title is the shared alert title, when they share one.
	Title string `json:"title,omitempty"`
	// Hosts are the hosts involved, so "everywhere" and "one box" are
	// distinguishable at a glance.
	Hosts     []string  `json:"hosts"`
	AlertIDs  []string  `json:"alertIds"`
	Count     int       `json:"count"`
	Severity  string    `json:"severity"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Summary is what triage can say about a set of alerts.
type Summary struct {
	Total      int            `json:"total"`
	ByStatus   map[string]int `json:"byStatus"`
	BySeverity map[string]int `json:"bySeverity"`
	ByKind     map[string]int `json:"byKind"`
	// Clusters are alerts that look like one underlying event, largest
	// first. A fleet-wide cluster is usually a change; a single-host one is
	// usually the interesting one.
	Clusters []Cluster `json:"clusters,omitempty"`
	// Singletons are alerts that group with nothing else. Called out because
	// on a busy fleet the lone alert is the one worth reading, and it is the
	// one a queue sorted by time buries.
	Singletons []string `json:"singletons,omitempty"`
	// Notes are the plain observations worth stating, worst first.
	Notes []string `json:"notes,omitempty"`
}

// severityRank orders severities worst first.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// Summarise groups alerts into clusters and counts.
//
// Clustering is on (kind, title), which is deliberately crude. A cleverer
// similarity measure would group things that merely look alike, and an
// operator who trusts a cluster that silently swallowed an unrelated alert is
// worse off than one reading a slightly longer list.
func Summarise(alerts []Alert) Summary {
	out := Summary{
		Total:      len(alerts),
		ByStatus:   map[string]int{},
		BySeverity: map[string]int{},
		ByKind:     map[string]int{},
	}
	if len(alerts) == 0 {
		out.Notes = append(out.Notes, "No alerts match. That is not the same as nothing happening — check the detection coverage view for the event kinds no sensor reports.")
		return out
	}

	type key struct{ kind, title string }
	groups := map[key][]Alert{}
	for _, a := range alerts {
		out.ByStatus[orUnknown(a.Status)]++
		out.BySeverity[orUnknown(a.Severity)]++
		out.ByKind[orUnknown(a.Kind)]++
		groups[key{a.Kind, a.Title}] = append(groups[key{a.Kind, a.Title}], a)
	}

	for k, group := range groups {
		if len(group) < 2 {
			out.Singletons = append(out.Singletons, group[0].ID)
			continue
		}
		hosts := map[string]bool{}
		worst := group[0].Severity
		first, last := group[0].DetectedAt, group[0].DetectedAt
		ids := make([]string, 0, len(group))
		for _, a := range group {
			name := a.Hostname
			if name == "" {
				name = a.DeviceID
			}
			hosts[name] = true
			ids = append(ids, a.ID)
			if severityRank(a.Severity) < severityRank(worst) {
				worst = a.Severity
			}
			if !a.DetectedAt.IsZero() {
				if first.IsZero() || a.DetectedAt.Before(first) {
					first = a.DetectedAt
				}
				if a.DetectedAt.After(last) {
					last = a.DetectedAt
				}
			}
		}
		hostList := make([]string, 0, len(hosts))
		for h := range hosts {
			hostList = append(hostList, h)
		}
		sort.Strings(hostList)
		sort.Strings(ids)

		reason := fmt.Sprintf("%d alerts of the same kind and title across %d host(s)",
			len(group), len(hostList))
		if len(hostList) == 1 {
			reason = fmt.Sprintf("%d alerts of the same kind and title, all on %s",
				len(group), hostList[0])
		}
		out.Clusters = append(out.Clusters, Cluster{
			Reason: reason, Kind: k.kind, Title: k.title,
			Hosts: hostList, AlertIDs: ids, Count: len(group),
			Severity: worst, FirstSeen: first, LastSeen: last,
		})
	}

	sort.Slice(out.Clusters, func(i, j int) bool {
		if out.Clusters[i].Count != out.Clusters[j].Count {
			return out.Clusters[i].Count > out.Clusters[j].Count
		}
		return out.Clusters[i].Title < out.Clusters[j].Title
	})
	sort.Strings(out.Singletons)

	// Notes, worst first.
	if n := out.BySeverity["critical"]; n > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("%d critical alert(s).", n))
	}
	for _, c := range out.Clusters {
		if len(c.Hosts) >= 3 {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"%q appears on %d hosts. A finding that arrives everywhere at once is usually one change rolling across the fleet rather than %d separate incidents.",
				c.Title, len(c.Hosts), len(c.Hosts)))
			break
		}
	}
	if len(out.Singletons) > 0 && len(out.Clusters) > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d alert(s) group with nothing else. On a busy fleet those are usually the ones worth reading first, and a queue sorted by time buries them.",
			len(out.Singletons)))
	}
	return out
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}

// SavedQuery is an operator-defined live query.
type SavedQuery struct {
	ID    string
	Name  string
	Query string
}

// Suggestion is a follow-up an operator or an agent could run.
type Suggestion struct {
	QueryID string `json:"queryId"`
	Name    string `json:"name"`
	// Why explains the relevance, so a suggestion can be judged rather than
	// followed.
	Why string `json:"why"`
}

// SuggestFollowUps picks saved queries relevant to an alert.
//
// Drawn only from the operator's own saved queries — never generated. That is
// the whole point: a suggested query that DefendSec invented would be a query
// nobody approved, and the live-query surface is an allowlist precisely so
// that arbitrary queries cannot be run. Suggesting one would route around the
// allowlist using the operator's own credentials.
//
// Matching is keyword overlap against the query's name, which is crude and
// will miss things. The failure direction is right: a missed suggestion costs
// an operator nothing, and a confidently irrelevant one costs their trust in
// all of them.
func SuggestFollowUps(alert Alert, saved []SavedQuery) []Suggestion {
	keywords := alertKeywords(alert)
	if len(keywords) == 0 {
		return nil
	}

	var out []Suggestion
	for _, q := range saved {
		haystack := strings.ToLower(q.Name + " " + q.Query)
		for _, kw := range keywords {
			if strings.Contains(haystack, kw) {
				out = append(out, Suggestion{
					QueryID: q.ID, Name: q.Name,
					Why: fmt.Sprintf("Mentions %q, which appears in this %s alert.", kw, orUnknown(alert.Kind)),
				})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// alertKeywords are the terms worth matching against a query name.
func alertKeywords(alert Alert) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		// Two characters or fewer matches almost anything; "the" and its kind
		// match everything. Both would produce suggestions that are noise.
		if len(s) < 4 || seen[s] || stopWords[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(alert.Kind)
	for _, word := range strings.FieldsFunc(alert.Title, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == '/' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		add(word)
		// Path and identifier components are added individually as well as
		// whole. A keyword extractor that keeps only "/etc/ssh/sshd_config"
		// will never match a query an operator named "sshd config drift",
		// which is how every real saved query is named — so the whole-token
		// form alone matches almost nothing.
		for _, part := range strings.FieldsFunc(word, func(r rune) bool {
			return r == '/' || r == '_' || r == '-' || r == '.'
		}) {
			add(part)
		}
	}
	return out
}

// stopWords are terms that would match a query name without meaning anything.
var stopWords = map[string]bool{
	"alert": true, "changed": true, "detected": true, "failed": true,
	"file": true, "from": true, "have": true, "host": true, "into": true,
	"that": true, "them": true, "this": true, "were": true, "with": true,
}
