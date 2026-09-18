package triage

import (
	"strings"
	"testing"
	"time"
)

func alert(id, kind, title, host, severity string) Alert {
	return Alert{
		ID: id, Kind: kind, Title: title, Hostname: host,
		Severity: severity, Status: "open", DeviceID: "dev-" + host,
		DetectedAt: now,
	}
}

// The reason summarisation is worth having: a hundred alerts that are one
// upgrade rolling across the fleet should read as one thing.
func TestFleetWideFindingsClusterIntoOne(t *testing.T) {
	var alerts []Alert
	for i := 0; i < 12; i++ {
		alerts = append(alerts, alert(
			"a"+string(rune('a'+i)), "fim", "/etc/ssh/sshd_config changed",
			"web-"+string(rune('a'+i)), "high"))
	}
	sum := Summarise(alerts)

	if sum.Total != 12 {
		t.Errorf("total = %d", sum.Total)
	}
	if len(sum.Clusters) != 1 {
		t.Fatalf("clusters = %d, want one: %+v", len(sum.Clusters), sum.Clusters)
	}
	c := sum.Clusters[0]
	if c.Count != 12 || len(c.Hosts) != 12 {
		t.Errorf("cluster = %+v", c)
	}
	joined := strings.Join(sum.Notes, " ")
	if !strings.Contains(joined, "rolling across the fleet") {
		t.Errorf("the notes do not name the likely cause: %v", sum.Notes)
	}
}

// The lone alert on a busy fleet is the one worth reading, and a queue sorted
// by time buries it. It has to be called out separately.
func TestTheLoneAlertIsCalledOutSeparately(t *testing.T) {
	alerts := []Alert{
		alert("a1", "fim", "/etc/ssh/sshd_config changed", "web-1", "high"),
		alert("a2", "fim", "/etc/ssh/sshd_config changed", "web-2", "high"),
		alert("a3", "fim", "/etc/ssh/sshd_config changed", "web-3", "high"),
		alert("odd", "detection", "Reverse shell from a web server", "web-9", "critical"),
	}
	sum := Summarise(alerts)

	if len(sum.Singletons) != 1 || sum.Singletons[0] != "odd" {
		t.Errorf("singletons = %v, want just the lone detection", sum.Singletons)
	}
	joined := strings.Join(sum.Notes, " ")
	if !strings.Contains(joined, "critical") {
		t.Errorf("the critical alert is not surfaced in the notes: %v", sum.Notes)
	}
}

// Alerts on one host are distinguishable from the same finding fleet-wide:
// one is usually a change, the other usually an incident.
func TestASingleHostClusterSaysSo(t *testing.T) {
	sum := Summarise([]Alert{
		alert("a1", "detection", "Suspicious process", "web-1", "high"),
		alert("a2", "detection", "Suspicious process", "web-1", "high"),
	})
	if len(sum.Clusters) != 1 {
		t.Fatalf("clusters = %+v", sum.Clusters)
	}
	if !strings.Contains(sum.Clusters[0].Reason, "all on web-1") {
		t.Errorf("reason = %q", sum.Clusters[0].Reason)
	}
}

// A cluster takes the worst severity in it, not the first one seen.
func TestAClusterReportsItsWorstSeverity(t *testing.T) {
	sum := Summarise([]Alert{
		alert("a1", "fim", "same title", "web-1", "low"),
		alert("a2", "fim", "same title", "web-2", "critical"),
		alert("a3", "fim", "same title", "web-3", "medium"),
	})
	if sum.Clusters[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", sum.Clusters[0].Severity)
	}
}

// An empty result must not read as "nothing is happening".
func TestNoAlertsDoesNotMeanNothingHappened(t *testing.T) {
	sum := Summarise(nil)
	if sum.Total != 0 {
		t.Errorf("total = %d", sum.Total)
	}
	joined := strings.Join(sum.Notes, " ")
	if !strings.Contains(joined, "not the same as nothing happening") {
		t.Errorf("notes = %v", sum.Notes)
	}
}

func TestClustersAreOrderedLargestFirst(t *testing.T) {
	var alerts []Alert
	for i := 0; i < 2; i++ {
		alerts = append(alerts, alert("s"+string(rune('a'+i)), "fim", "small", "h"+string(rune('a'+i)), "low"))
	}
	for i := 0; i < 5; i++ {
		alerts = append(alerts, alert("b"+string(rune('a'+i)), "fim", "big", "g"+string(rune('a'+i)), "low"))
	}
	sum := Summarise(alerts)
	if len(sum.Clusters) != 2 {
		t.Fatalf("clusters = %d", len(sum.Clusters))
	}
	if sum.Clusters[0].Title != "big" {
		t.Errorf("first cluster = %q, want the largest", sum.Clusters[0].Title)
	}
}

// Suggestions come only from the operator's own saved queries. A generated
// one would route around the live-query allowlist using the operator's
// credentials, which is the thing the allowlist exists to prevent.
func TestSuggestionsComeOnlyFromSavedQueries(t *testing.T) {
	saved := []SavedQuery{
		{ID: "q1", Name: "sshd config drift", Query: "SELECT * FROM ssh"},
		{ID: "q2", Name: "listening ports", Query: "SELECT * FROM ports"},
		{ID: "q3", Name: "logged in users", Query: "SELECT * FROM users"},
	}
	got := SuggestFollowUps(alert("a1", "fim", "/etc/ssh/sshd_config changed", "web-1", "high"), saved)

	if len(got) == 0 {
		t.Fatal("no suggestion for an sshd_config alert against a saved sshd query")
	}
	for _, s := range got {
		var known bool
		for _, q := range saved {
			if q.ID == s.QueryID {
				known = true
			}
		}
		if !known {
			t.Errorf("suggested a query that is not in the allowlist: %+v", s)
		}
		if s.Why == "" {
			t.Errorf("suggestion %q has no stated reason", s.Name)
		}
	}
}

// With no saved queries there is nothing to suggest, and nothing is invented.
func TestNoSavedQueriesMeansNoSuggestions(t *testing.T) {
	if got := SuggestFollowUps(alert("a1", "fim", "sshd_config changed", "h", "high"), nil); len(got) != 0 {
		t.Errorf("invented suggestions with an empty allowlist: %+v", got)
	}
}

// Common words must not match every query name, or every suggestion is noise
// and an operator stops reading them.
func TestStopWordsDoNotMatchEverything(t *testing.T) {
	saved := []SavedQuery{
		{ID: "q1", Name: "all the host file things", Query: "SELECT 1"},
	}
	got := SuggestFollowUps(Alert{
		ID: "a1", Kind: "fim", Title: "This file changed on that host",
		Hostname: "web-1", Severity: "low",
	}, saved)
	if len(got) != 0 {
		t.Errorf("stop words produced a suggestion: %+v", got)
	}
}

func TestDetectedAtSpanIsRecordedForACluster(t *testing.T) {
	early := now.Add(-time.Hour)
	a1 := alert("a1", "fim", "same", "h1", "low")
	a1.DetectedAt = early
	a2 := alert("a2", "fim", "same", "h2", "low")
	sum := Summarise([]Alert{a1, a2})
	if len(sum.Clusters) != 1 {
		t.Fatalf("clusters = %d", len(sum.Clusters))
	}
	c := sum.Clusters[0]
	if !c.FirstSeen.Equal(early) || !c.LastSeen.Equal(now) {
		t.Errorf("span = %v..%v, want %v..%v", c.FirstSeen, c.LastSeen, early, now)
	}
}
