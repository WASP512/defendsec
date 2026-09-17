package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/savedqueries"
	"defendsec/internal/storepg"
	"defendsec/internal/triage"
)

// Triage assistance (roadmap 4.3).
//
// The roadmap files this under the AI control plane, and it would have been
// easy to make it a prompt. It is deterministic correlation instead. "Was this
// file rewritten by a package upgrade?" has a factual answer in stored data,
// and a self-hosted security product that needs an outbound API call to triage
// an alert is one that stops triaging when the network is the thing under
// attack.
//
// The same explanation is served to the console and to an agent over MCP, so
// the operator and the model are reading the same thing rather than two
// analyses that can disagree.

// findAlert locates one alert by id across whichever store is configured.
func (s *Server) findAlert(ctx context.Context, id string) (storepg.Alert, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return storepg.Alert{}, false
	}
	if s.pg != nil {
		alerts, err := s.pg.ListAlerts(ctx, storepg.AlertFilters{Limit: 1000})
		if err == nil {
			for _, a := range alerts {
				if a.ID == id {
					return a, true
				}
			}
		}
		return storepg.Alert{}, false
	}
	for _, a := range s.store.ListAlerts("", "", "", 1000) {
		if a.ID == id {
			return storeAlert(a), true
		}
	}
	return storepg.Alert{}, false
}

// parseAlertTime reads an alert timestamp, preferring when the thing was
// detected over when DefendSec recorded it. Correlation is against the world,
// not against the database's clock.
func parseAlertTime(a storepg.Alert) time.Time {
	for _, raw := range []string{a.DetectedAt, a.CreatedAt, a.IngestedAt} {
		if raw == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// triageAlert converts a stored alert to the triage package's shape.
func triageAlert(a storepg.Alert) triage.Alert {
	return triage.Alert{
		ID: a.ID, DeviceID: a.DeviceID, Hostname: a.Hostname,
		Kind: a.Kind, Severity: a.Severity, Title: a.Title,
		Status: a.Status, SourceID: a.SourceID,
		DetectedAt: parseAlertTime(a),
	}
}

// driftPath pulls the changed path out of a file-integrity alert.
//
// The alert detail is the authority; the title is a fallback because older
// alerts were raised before the path was carried in the detail, and refusing
// to explain those would make the feature useless on any existing deployment.
func driftPath(a storepg.Alert) string {
	var detail map[string]any
	if len(a.Detail) > 0 {
		_ = json.Unmarshal(a.Detail, &detail)
	}
	for _, key := range []string{"path", "targetFilename", "file"} {
		if v, ok := detail[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	// Titles are written as "<path> changed" and similar.
	for _, field := range strings.Fields(a.Title) {
		if strings.HasPrefix(field, "/") {
			return field
		}
	}
	return ""
}

// ExplainAlertDrift explains a file-integrity alert.
func (s *Server) ExplainAlertDrift(ctx context.Context, alertID string) (*triage.Explanation, string, error) {
	alert, ok := s.findAlert(ctx, alertID)
	if !ok {
		return nil, fmt.Sprintf("No alert has id %q.", alertID), nil
	}
	path := driftPath(alert)
	if path == "" {
		return nil, fmt.Sprintf(
			"Alert %s is a %s alert with no changed file recorded, so there is nothing to correlate against package history. Drift explanation applies to file-integrity alerts.",
			alert.ID, orUnknownKind(alert.Kind)), nil
	}

	detectedAt := parseAlertTime(alert)
	var events []triage.PackageEvent
	if s.pg != nil {
		// A window wider than the correlation window, so the explanation can
		// report activity it then declines to correlate. Showing an operator
		// "twelve packages changed, none of them owns this file" is more
		// useful than showing nothing.
		since := detectedAt.Add(-2 * triage.CorrelationWindow)
		changes, err := s.pg.PackageChangesSince(ctx, alert.DeviceID, since)
		if err != nil {
			return nil, "", err
		}
		for _, c := range changes {
			events = append(events, triage.PackageEvent{
				Package: c.Package, PreviousVersion: c.PreviousVersion,
				NewVersion: c.NewVersion, ObservedAt: c.ObservedAt,
			})
		}
	}

	var detail map[string]any
	if len(alert.Detail) > 0 {
		_ = json.Unmarshal(alert.Detail, &detail)
	}
	exp := triage.ExplainDrift(triage.DriftEvent{
		Path:       path,
		Previous:   stringField(detail, "previous"),
		Current:    stringField(detail, "current"),
		DetectedAt: detectedAt,
		Action:     stringField(detail, "action"),
	}, events)

	if s.pg == nil {
		// Without a database there is no package history at all, so an
		// "unexplained" verdict would be an artefact of the deployment
		// rather than a finding. Said plainly rather than left to be
		// inferred from a confident-looking verdict.
		exp.Caveat = "No database is configured, so DefendSec has no package history for this host. This verdict reflects the absence of data, not the absence of an upgrade."
	}
	return &exp, "", nil
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func orUnknownKind(k string) string {
	if strings.TrimSpace(k) == "" {
		return "unknown-kind"
	}
	return k
}

// SummariseAlerts groups the alerts matching a filter.
func (s *Server) SummariseAlerts(ctx context.Context, f storepg.AlertFilters) (triage.Summary, error) {
	var alerts []triage.Alert
	if s.pg != nil {
		rows, err := s.pg.ListAlerts(ctx, f)
		if err != nil {
			return triage.Summary{}, err
		}
		for _, a := range rows {
			alerts = append(alerts, triageAlert(a))
		}
	} else {
		for _, a := range s.store.ListAlerts(f.Status, f.Kind, f.DeviceID, f.Limit) {
			alerts = append(alerts, triageAlert(storeAlert(a)))
		}
	}
	return triage.Summarise(alerts), nil
}

// FollowUpsForAlert suggests saved queries relevant to an alert.
//
// Only the operator's own saved queries, never a generated one. The
// live-query surface is an allowlist precisely so arbitrary queries cannot be
// run; suggesting one DefendSec invented would route around that allowlist
// using the operator's credentials.
func (s *Server) FollowUpsForAlert(ctx context.Context, alertID string) ([]triage.Suggestion, string, error) {
	alert, ok := s.findAlert(ctx, alertID)
	if !ok {
		return nil, fmt.Sprintf("No alert has id %q.", alertID), nil
	}
	rows, err := savedqueries.NewFile(s.savedQueriesPath()).List()
	if err != nil {
		return nil, "", err
	}
	saved := make([]triage.SavedQuery, 0, len(rows))
	for _, r := range rows {
		saved = append(saved, triage.SavedQuery{ID: r.ID, Name: r.Name, Query: r.Query})
	}
	return triage.SuggestFollowUps(triageAlert(alert), saved), "", nil
}

// HandleTriage serves the triage views.
//
// Viewers are allowed: reading why an alert fired is exactly what somebody
// without response authority is for.
func (s *Server) HandleTriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	q := r.URL.Query()
	if alertID := strings.TrimSpace(q.Get("alertId")); alertID != "" {
		exp, why, err := s.ExplainAlertDrift(r.Context(), alertID)
		if err != nil {
			s.log.Warn("explain drift", "err", err)
			http.Error(w, "could not explain this alert", http.StatusInternalServerError)
			return
		}
		if exp == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": why})
			return
		}
		followUps, _, err := s.FollowUpsForAlert(r.Context(), alertID)
		if err != nil {
			s.log.Warn("follow-up suggestions", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"explanation": exp,
			"followUps":   followUps,
			"detail":      "DefendSec correlates its own records; no model is involved and nothing is sent anywhere. A correlation explains an alert, it does not resolve it.",
		})
		return
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	summary, err := s.SummariseAlerts(r.Context(), storepg.AlertFilters{
		Status: q.Get("status"), Kind: q.Get("kind"),
		DeviceID: q.Get("deviceId"), Limit: limit,
	})
	if err != nil {
		s.log.Warn("summarise alerts", "err", err)
		http.Error(w, "could not summarise alerts", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary})
}

// HandlePackageChanges reports a host's observed package history.
func (s *Server) HandlePackageChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	deviceID := strings.TrimSpace(r.URL.Query().Get("deviceId"))
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "deviceId is required"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	changes, err := pg.RecentPackageChanges(r.Context(), deviceID, limit)
	if err != nil {
		s.log.Warn("package changes", "err", err)
		http.Error(w, "could not read package history", http.StatusInternalServerError)
		return
	}
	if changes == nil {
		changes = []storepg.PackageChange{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"changes": changes,
		"detail":  "Observed version transitions. The timestamp is when DefendSec noticed, not when the upgrade ran: inventory arrives on a heartbeat interval, so the change is somewhere in the preceding window.",
	})
}
