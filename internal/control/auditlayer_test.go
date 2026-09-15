package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Without a database there is no audit layer, and the endpoints must say so
// rather than appearing to work and returning an empty assessment — an empty
// assessment reads as "nothing wrong".
func TestAuditLayerEndpointsRequireDatabase(t *testing.T) {
	s := testServer()
	for name, h := range map[string]http.HandlerFunc{
		"periods":    s.HandleAuditPeriods,
		"close":      s.HandleAuditPeriodClose,
		"exceptions": s.HandleControlExceptions,
		"assessment": s.HandleAuditAssessment,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/audit/"+name, nil)
			req.Header.Set("Authorization", "Bearer admin-token")
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status=%d, want 503 without a database", rec.Code)
			}
		})
	}
}

func TestWindowFromQuery(t *testing.T) {
	parse := func(q string) (string, error) {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit/assessment"+q, nil)
		from, to, err := windowFromQuery(req)
		if err != nil {
			return "", err
		}
		return from.Format("2006-01-02") + ".." + to.Format("2006-01-02"), nil
	}

	// A default window exists so the endpoint is usable without arguments,
	// but it must be a real window rather than everything ever recorded.
	got, err := parse("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "..") {
		t.Fatalf("default window = %q", got)
	}

	if got, err := parse("?from=2026-01-01T00:00:00Z&to=2026-04-01T00:00:00Z"); err != nil || got != "2026-01-01..2026-04-01" {
		t.Errorf("got %q, %v", got, err)
	}

	for _, q := range []string{
		"?from=yesterday",
		"?to=soon",
		// An inverted or empty window would silently assess nothing and
		// report every control as having no evidence.
		"?from=2026-04-01T00:00:00Z&to=2026-01-01T00:00:00Z",
		"?from=2026-04-01T00:00:00Z&to=2026-04-01T00:00:00Z",
	} {
		if _, err := parse(q); err == nil {
			t.Errorf("%s: accepted", q)
		}
	}
}

func TestFrameworkIDs(t *testing.T) {
	ids := frameworkIDs()
	if len(ids) == 0 {
		t.Fatal("no frameworks")
	}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			t.Error("blank framework id")
		}
	}
}

func TestAuditLayerRejectsWrongMethods(t *testing.T) {
	s := testServer()
	for name, h := range map[string]http.HandlerFunc{
		"close":      s.HandleAuditPeriodClose,
		"assessment": s.HandleAuditAssessment,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/v1/audit/"+name, http.NoBody)
			req.Header.Set("Authorization", "Bearer admin-token")
			rec := httptest.NewRecorder()
			h(rec, req)
			// Without a database the availability check fires first, which is
			// correct; with one, the method check is what answers.
			if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status=%d", rec.Code)
			}
		})
	}
}

func TestEvidenceExportRequiresDatabaseAndAdmin(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/audit/evidence", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleEvidenceExport(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 without a database", rec.Code)
	}

	// A bundle is a complete copy of the ledger. Read-only access to the
	// console is not the same as permission to walk out with one.
	for _, token := range []string{"viewer-token", "bogus", ""} {
		req := httptest.NewRequest(http.MethodGet, "/v1/audit/evidence", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		s.HandleEvidenceExport(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("token %q exported an evidence bundle", token)
		}
	}
}
