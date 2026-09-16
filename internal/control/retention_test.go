package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"defendsec/internal/cmdlog"
)

func TestRetentionPostureReportsWhatIsConfigured(t *testing.T) {
	s := testServer()
	st := s.RetentionPosture(t.Context())

	// Without a database the JSON file is the only copy, and the report must
	// say so rather than implying the history is safe.
	if !strings.Contains(strings.Join(st.Notes, " "), "only copy") {
		t.Errorf("no database, but the notes do not warn about it: %v", st.Notes)
	}
	// The ledger is never pruned, which is the honest answer rather than a
	// large number.
	if !strings.Contains(strings.Join(st.Notes, " "), "never pruned") {
		t.Errorf("the notes do not state that the ledger is not pruned: %v", st.Notes)
	}
	// Open findings are never aged out, and that distinction matters.
	if !strings.Contains(strings.Join(st.Notes, " "), "resolved findings only") {
		t.Errorf("the notes do not distinguish resolved from open: %v", st.Notes)
	}
}

func TestRetentionDefaultsMeetTheCJISMinimum(t *testing.T) {
	s := testServer()
	st := s.RetentionPosture(t.Context())
	if st.CommandHistoryDays < cjisMinimumDays {
		t.Errorf("command history default = %d days, below the CJIS minimum", st.CommandHistoryDays)
	}
	if st.AlertRetentionDays < cjisMinimumDays {
		t.Errorf("alert retention default = %d days, below the CJIS minimum", st.AlertRetentionDays)
	}
	if !st.MeetsCJISMinimum {
		t.Error("the shipped defaults do not meet the minimum the product claims to evidence")
	}
}

// A short window must be reported as short, with the fix, rather than passing
// quietly.
func TestShortRetentionIsFlagged(t *testing.T) {
	t.Setenv("DEFENDSEC_ALERT_RETENTION_DAYS", "30")
	s := testServer()
	st := s.RetentionPosture(t.Context())
	if st.MeetsCJISMinimum {
		t.Fatal("a 30-day window was reported as meeting a one-year minimum")
	}
	joined := strings.Join(st.Notes, " ")
	if !strings.Contains(joined, "shorter than the year") {
		t.Errorf("the shortfall is not stated: %v", st.Notes)
	}
	if !strings.Contains(joined, "documented exception") {
		t.Errorf("the notes do not offer the remedy: %v", st.Notes)
	}
}

// Keeping everything must be expressible, and must not read as a shortfall.
func TestIndefiniteRetentionMeetsTheMinimum(t *testing.T) {
	t.Setenv("DEFENDSEC_ALERT_RETENTION_DAYS", "-1")
	s := testServer()
	s.commands = cmdlog.New(t.TempDir() + "/commands.json")
	s.commands.SetRetentionDays(-1)

	st := s.RetentionPosture(t.Context())
	if !st.MeetsCJISMinimum {
		t.Fatalf("indefinite retention was reported as a shortfall: %+v", st)
	}
}

func TestRetentionEndpointIsAdminOnly(t *testing.T) {
	s := testServer()
	for token, want := range map[string]int{
		"admin-token":  http.StatusOK,
		"viewer-token": http.StatusUnauthorized,
		"bogus":        http.StatusUnauthorized,
		"":             http.StatusUnauthorized,
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/retention", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		s.HandleRetention(rec, req)
		if rec.Code != want {
			t.Errorf("token %q: status=%d, want %d", token, rec.Code, want)
		}
	}
}

func TestRetentionEndpointRejectsWrongMethod(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/retention", http.NoBody)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleRetention(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}
