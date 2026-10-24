package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"defendsec/internal/storepg"
)

func getOSCalendar(s *Server, token string, method string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/v1/lifecycle/os", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.HandleOSCalendar(rec, req)
	return rec
}

func TestHandleOSCalendarAuthAndMethod(t *testing.T) {
	s := testServer()
	if rec := getOSCalendar(s, "", http.MethodGet); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := getOSCalendar(s, "wrong", http.MethodGet); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	if rec := getOSCalendar(s, "admin-token", http.MethodPost); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	if rec := getOSCalendar(s, "admin-token", http.MethodGet); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no postgres: %d", rec.Code)
	}
}

// The endpoint hands the console the Windows rows and nothing else: not the
// application calendar, not a product the Supported OS policy does not read.
func TestHandleOSCalendarServesOnlyOSProducts(t *testing.T) {
	s, store := pgServer(t)
	ctx := context.Background()
	rows := []storepg.EOLRow{
		{Product: "windows-server", Label: "Microsoft Windows Server", Cycle: "2016", EoasFrom: "2022-01-11", EolFrom: "2027-01-12", EoesFrom: "2030-01-12", IsLTS: true, Latest: "10.0.14393"},
		{Product: "windows", Label: "Microsoft Windows", Cycle: "10-22h2", EoasFrom: "2025-10-14", EolFrom: "2025-10-14", EoesFrom: "2028-10-10", Latest: "10.0.19045"},
		{Product: "php", Label: "PHP", Cycle: "8.0", EolFrom: "2023-11-26", Latest: "8.0.30"},
	}
	snap, err := store.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: storepg.EOLFeedName, URL: "https://endoflife.date/api/v1/products/full",
		FetchedAt: time.Date(2026, 10, 24, 0, 8, 55, 0, time.UTC), SHA256: strings.Repeat("ab", 32), RecordCount: len(rows)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyEOL(ctx, rows, snap.ID); err != nil {
		t.Fatal(err)
	}
	rec := getOSCalendar(s, "admin-token", http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out osCalendarResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Releases) != 2 || out.FeedDate == nil || *out.FeedDate != "2026-10-24T00:08:55Z" {
		t.Fatalf("response = %+v", out)
	}
	for _, r := range out.Releases {
		if r.Product == "windows-server" && (r.Cycle != "2016" || r.EolFrom != "2027-01-12" || r.Latest != "10.0.14393" || !r.IsLTS) {
			t.Errorf("server row = %+v", r)
		}
		if r.Product == "php" {
			t.Errorf("an application product leaked: %+v", r)
		}
	}
}
