package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/internal/storepg"
)

func getFeeds(t *testing.T, s *Server, token string) (*httptest.ResponseRecorder, feedsResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/feeds", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.HandleFeeds(rec, req)
	var out feedsResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v\n%s", err, rec.Body.String())
		}
	}
	return rec, out
}

func findFeed(out feedsResponse, name string) (feedStatusJSON, bool) {
	for _, f := range out.Feeds {
		if f.Name == name {
			return f, true
		}
	}
	return feedStatusJSON{}, false
}

func TestHandleFeedsAuthAndMethod(t *testing.T) {
	s := testServer() // no Postgres needed for these checks
	if rec, _ := getFeeds(t, s, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec, _ := getFeeds(t, s, "wrong"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/feeds", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleFeeds(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	if rec, _ := getFeeds(t, s, "admin-token"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no postgres: %d", rec.Code)
	}
}

func TestHandleFeedsReportsAgeAndStaleness(t *testing.T) {
	s, store := pgServer(t)
	ctx := context.Background()
	cleanupPool, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanupPool.Close)
	now := time.Now().UTC()
	fresh, old, never := "apitest-fresh", "apitest-old", "apitest-never"
	for _, n := range []string{fresh, old, never} {
		n := n
		t.Cleanup(func() { cleanupPool.Exec(context.Background(), `DELETE FROM feed_status WHERE name = $1`, n) }) //nolint:errcheck
	}
	snap, err := store.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: fresh, URL: "https://example.invalid/f", FetchedAt: now, SHA256: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	freshT, oldT := now.Add(-3*time.Hour), now.Add(-8*24*time.Hour)
	if err := store.RecordFeedSuccess(ctx, storepg.FeedStatus{Name: fresh, Kind: "kev", URL: "https://example.invalid/f", LastSuccess: &freshT, RecordCount: 1756, SHA256: strings.Repeat("a", 64), SnapshotID: &snap.ID}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordFeedSuccess(ctx, storepg.FeedStatus{Name: old, Kind: "epss", URL: "https://example.invalid/e", LastSuccess: &oldT, RecordCount: 5}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordFeedFailure(ctx, never, "debian", "https://example.invalid/d", now, "dial tcp: lookup failed"); err != nil {
		t.Fatal(err)
	}

	// A viewer token may read it, like the other GET endpoints.
	rec, out := getFeeds(t, s, "viewer-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", rec.Header())
	}
	if out.StaleAfterSeconds != 7*24*3600 || out.GeneratedAt == "" {
		t.Errorf("envelope = %+v", out)
	}

	f, ok := findFeed(out, fresh)
	if !ok || f.Kind != "kev" || f.RecordCount != 1756 || f.SnapshotID == nil || *f.SnapshotID != snap.ID || f.Stale || f.LastSuccess == nil {
		t.Fatalf("fresh = %+v", f)
	}
	if f.AgeSeconds == nil || *f.AgeSeconds < 3*3600-5 || *f.AgeSeconds > 3*3600+60 {
		t.Errorf("fresh age = %v, want about 3h", f.AgeSeconds)
	}
	o, _ := findFeed(out, old)
	if !o.Stale || o.AgeSeconds == nil || *o.AgeSeconds < 8*24*3600-5 {
		t.Errorf("old = %+v, want stale at ~8 days", o)
	}
	n, _ := findFeed(out, never)
	if !n.Stale || n.LastSuccess != nil || n.AgeSeconds != nil || n.LastError != "dial tcp: lookup failed" || n.LastAttempt == nil {
		t.Errorf("never-succeeded = %+v, want stale with an error and no age", n)
	}
	if !out.AnyStale || out.OldestAgeSeconds == nil || *out.OldestAgeSeconds < 8*24*3600-5 {
		t.Errorf("anyStale=%v oldest=%v", out.AnyStale, out.OldestAgeSeconds)
	}
	if out.LatestSnapshotID == nil || *out.LatestSnapshotID < snap.ID {
		t.Errorf("latest snapshot = %v, want >= %d", out.LatestSnapshotID, snap.ID)
	}
}
