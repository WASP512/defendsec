package control

import (
	"encoding/json"
	"net/http"
	"time"
)

// FeedStaleAfter is how old a feed may get before the API and the console call
// it stale. One week: the distro feeds change daily, so a week without a
// confirmed-current sync means the timer or the network has been broken for a
// while and findings are being computed against old data.
const FeedStaleAfter = 7 * 24 * time.Hour

type feedStatusJSON struct {
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	URL         string  `json:"url"`
	LastSuccess *string `json:"lastSuccess"`
	LastAttempt *string `json:"lastAttempt"`
	// AgeSeconds is the time since the feed was last confirmed current and
	// loaded; null if it never has been.
	AgeSeconds  *int64 `json:"ageSeconds"`
	Stale       bool   `json:"stale"`
	RecordCount int64  `json:"recordCount"`
	SnapshotID  *int64 `json:"snapshotId"`
	SHA256      string `json:"sha256"`
	LastError   string `json:"lastError"`
}

type feedsResponse struct {
	Feeds             []feedStatusJSON `json:"feeds"`
	GeneratedAt       string           `json:"generatedAt"`
	StaleAfterSeconds int64            `json:"staleAfterSeconds"`
	// AnyStale is true if any feed is older than StaleAfterSeconds or has
	// never succeeded.
	AnyStale         bool   `json:"anyStale"`
	OldestAgeSeconds *int64 `json:"oldestAgeSeconds"`
	LatestSnapshotID *int64 `json:"latestSnapshotId"`
}

// HandleFeeds serves GET /v1/feeds: per feed, when it last succeeded, how old
// that makes it, how many records it holds and which snapshot it belongs to.
// It reports what defendsec-feeds has written to feed_status; it never fetches.
func (s *Server) HandleFeeds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.pg == nil {
		http.Error(w, "postgres not configured", http.StatusServiceUnavailable)
		return
	}
	rows, err := s.pg.ListFeedStatus(r.Context())
	if err != nil {
		s.log.Warn("list feed status", "err", err)
		http.Error(w, "could not read feed status", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	resp := feedsResponse{
		Feeds:             make([]feedStatusJSON, 0, len(rows)),
		GeneratedAt:       now.Format(time.RFC3339),
		StaleAfterSeconds: int64(FeedStaleAfter / time.Second),
	}
	for _, f := range rows {
		j := feedStatusJSON{
			Name: f.Name, Kind: f.Kind, URL: f.URL, RecordCount: f.RecordCount,
			SnapshotID: f.SnapshotID, SHA256: f.SHA256, LastError: f.LastError,
		}
		if f.LastAttempt != nil {
			v := f.LastAttempt.UTC().Format(time.RFC3339)
			j.LastAttempt = &v
		}
		if f.LastSuccess != nil {
			v := f.LastSuccess.UTC().Format(time.RFC3339)
			age := int64(now.Sub(*f.LastSuccess) / time.Second)
			if age < 0 {
				age = 0
			}
			j.LastSuccess, j.AgeSeconds = &v, &age
			j.Stale = time.Duration(age)*time.Second > FeedStaleAfter
			if resp.OldestAgeSeconds == nil || age > *resp.OldestAgeSeconds {
				resp.OldestAgeSeconds = &age
			}
		} else {
			j.Stale = true
		}
		if j.Stale {
			resp.AnyStale = true
		}
		resp.Feeds = append(resp.Feeds, j)
	}
	if snap, ok, err := s.pg.LatestFeedSnapshot(r.Context()); err == nil && ok {
		resp.LatestSnapshotID = &snap.ID
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
