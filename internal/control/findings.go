package control

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/storepg"
)

// Findings API (read-only):
//
//	GET /v1/findings?deviceId=&kind=finding|informational&resolved=1&limit=
//	GET /v1/findings/{id}
//
// Findings are computed by the matcher when a host reports inventory and when a
// new feed snapshot lands; these endpoints only read what it stored. Every
// finding carries the advisory, the range it matched, the snapshot and the feed
// (name and fetch date) it was computed from.

type findingsResponse struct {
	Findings         []storepg.VulnFinding  `json:"findings"`
	Total            int                    `json:"total"`
	Truncated        bool                   `json:"truncated"`
	State            *storepg.HostVulnState `json:"state"`
	LatestSnapshotID *int64                 `json:"latestSnapshotId"`
	GeneratedAt      string                 `json:"generatedAt"`
}

// HandleFindings serves GET /v1/findings and GET /v1/findings/{id}.
func (s *Server) HandleFindings(w http.ResponseWriter, r *http.Request) {
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
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/findings"), "/")
	if rest != "" {
		s.handleFindingDetail(w, r, rest)
		return
	}
	q := r.URL.Query()
	f := storepg.FindingFilter{
		DeviceID:        q.Get("deviceId"),
		Kind:            q.Get("kind"),
		IncludeResolved: q.Get("resolved") == "1",
	}
	if f.Kind != "" && f.Kind != "finding" && f.Kind != "informational" {
		http.Error(w, "kind must be finding or informational", http.StatusBadRequest)
		return
	}
	limit := 500
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > storepg.MaxFindingsPage {
			http.Error(w, "limit must be between 1 and "+strconv.Itoa(storepg.MaxFindingsPage), http.StatusBadRequest)
			return
		}
		limit = n
	}
	// One more than asked for, to know whether the answer was cut short.
	f.Limit = limit + 1
	rows, err := s.pg.ListFindings(r.Context(), f)
	if err != nil {
		s.log.Warn("list findings", "err", err)
		http.Error(w, "could not read findings", http.StatusInternalServerError)
		return
	}
	resp := findingsResponse{Findings: rows, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	if len(rows) > limit {
		resp.Findings, resp.Truncated = rows[:limit], true
	}
	if resp.Findings == nil {
		resp.Findings = []storepg.VulnFinding{}
	}
	resp.Total = len(resp.Findings)
	if f.DeviceID != "" {
		if st, ok, err := s.pg.GetHostVulnState(r.Context(), f.DeviceID); err == nil && ok {
			resp.State = &st
		}
	}
	if snap, ok, err := s.pg.LatestFeedSnapshot(r.Context()); err == nil && ok {
		resp.LatestSnapshotID = &snap.ID
	}
	writeJSON(w, http.StatusOK, resp)
}

type rangeJSON struct {
	ID            int64  `json:"id"`
	Ecosystem     string `json:"ecosystem"`
	Distro        string `json:"distro"`
	Release       string `json:"release"`
	Package       string `json:"package"`
	SourcePackage string `json:"sourcePackage"`
	Introduced    string `json:"introduced"`
	Fixed         string `json:"fixed"`
	FixState      string `json:"fixState"`
	SnapshotID    *int64 `json:"snapshotId"`
	Feed          string `json:"feed"`
}

type advisoryJSON struct {
	ID         string   `json:"id"`
	CVE        string   `json:"cve"`
	Summary    string   `json:"summary"`
	Severity   string   `json:"severity"`
	Source     string   `json:"source"`
	CVSSVector string   `json:"cvssVector"`
	CVSSScore  *float64 `json:"cvssScore"`
	CWE        []string `json:"cwe"`
	KEV        bool     `json:"kev"`
	KEVAdded   *string  `json:"kevAdded"`
	EPSS       *float64 `json:"epss"`
	EPSSDate   *string  `json:"epssDate"`
}

type snapshotFeedJSON struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	FetchedAt   string `json:"fetchedAt"`
	SHA256      string `json:"sha256"`
	RecordCount int    `json:"recordCount"`
}

type snapshotJSON struct {
	ID        int64              `json:"id"`
	CreatedAt string             `json:"createdAt"`
	Feeds     []snapshotFeedJSON `json:"feeds"`
}

type findingDetailResponse struct {
	Finding storepg.VulnFinding `json:"finding"`
	// Advisory is the vulnerability record; nil if it has been removed.
	Advisory *advisoryJSON `json:"advisory"`
	// Range is the advisory range the finding matched, as it exists now. Nil
	// if the feed was re-synced and the range no longer exists; the finding's
	// own fields still say what matched.
	Range *rangeJSON `json:"range"`
	// Snapshot is the feed snapshot the finding was computed from: each feed's
	// URL, fetch time and SHA-256.
	Snapshot *snapshotJSON `json:"snapshot"`
}

func dateString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02")
	return &s
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request, rest string) {
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "finding id must be a positive integer", http.StatusBadRequest)
		return
	}
	d, err := s.pg.GetFindingDetail(r.Context(), id)
	if errors.Is(err, storepg.ErrNoFinding) {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.log.Warn("finding detail", "err", err, "finding", id)
		http.Error(w, "could not read finding", http.StatusInternalServerError)
		return
	}
	resp := findingDetailResponse{Finding: d.Finding}
	if a := d.Advisory; a != nil {
		cwe := a.CWE
		if cwe == nil {
			cwe = []string{}
		}
		resp.Advisory = &advisoryJSON{
			ID: a.ID, CVE: a.CVE, Summary: a.Summary, Severity: a.Severity, Source: a.Source,
			CVSSVector: a.CVSSVector, CVSSScore: a.CVSSScore, CWE: cwe, KEV: a.KEV,
			KEVAdded: dateString(a.KEVAdded), EPSS: a.EPSS, EPSSDate: dateString(a.EPSSDate),
		}
	}
	if rg := d.Range; rg != nil {
		resp.Range = &rangeJSON{
			ID: rg.ID, Ecosystem: rg.Ecosystem, Distro: rg.Distro, Release: rg.Release, Package: rg.Package,
			SourcePackage: rg.SourcePackage, Introduced: rg.Introduced, Fixed: rg.Fixed,
			FixState: string(rg.FixState), SnapshotID: rg.SnapshotID, Feed: rg.Feed,
		}
	}
	if sn := d.Snapshot; sn != nil {
		out := &snapshotJSON{ID: sn.ID, CreatedAt: sn.CreatedAt.UTC().Format(time.RFC3339), Feeds: []snapshotFeedJSON{}}
		for _, f := range sn.Feeds {
			out.Feeds = append(out.Feeds, snapshotFeedJSON{
				Name: f.Name, URL: f.URL, FetchedAt: f.FetchedAt.UTC().Format(time.RFC3339),
				SHA256: f.SHA256, RecordCount: f.RecordCount,
			})
		}
		resp.Snapshot = out
	}
	writeJSON(w, http.StatusOK, resp)
}
