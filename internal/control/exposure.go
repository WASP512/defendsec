package control

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/exposure"
	"defendsec/internal/storepg"
	"defendsec/internal/vuln"
)

// Exposure API (read-only), the data behind the console's exposure view:
//
//	GET /v1/exposure/summary?top=5
//	GET /v1/exposure/findings?sort=rank&status=open&bucket=fix&kevOnly=1&limit=&cursor=
//	GET /v1/exposure/advisory?id=<advisory id>&bucket=fix&status=open
//	GET /v1/exposure/trend?from=&to=   (or periodId=, an audit period)
//
// A "finding" here is an advisory with the hosts it affects, ranked KEV, then
// EPSS, then CVSS (see internal/exposure). Only fixable findings are in the
// "fix" bucket; the "watch" bucket holds findings with nothing to install yet
// (no fix published, or fixed upstream and awaiting the rebuild distribution).
// Lists page with an opaque keyset cursor, like /v1/devices, and are sorted and
// cut in the database: no response carries the whole fleet.

// defaultTop is how many ranked rows the summary carries.
const (
	defaultTop = 5
	maxTop     = 25
	kevWatchN  = 10
)

type exposureSummaryResponse struct {
	storepg.ExposureSummary
	// FixThisWeek is the top of the fix bucket, in rank order.
	FixThisWeek []storepg.ExposureGroup `json:"fixThisWeek"`
	// KEVWatch is the exploited-in-the-wild advisories that have nothing to
	// install: the red callout. A patch cannot fix these; a mitigation can.
	KEVWatch         []storepg.ExposureGroup `json:"kevWatch"`
	LatestSnapshotID *int64                  `json:"latestSnapshotId"`
	GeneratedAt      string                  `json:"generatedAt"`
}

// HandleExposure serves the /v1/exposure/ endpoints.
func (s *Server) HandleExposure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
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
	switch strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/exposure"), "/") {
	case "summary":
		s.exposureSummary(w, r)
	case "findings":
		s.exposureFindings(w, r)
	case "advisory":
		s.exposureAdvisory(w, r)
	case "trend":
		s.exposureTrend(w, r)
	default:
		http.NotFound(w, r)
	}
}

// exposureError answers a store error: validation problems are the caller's
// (400), anything else is ours and is logged.
func (s *Server) exposureError(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, storepg.ErrBadExposureQuery) || errors.Is(err, storepg.ErrBadCursor) || errors.Is(err, storepg.ErrBadTrendWindow) || errors.Is(err, storepg.ErrBadSurfaceKey) || errors.Is(err, storepg.ErrBadIdentityKey) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.log.Warn(what, "err", err)
	http.Error(w, "could not read exposure", http.StatusInternalServerError)
}

func (s *Server) latestSnapshotID(r *http.Request) *int64 {
	if snap, ok, err := s.pg.LatestFeedSnapshot(r.Context()); err == nil && ok {
		return &snap.ID
	}
	return nil
}

func (s *Server) exposureSummary(w http.ResponseWriter, r *http.Request) {
	top := defaultTop
	if v := r.URL.Query().Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxTop {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "top must be between 1 and " + strconv.Itoa(maxTop)})
			return
		}
		top = n
	}
	now := time.Now().UTC()
	sum, err := s.pg.ExposureSummary(r.Context(), now)
	if err != nil {
		s.exposureError(w, "exposure summary", err)
		return
	}
	fix, err := s.pg.ListExposure(r.Context(), storepg.ExposureQuery{Bucket: storepg.BucketFix, Limit: top})
	if err != nil {
		s.exposureError(w, "exposure top", err)
		return
	}
	kev, err := s.pg.ListExposure(r.Context(), storepg.ExposureQuery{Bucket: storepg.BucketWatch, KEVOnly: true, Limit: kevWatchN})
	if err != nil {
		s.exposureError(w, "exposure kev watch", err)
		return
	}
	writeJSON(w, http.StatusOK, exposureSummaryResponse{
		ExposureSummary:  sum,
		FixThisWeek:      fix.Findings,
		KEVWatch:         kev.Findings,
		LatestSnapshotID: s.latestSnapshotID(r),
		GeneratedAt:      now.Format(time.RFC3339),
	})
}

type exposureFindingsResponse struct {
	storepg.ExposurePage
	Sort             string `json:"sort"`
	Bucket           string `json:"bucket"`
	Status           string `json:"status"`
	LatestSnapshotID *int64 `json:"latestSnapshotId"`
	GeneratedAt      string `json:"generatedAt"`
}

func (s *Server) exposureFindings(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	if sort := v.Get("sort"); sort != "" && sort != "rank" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sort must be rank"})
		return
	}
	q := storepg.ExposureQuery{
		Bucket: v.Get("bucket"), Status: v.Get("status"), Cursor: v.Get("cursor"),
		KEVOnly: v.Get("kevOnly") == "1",
	}
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a number"})
			return
		}
		q.Limit = n
	}
	page, err := s.pg.ListExposure(r.Context(), q)
	if err != nil {
		s.exposureError(w, "exposure findings", err)
		return
	}
	bucket := q.Bucket
	if bucket == "" {
		bucket = storepg.BucketFix
	}
	writeJSON(w, http.StatusOK, exposureFindingsResponse{
		ExposurePage: page, Sort: "rank", Bucket: bucket, Status: q.Status,
		LatestSnapshotID: s.latestSnapshotID(r), GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

type exposureAdvisoryResponse struct {
	AdvisoryID string `json:"advisoryId"`
	// Source is storepg.SourceVulnerability; a surface row's drawer answers
	// with exposureSurfaceResponse and source "surface".
	Source string `json:"source"`
	Bucket string `json:"bucket"`
	Status string `json:"status"`
	// Advisory is the vulnerability record; nil if it has been removed.
	Advisory *advisoryJSON `json:"advisory"`
	// Hosts is one row per affected host (and package family): installed vs
	// fixed version, how long it has been open, how it closed, and the feed and
	// snapshot it was computed from.
	Hosts     []exposureHostRow `json:"hosts"`
	Truncated bool              `json:"truncated"`
	// Snapshots are the feed snapshots the hosts' findings reference.
	Snapshots []snapshotJSON `json:"snapshots"`
}

type exposureHostRow struct {
	FindingID int64  `json:"findingId"`
	Key       string `json:"key"`
	DeviceID  string `json:"deviceId"`
	Hostname  string `json:"hostname"`
	Kind      string `json:"kind"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	FixState  string `json:"fixState"`
	Reason    string `json:"reason"`
	// UpstreamFixedOn: for awaiting_vendor, the date Red Hat shipped the fix.
	UpstreamFixedOn string     `json:"upstreamFixedOn"`
	Feed            string     `json:"feed"`
	FeedDate        *time.Time `json:"feedDate"`
	SnapshotID      *int64     `json:"snapshotId"`
	RangeID         *int64     `json:"rangeId"`
	FirstSeen       time.Time  `json:"firstSeen"`
	LastSeen        time.Time  `json:"lastSeen"`
	ResolvedAt      *time.Time `json:"resolvedAt"`
	// Resolution says how a closed finding closed: fixed (the host now has the
	// fixed version), package_removed, no_longer_affected, or "" if not
	// recorded. ResolvedInstalled is the version the host had when it closed.
	Resolution        string `json:"resolution"`
	ResolvedInstalled string `json:"resolvedInstalled"`
	// Origin, OriginRepo, EOL and Controls are set on end-of-life findings:
	// where the packages came from, which release is past support and what to
	// upgrade to, and the framework controls the finding is evidence about.
	Origin     string          `json:"origin"`
	OriginRepo string          `json:"originRepo"`
	EOL        *vuln.EOLDetail `json:"eol"`
	Controls   []string        `json:"controls"`
	// Repo is set on repository-health findings: the repository, every problem
	// found, the evidence dates and the fix text.
	Repo *vuln.RepoDetail `json:"repo"`
}

// exposureSurfaceResponse is the drawer of a surface row of the list: the
// finding, how long it has been open, and the raw observation behind it.
type exposureSurfaceResponse struct {
	AdvisoryID string                `json:"advisoryId"`
	Source     string                `json:"source"`
	Status     string                `json:"status"`
	Detail     storepg.SurfaceDetail `json:"detail"`
}

// exposureSurface serves the drawer of a surface row (id "surface:<12 digits>").
func (s *Server) exposureSurface(w http.ResponseWriter, r *http.Request, id string) {
	d, err := s.pg.GetSurfaceDetail(r.Context(), id)
	if errors.Is(err, storepg.ErrNoSurfaceFinding) {
		http.Error(w, "no such findings", http.StatusNotFound)
		return
	}
	if err != nil {
		s.exposureError(w, "exposure surface finding", err)
		return
	}
	status := storepg.ExposureOpen
	if d.Finding.ResolvedAt != nil {
		status = storepg.ExposureResolved
	}
	writeJSON(w, http.StatusOK, exposureSurfaceResponse{AdvisoryID: id, Source: storepg.SourceSurface, Status: status, Detail: d})
}

// exposureIdentityResponse is the drawer of an identity row of the list: the
// finding, how long it has been open, and what the latest run said of its check.
type exposureIdentityResponse struct {
	AdvisoryID string                 `json:"advisoryId"`
	Source     string                 `json:"source"`
	Status     string                 `json:"status"`
	Detail     storepg.IdentityDetail `json:"detail"`
}

// exposureIdentity serves the drawer of an identity row (id "identity:<12 digits>").
func (s *Server) exposureIdentity(w http.ResponseWriter, r *http.Request, id string) {
	d, err := s.pg.GetIdentityDetail(r.Context(), id)
	if errors.Is(err, storepg.ErrNoIdentityFinding) {
		http.Error(w, "no such findings", http.StatusNotFound)
		return
	}
	if errors.Is(err, storepg.ErrBadIdentityKey) {
		http.Error(w, "bad identity finding id", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.exposureError(w, "exposure identity finding", err)
		return
	}
	status := storepg.ExposureOpen
	if d.Finding.ResolvedAt != nil {
		status = storepg.ExposureResolved
	}
	writeJSON(w, http.StatusOK, exposureIdentityResponse{AdvisoryID: id, Source: storepg.SourceIdentity, Status: status, Detail: d})
}

func (s *Server) exposureAdvisory(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	bucket, status := v.Get("bucket"), v.Get("status")
	if id := v.Get("id"); strings.HasPrefix(id, exposure.SurfaceKeyPrefix) {
		s.exposureSurface(w, r, id)
		return
	}
	if id := v.Get("id"); strings.HasPrefix(id, exposure.IdentityKeyPrefix) {
		s.exposureIdentity(w, r, id)
		return
	}
	d, err := s.pg.GetExposureDetail(r.Context(), v.Get("id"), bucket, status)
	if err != nil {
		s.exposureError(w, "exposure advisory", err)
		return
	}
	if len(d.Findings) == 0 {
		http.Error(w, "no such findings", http.StatusNotFound)
		return
	}
	if bucket == "" {
		bucket = storepg.BucketFix
	}
	if status == "" {
		status = storepg.ExposureOpen
	}
	resp := exposureAdvisoryResponse{
		AdvisoryID: d.AdvisoryID, Source: storepg.SourceVulnerability, Bucket: bucket, Status: status, Truncated: d.Truncated,
		Hosts: make([]exposureHostRow, 0, len(d.Findings)), Snapshots: []snapshotJSON{},
	}
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
	for _, f := range d.Findings {
		resp.Hosts = append(resp.Hosts, exposureHostRow{
			FindingID: f.ID, Key: f.Key, DeviceID: f.DeviceID, Hostname: f.Hostname, Kind: f.Kind,
			Package: f.Package, Installed: f.Installed, Fixed: f.Fixed, FixState: f.FixState, Reason: f.Reason, UpstreamFixedOn: f.UpstreamFixedOn,
			Feed: f.Feed, FeedDate: utcPtr(f.FeedDate), SnapshotID: f.SnapshotID, RangeID: f.RangeID,
			FirstSeen: f.FirstSeen.UTC(), LastSeen: f.LastSeen.UTC(), ResolvedAt: utcPtr(f.ResolvedAt),
			Resolution: f.Resolution, ResolvedInstalled: f.ResolvedInstalled,
			Origin: f.Origin, OriginRepo: f.OriginRepo, EOL: f.EOL, Controls: f.Controls, Repo: f.Repo,
		})
	}
	for _, sn := range d.Snapshots {
		out := snapshotJSON{ID: sn.ID, CreatedAt: sn.CreatedAt.UTC().Format(time.RFC3339), Feeds: []snapshotFeedJSON{}}
		for _, f := range sn.Feeds {
			out.Feeds = append(out.Feeds, snapshotFeedJSON{
				Name: f.Name, URL: f.URL, FetchedAt: f.FetchedAt.UTC().Format(time.RFC3339),
				SHA256: f.SHA256, RecordCount: f.RecordCount,
			})
		}
		resp.Snapshots = append(resp.Snapshots, out)
	}
	writeJSON(w, http.StatusOK, resp)
}

// utcPtr is t in UTC: the console reads dates off the front of these strings,
// so they must not depend on the server's zone.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

type exposureTrendResponse struct {
	storepg.ExposureTrend
	// Period names the audit period the window was taken from, if any.
	Period      *exposurePeriod `json:"period"`
	GeneratedAt string          `json:"generatedAt"`
	Caveats     []string        `json:"caveats"`
}

type exposurePeriod struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Closed bool   `json:"closed"`
}

// exposureTrendCaveats say what the series is built from, so a chart is never
// read as more than it is.
var exposureTrendCaveats = []string{
	"A finding is one advisory on one host. Each day counts the findings first seen by the end of that day and not yet closed.",
	"Days before the first feed snapshot are marked unknown; their zeros mean no data, not a clean fleet.",
	"A finding whose kind changed (awaiting vendor, then fixable) counts under its current kind for its whole open interval.",
	"The surface line counts external surface findings (critical, high, medium, low; never info) open at the end of each day, from the first surface scan; days before it are marked unknown. A surface finding that closed and came back counts as closed in between, except for findings reopened before slice 7b, whose closed days were not recorded. A finding's severity is taken from its record at the time it was last open.",
	"Software past its upstream end of life counts with the fixable findings: upgrading it is work for this week.",
}

func (s *Server) exposureTrend(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	var period *exposurePeriod
	var from, to time.Time
	if id := r.URL.Query().Get("periodId"); id != "" {
		p, err := s.pg.GetAuditPeriod(r.Context(), id)
		if errors.Is(err, storepg.ErrNotFound) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no such audit period"})
			return
		}
		if err != nil {
			s.exposureError(w, "exposure trend period", err)
			return
		}
		period = &exposurePeriod{ID: p.ID, Name: p.Name, Closed: p.Closed()}
		from, to = p.StartsAt, p.EndsAt
	} else {
		var err error
		if from, to, err = windowFromQuery(r); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	trend, err := s.pg.ExposureTrend(r.Context(), from, to, now)
	if err != nil {
		s.exposureError(w, "exposure trend", err)
		return
	}
	writeJSON(w, http.StatusOK, exposureTrendResponse{
		ExposureTrend: trend, Period: period, GeneratedAt: now.Format(time.RFC3339), Caveats: exposureTrendCaveats,
	})
}
