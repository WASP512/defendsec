package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"defendsec/internal/storepg"
	"defendsec/internal/surface"
)

// External surface scanner API (slice 7a):
//
//	GET    /v1/assets                     declared assets (viewers may read)
//	POST   /v1/assets                     declare one: {kind, value, label, dkimSelectors, sharedHosting, mailHost, authorised}
//	POST   /v1/assets/{id}/authorise      {authorised: true|false}: the "I am authorised to test this" confirmation
//	DELETE /v1/assets/{id}                stop scanning and hide it (findings stay as evidence)
//	GET    /v1/surface/findings           findings with each asset's state and what could not be assessed
//	POST   /v1/surface/scan               {assetId?, wait?}: scan one asset, or every authorised one
//
// Reads are open to viewers; every write needs an administrator, as for the
// neighbouring admin routes. The scanner only ever checks assets that are
// declared and confirmed as authorised; see surface.Scanner.ScanAsset.

const (
	// SurfaceScanInterval is how often a confirmed asset is rescanned.
	SurfaceScanInterval = 24 * time.Hour
	// SurfaceScheduleCheck is how often the scheduler looks for assets that are due.
	SurfaceScheduleCheck = 30 * time.Minute
	surfaceScanTimeout   = 5 * time.Minute
	// surfaceManualCooldown stops a double click starting a scan right after one.
	surfaceManualCooldown = 15 * time.Second
)

// surfaceRunner holds the scanner and what is running.
type surfaceRunner struct {
	mu       sync.Mutex
	scanner  *surface.Scanner
	running  map[int64]bool
	lastRun  map[int64]time.Time
	cooldown time.Duration
	wg       sync.WaitGroup
}

// SetSurfaceScanner installs the scanner. Without a call apid builds one from
// the environment the first time a scan is requested.
func (s *Server) SetSurfaceScanner(sc *surface.Scanner) {
	s.surf.mu.Lock()
	defer s.surf.mu.Unlock()
	s.surf.scanner = sc
}

func (s *Server) surfaceScanner() *surface.Scanner {
	s.surf.mu.Lock()
	defer s.surf.mu.Unlock()
	if s.surf.scanner == nil {
		s.surf.scanner = surface.NewScanner(surface.ConfigFromEnv())
	}
	return s.surf.scanner
}

func (s *Server) surfaceReady(w http.ResponseWriter, r *http.Request, write bool) bool {
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if write && !s.adminWriteOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if s.pg == nil {
		http.Error(w, "postgres not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func decodeStrict(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

type assetsResponse struct {
	Assets      []storepg.SurfaceAsset `json:"assets"`
	GeneratedAt string                 `json:"generatedAt"`
}

type assetRequest struct {
	Kind          string   `json:"kind"`
	Value         string   `json:"value"`
	Label         string   `json:"label"`
	DKIMSelectors []string `json:"dkimSelectors"`
	SharedHosting bool     `json:"sharedHosting"`
	MailHost      bool     `json:"mailHost"`
	Authorised    bool     `json:"authorised"`
}

// HandleAssets serves /v1/assets and /v1/assets/{id}[/authorise].
func (s *Server) HandleAssets(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/assets"), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		if !s.surfaceReady(w, r, false) {
			return
		}
		s.listAssets(w, r)
	case rest == "" && r.Method == http.MethodPost:
		if !s.surfaceReady(w, r, true) {
			return
		}
		s.createAsset(w, r)
	case rest != "":
		idPart, action, _ := strings.Cut(rest, "/")
		id, err := strconv.ParseInt(idPart, 10, 64)
		if err != nil || id < 1 {
			http.Error(w, "asset id must be a positive integer", http.StatusBadRequest)
			return
		}
		switch {
		case action == "authorise" && r.Method == http.MethodPost:
			if !s.surfaceReady(w, r, true) {
				return
			}
			s.authoriseAsset(w, r, id)
		case action == "" && r.Method == http.MethodDelete:
			if !s.surfaceReady(w, r, true) {
				return
			}
			s.removeAsset(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.pg.ListSurfaceAssets(r.Context())
	if err != nil {
		s.log.Warn("list surface assets", "err", err)
		http.Error(w, "could not read assets", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, assetsResponse{Assets: assets, GeneratedAt: time.Now().UTC().Format(time.RFC3339)})
}

func (s *Server) createAsset(w http.ResponseWriter, r *http.Request) {
	var req assetRequest
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	value, err := surface.NormaliseAsset(surface.Kind(req.Kind), req.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	selectors, err := surface.NormaliseSelectors(req.DKIMSelectors)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(selectors) > 0 && req.Kind != string(surface.KindDomain) {
		http.Error(w, "DKIM selectors apply to domain assets only", http.StatusBadRequest)
		return
	}
	if (req.SharedHosting || req.MailHost) && req.Kind != string(surface.KindIP) {
		http.Error(w, "sharedHosting and mailHost describe an IP address asset", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > 200 {
		http.Error(w, "label is longer than 200 characters", http.StatusBadRequest)
		return
	}
	actor := s.actorIdentity(r)
	a, err := s.pg.CreateSurfaceAsset(r.Context(), storepg.SurfaceAssetInput{
		Kind: req.Kind, Value: value, Label: label, DKIMSelectors: selectors,
		SharedHosting: req.SharedHosting, MailHost: req.MailHost,
		Authorised: req.Authorised, AuthorisedBy: actor, CreatedBy: actor,
	})
	if errors.Is(err, storepg.ErrSurfaceAssetExists) {
		http.Error(w, "that asset is already declared", http.StatusConflict)
		return
	}
	if err != nil {
		s.log.Warn("create surface asset", "err", err)
		http.Error(w, "could not save the asset", http.StatusInternalServerError)
		return
	}
	s.audit(actor, "surface_asset_add", "", map[string]any{"id": a.ID, "kind": a.Kind, "value": a.Value, "authorised": a.Authorised})
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) authoriseAsset(w http.ResponseWriter, r *http.Request, id int64) {
	var req struct {
		Authorised *bool `json:"authorised"`
	}
	if err := decodeStrict(r, &req); err != nil || req.Authorised == nil {
		http.Error(w, `body must be {"authorised": true|false}`, http.StatusBadRequest)
		return
	}
	actor := s.actorIdentity(r)
	if err := s.pg.SetSurfaceAssetAuthorised(r.Context(), id, *req.Authorised, actor); err != nil {
		if errors.Is(err, storepg.ErrNoSurfaceAsset) {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		s.log.Warn("authorise surface asset", "err", err)
		http.Error(w, "could not save the asset", http.StatusInternalServerError)
		return
	}
	a, err := s.pg.GetSurfaceAsset(r.Context(), id)
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	s.audit(actor, "surface_asset_authorise", "", map[string]any{"id": a.ID, "value": a.Value, "authorised": a.Authorised})
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) removeAsset(w http.ResponseWriter, r *http.Request, id int64) {
	a, err := s.pg.GetSurfaceAsset(r.Context(), id)
	if errors.Is(err, storepg.ErrNoSurfaceAsset) {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "could not read the asset", http.StatusInternalServerError)
		return
	}
	if err := s.pg.RemoveSurfaceAsset(r.Context(), id); err != nil {
		s.log.Warn("remove surface asset", "err", err)
		http.Error(w, "could not remove the asset", http.StatusInternalServerError)
		return
	}
	s.audit(s.actorIdentity(r), "surface_asset_remove", "", map[string]any{"id": a.ID, "kind": a.Kind, "value": a.Value})
	writeJSON(w, http.StatusOK, map[string]any{"removed": true})
}

// --- findings ---------------------------------------------------------------

type surfaceCheckJSON struct {
	Check      string         `json:"check"`
	Assessed   bool           `json:"assessed"`
	Reason     string         `json:"reason"`
	Observed   map[string]any `json:"observed"`
	ObservedAt time.Time      `json:"observedAt"`
	ScanID     int64          `json:"scanId"`
}

type surfaceAssetState struct {
	storepg.SurfaceAsset
	// Open counts open findings by severity.
	Open map[string]int `json:"open"`
	// Checks is the latest observation of every check that has run, with the
	// raw material behind it. NotAssessed are the ones that could not reach a
	// conclusion: missing evidence, which is not the same as clean.
	Checks      []surfaceCheckJSON `json:"checks"`
	NotAssessed []surfaceCheckJSON `json:"notAssessed"`
	Scanning    bool               `json:"scanning"`
}

type surfaceFindingsResponse struct {
	Findings    []storepg.SurfaceFinding `json:"findings"`
	Assets      []surfaceAssetState      `json:"assets"`
	Total       int                      `json:"total"`
	Truncated   bool                     `json:"truncated"`
	GeneratedAt string                   `json:"generatedAt"`
}

// HandleSurfaceFindings serves GET /v1/surface/findings?assetId=&resolved=1&limit=.
func (s *Server) HandleSurfaceFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.surfaceReady(w, r, false) {
		return
	}
	q := r.URL.Query()
	f := storepg.SurfaceFindingFilter{IncludeResolved: q.Get("resolved") == "1"}
	if v := q.Get("assetId"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 1 {
			http.Error(w, "assetId must be a positive integer", http.StatusBadRequest)
			return
		}
		f.AssetID = id
	}
	limit := 1000
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > storepg.MaxSurfaceFindingsPage {
			http.Error(w, "limit must be between 1 and "+strconv.Itoa(storepg.MaxSurfaceFindingsPage), http.StatusBadRequest)
			return
		}
		limit = n
	}
	f.Limit = limit + 1
	rows, err := s.pg.ListSurfaceFindings(r.Context(), f)
	if err != nil {
		s.log.Warn("list surface findings", "err", err)
		http.Error(w, "could not read findings", http.StatusInternalServerError)
		return
	}
	resp := surfaceFindingsResponse{Findings: rows, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	if len(rows) > limit {
		resp.Findings, resp.Truncated = rows[:limit], true
	}
	resp.Total = len(resp.Findings)

	assets, err := s.pg.ListSurfaceAssets(r.Context())
	if err != nil {
		http.Error(w, "could not read assets", http.StatusInternalServerError)
		return
	}
	checks, err := s.pg.SurfaceChecks(r.Context(), f.AssetID)
	if err != nil {
		http.Error(w, "could not read observations", http.StatusInternalServerError)
		return
	}
	// Open counts come from every open finding, not just this page of them.
	openRows, err := s.pg.ListSurfaceFindings(r.Context(), storepg.SurfaceFindingFilter{AssetID: f.AssetID})
	if err != nil {
		http.Error(w, "could not read findings", http.StatusInternalServerError)
		return
	}
	openBy := map[int64]map[string]int{}
	for _, o := range openRows {
		if openBy[o.AssetID] == nil {
			openBy[o.AssetID] = map[string]int{}
		}
		openBy[o.AssetID][o.Severity]++
	}
	checksBy := map[int64][]surfaceCheckJSON{}
	for _, c := range checks {
		checksBy[c.AssetID] = append(checksBy[c.AssetID], surfaceCheckJSON{
			Check: c.Check, Assessed: c.Assessed, Reason: c.Reason, Observed: c.Observed, ObservedAt: c.ObservedAt, ScanID: c.ScanID,
		})
	}
	resp.Assets = make([]surfaceAssetState, 0, len(assets))
	for _, a := range assets {
		if f.AssetID != 0 && a.ID != f.AssetID {
			continue
		}
		st := surfaceAssetState{SurfaceAsset: a, Open: openBy[a.ID], Checks: checksBy[a.ID], NotAssessed: []surfaceCheckJSON{}, Scanning: s.surfaceRunning(a.ID)}
		if st.Open == nil {
			st.Open = map[string]int{}
		}
		if st.Checks == nil {
			st.Checks = []surfaceCheckJSON{}
		}
		for _, c := range st.Checks {
			if !c.Assessed {
				st.NotAssessed = append(st.NotAssessed, c)
			}
		}
		resp.Assets = append(resp.Assets, st)
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- scanning ---------------------------------------------------------------

type surfaceScanResult struct {
	AssetID int64                       `json:"assetId"`
	Value   string                      `json:"value"`
	Status  string                      `json:"status"` // started, done, already_running, too_soon, skipped, failed
	Reason  string                      `json:"reason,omitempty"`
	Summary *storepg.SurfaceScanSummary `json:"summary,omitempty"`
}

func (s *Server) surfaceRunning(id int64) bool {
	s.surf.mu.Lock()
	defer s.surf.mu.Unlock()
	return s.surf.running[id]
}

// claimSurfaceScan marks an asset as scanning, or says why it cannot be.
func (s *Server) claimSurfaceScan(id int64, manual bool) (string, bool) {
	s.surf.mu.Lock()
	defer s.surf.mu.Unlock()
	if s.surf.running == nil {
		s.surf.running, s.surf.lastRun = map[int64]bool{}, map[int64]time.Time{}
	}
	if s.surf.running[id] {
		return "already_running", false
	}
	cool := surfaceManualCooldown
	if s.surf.cooldown != 0 {
		cool = s.surf.cooldown
	}
	if manual && cool > 0 && time.Since(s.surf.lastRun[id]) < cool {
		return "too_soon", false
	}
	s.surf.running[id] = true
	s.surf.lastRun[id] = time.Now()
	return "", true
}

func (s *Server) releaseSurfaceScan(id int64) {
	s.surf.mu.Lock()
	delete(s.surf.running, id)
	s.surf.mu.Unlock()
}

// runSurfaceScan scans one asset and records the result. The asset is read
// again from the database first, so an authorisation withdrawn a moment ago is
// honoured, and RecordSurfaceScan checks it once more before writing.
func (s *Server) runSurfaceScan(ctx context.Context, id int64, trigger string) (*storepg.SurfaceScanSummary, storepg.SurfaceAsset, error) {
	ctx, cancel := context.WithTimeout(ctx, surfaceScanTimeout)
	defer cancel()
	a, err := s.pg.GetSurfaceAsset(ctx, id)
	if err != nil {
		return nil, a, err
	}
	if !a.Authorised {
		return nil, a, storepg.ErrSurfaceAssetNotAuthorised
	}
	rep, err := s.surfaceScanner().ScanAsset(ctx, a.ScanAsset())
	if err != nil {
		return nil, a, err
	}
	sum, err := s.pg.RecordSurfaceScan(ctx, a.ID, trigger, rep)
	if err != nil {
		return nil, a, err
	}
	return &sum, a, nil
}

// HandleSurfaceScan serves POST /v1/surface/scan.
func (s *Server) HandleSurfaceScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.surfaceReady(w, r, true) {
		return
	}
	var req struct {
		AssetID int64 `json:"assetId"`
		Wait    bool  `json:"wait"`
	}
	if r.ContentLength != 0 {
		if err := decodeStrict(r, &req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	var targets []storepg.SurfaceAsset
	if req.AssetID != 0 {
		a, err := s.pg.GetSurfaceAsset(r.Context(), req.AssetID)
		if errors.Is(err, storepg.ErrNoSurfaceAsset) {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "could not read the asset", http.StatusInternalServerError)
			return
		}
		if !a.Authorised {
			http.Error(w, "asset is not confirmed as authorised to test: confirm it on the Assets page first", http.StatusConflict)
			return
		}
		targets = []storepg.SurfaceAsset{a}
	} else {
		all, err := s.pg.ListSurfaceAssets(r.Context())
		if err != nil {
			http.Error(w, "could not read assets", http.StatusInternalServerError)
			return
		}
		targets = all
	}
	actor := s.actorIdentity(r)
	s.audit(actor, "surface_scan", "", map[string]any{"assetId": req.AssetID, "assets": len(targets), "wait": req.Wait})

	results := make([]surfaceScanResult, 0, len(targets))
	var claimed []storepg.SurfaceAsset
	for _, a := range targets {
		res := surfaceScanResult{AssetID: a.ID, Value: a.Value}
		if !a.Authorised {
			res.Status, res.Reason = "skipped", "not confirmed as authorised to test"
			results = append(results, res)
			continue
		}
		if why, ok := s.claimSurfaceScan(a.ID, true); !ok {
			res.Status = why
			results = append(results, res)
			continue
		}
		claimed = append(claimed, a)
		res.Status = "started"
		results = append(results, res)
	}

	scanAll := func(ctx context.Context) map[int64]surfaceScanResult {
		done := map[int64]surfaceScanResult{}
		for _, a := range claimed {
			res := surfaceScanResult{AssetID: a.ID, Value: a.Value, Status: "done"}
			sum, _, err := s.runSurfaceScan(ctx, a.ID, "manual")
			s.releaseSurfaceScan(a.ID)
			if err != nil {
				res.Status, res.Reason = "failed", err.Error()
				s.log.Warn("surface scan", "err", err, "asset", a.Value)
				s.auditSurfaceScanFailed(actor, a, "manual", err)
			}
			res.Summary = sum
			done[a.ID] = res
		}
		return done
	}

	if req.Wait {
		// Detached from the request so a closed browser tab cannot leave a scan half-recorded.
		done := scanAll(context.WithoutCancel(r.Context()))
		for i, res := range results {
			if d, ok := done[res.AssetID]; ok {
				results[i] = d
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"scans": results})
		return
	}
	if len(claimed) > 0 {
		s.surf.wg.Add(1)
		go func() {
			defer s.surf.wg.Done()
			scanAll(context.Background())
		}()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scans": results})
}

// auditSurfaceScanFailed writes a failed scan to the ledger. A scan that could
// not be recorded leaves no scan row, so without this entry a failing schedule is
// silent: nothing would show that an asset has gone unscanned. The error is cut
// short, since it can carry a resolver's own wording.
func (s *Server) auditSurfaceScanFailed(actor string, a storepg.SurfaceAsset, trigger string, err error) {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	s.audit(actor, "surface_scan_failed", "", map[string]any{"assetId": a.ID, "value": a.Value, "trigger": trigger, "error": msg})
}

// RunSurfaceSchedule scans every confirmed asset that has not been scanned
// within SurfaceScanInterval, checking every `every` until ctx ends. Scanning
// by schedule is the same act as scanning on demand, on the same assets: it
// never reaches an asset that is not declared and confirmed.
func (s *Server) RunSurfaceSchedule(ctx context.Context, every time.Duration) {
	if s.pg == nil {
		return
	}
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.scanDueSurfaceAssets(ctx)
		timer.Reset(every)
	}
}

// scanDueSurfaceAssets runs one pass of the schedule and reports how many assets it scanned.
func (s *Server) scanDueSurfaceAssets(ctx context.Context) int {
	due, err := s.pg.SurfaceAssetsDue(ctx, SurfaceScanInterval)
	if err != nil {
		s.log.Warn("surface schedule", "err", err)
		return 0
	}
	n := 0
	for _, a := range due {
		if ctx.Err() != nil {
			break
		}
		if _, ok := s.claimSurfaceScan(a.ID, false); !ok {
			continue
		}
		sum, _, err := s.runSurfaceScan(ctx, a.ID, "schedule")
		s.releaseSurfaceScan(a.ID)
		if err != nil {
			s.log.Warn("scheduled surface scan", "err", err, "asset", a.Value)
			s.auditSurfaceScanFailed("system:surface-schedule", a, "schedule", err)
			continue
		}
		n++
		s.audit("system:surface-schedule", "surface_scan", "", map[string]any{"assetId": a.ID, "scheduled": true, "open": sum.Open})
	}
	if n > 0 {
		s.log.Info("surface schedule", "scanned", n)
	}
	return n
}
