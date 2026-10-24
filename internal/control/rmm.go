package control

import (
	"context"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"defendsec/internal/rmm"
	"defendsec/internal/rmm/datto"
	"defendsec/internal/secret"
	"defendsec/internal/storepg"
)

// Datto RMM collector API (slice 8):
//
//	GET  /v1/rmm/status           what is configured, the counts, the last read, and what is not assessed (viewers)
//	GET  /v1/rmm/sites            the live site list, to pick one from (admins: it spends RMM request quota and names clients)
//	PUT  /v1/rmm/settings         {siteUid, staleAfterDays?}: choose the one site this instance reads (admins)
//	POST /v1/rmm/sync             {wait?}: read the site now (admins). 202 and a background read, or 200 with the result
//	GET  /v1/rmm/devices          the RMM devices (viewers)
//	GET  /v1/rmm/devices/{id}     one device with its missing updates and software (viewers)
//	GET  /v1/rmm/syncs?limit=     the history of reads (viewers)
//
// The API key and secret are never accepted over the API. apid reads them from
// the files named in DEFENDSEC_RMM_KEY_FILE and DEFENDSEC_RMM_SECRET_FILE, and
// the platform's API host from DEFENDSEC_RMM_API_URL, each time it reads, so
// rotating a key is replacing a file.
//
// Everything the collector does against Datto is a GET. There is no route that
// runs a job, a component or a script, or changes anything in RMM.

const (
	// RMMSyncInterval is how often the site is read.
	RMMSyncInterval = 6 * time.Hour
	// RMMScheduleCheck is how often the scheduler looks whether a read is due.
	RMMScheduleCheck = 30 * time.Minute
	rmmSyncTimeout   = 45 * time.Minute
)

// rmmClient is what the API reads: the collector's source, and the site list.
type rmmClient interface {
	rmm.Source
	Sites(ctx context.Context) ([]datto.Site, error)
}

type rmmRunner struct {
	mu      sync.Mutex
	running bool
	// open builds the client for one read. Nil means: from the environment.
	open func() (rmmClient, error)
	// interval is how often the schedule reads the site (0 = RMMSyncInterval).
	interval time.Duration
}

// SetRMMClient replaces how the RMM client is built (tests, or a deployment
// that keeps its credentials somewhere else).
func (s *Server) SetRMMClient(open func() (rmmClient, error)) {
	s.rmmr.mu.Lock()
	defer s.rmmr.mu.Unlock()
	s.rmmr.open = open
}

// rmmCredentials describes the configured credentials for the status API,
// without a secret in it.
type rmmCredentials struct {
	Configured bool     `json:"configured"`
	APIURL     string   `json:"apiUrl"`
	Problem    string   `json:"problem,omitempty"`
	Warnings   []string `json:"warnings"`
}

// rmmClientFromEnv builds a client from the environment and the credential
// files. It describes what is wrong in plain words and never includes a value.
func rmmClientFromEnv() (rmmClient, rmmCredentials, error) {
	cr := rmmCredentials{Warnings: []string{}}
	raw := strings.TrimSpace(os.Getenv("DEFENDSEC_RMM_API_URL"))
	keyFile := strings.TrimSpace(os.Getenv("DEFENDSEC_RMM_KEY_FILE"))
	secFile := strings.TrimSpace(os.Getenv("DEFENDSEC_RMM_SECRET_FILE"))
	if raw == "" && keyFile == "" && secFile == "" {
		cr.Problem = "Datto RMM is not configured: set DEFENDSEC_RMM_API_URL, DEFENDSEC_RMM_KEY_FILE and DEFENDSEC_RMM_SECRET_FILE for apid"
		return nil, cr, errors.New(cr.Problem)
	}
	fail := func(msg string) (rmmClient, rmmCredentials, error) {
		cr.Problem = msg
		return nil, cr, errors.New(msg)
	}
	if raw == "" {
		return fail("DEFENDSEC_RMM_API_URL is not set (the API URL shown on the API user's page, https://<platform>-api.centrastage.net)")
	}
	u, err := datto.ValidateAPIURL(raw)
	if err != nil {
		return fail("DEFENDSEC_RMM_API_URL: " + err.Error())
	}
	cr.APIURL = u.String()
	key, w1, err := secret.ReadFile(keyFile)
	if err != nil {
		return fail("DEFENDSEC_RMM_KEY_FILE: " + err.Error())
	}
	sec, w2, err := secret.ReadFile(secFile)
	if err != nil {
		return fail("DEFENDSEC_RMM_SECRET_FILE: " + err.Error())
	}
	for _, w := range []string{w1, w2} {
		if w != "" {
			cr.Warnings = append(cr.Warnings, w)
		}
	}
	c, err := datto.New(datto.Config{APIURL: raw, Key: key, Secret: sec})
	if err != nil {
		return fail("Datto RMM client: " + err.Error())
	}
	cr.Configured = true
	return c, cr, nil
}

func (s *Server) rmmClient() (rmmClient, error) {
	s.rmmr.mu.Lock()
	open := s.rmmr.open
	s.rmmr.mu.Unlock()
	if open != nil {
		return open()
	}
	c, _, err := rmmClientFromEnv()
	return c, err
}

func (s *Server) rmmCredentialsState() rmmCredentials {
	s.rmmr.mu.Lock()
	open := s.rmmr.open
	s.rmmr.mu.Unlock()
	if open != nil {
		if _, err := open(); err != nil {
			return rmmCredentials{Problem: err.Error(), Warnings: []string{}}
		}
		return rmmCredentials{Configured: true, Warnings: []string{}}
	}
	_, cr, _ := rmmClientFromEnv()
	return cr
}

var rmmDeviceIDRe = regexp.MustCompile(`^rmm-[A-Za-z0-9_-]{4,64}$`)

// rmmNotAssessed is what the RMM collector does not cover, said once, here, so
// the console shows the same words every time it is asked.
var rmmNotAssessed = []map[string]string{
	{
		"what": "Third-party application vulnerabilities",
		"why":  "Datto RMM reports an application's name and version, with no publisher or package identity to match a security advisory against. Windows updates are matched through the Microsoft Security Update Guide; third-party applications (browsers, PDF readers, archivers, runtimes) are listed but their CVEs are not assessed.",
	},
	{
		"what": "Windows updates the RMM does not list",
		"why":  "Only updates RMM lists as not installed are mapped to CVEs. A device RMM has not audited recently, or whose patch list could not be read, is not assessed, and never counted clean.",
	},
}

func (s *Server) rmmReady(w http.ResponseWriter, r *http.Request, write bool) bool {
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

// HandleRMM serves /v1/rmm/...
func (s *Server) HandleRMM(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/rmm"), "/")
	switch {
	case rest == "status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.rmmReady(w, r, false) {
			s.rmmStatus(w, r)
		}
	case rest == "sites":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.rmmReady(w, r, true) {
			s.rmmSites(w, r)
		}
	case rest == "settings":
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.rmmReady(w, r, true) {
			s.rmmSettings(w, r)
		}
	case rest == "sync":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.rmmReady(w, r, true) {
			s.rmmSync(w, r)
		}
	case rest == "syncs":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.rmmReady(w, r, false) {
			n := 20
			if v := r.URL.Query().Get("limit"); v != "" {
				var err error
				if n, err = strconv.Atoi(v); err != nil || n < 1 || n > 100 {
					http.Error(w, "limit must be 1 to 100", http.StatusBadRequest)
					return
				}
			}
			list, err := s.pg.ListRMMSyncs(r.Context(), n)
			if err != nil {
				s.log.Warn("list rmm syncs", "err", err)
				http.Error(w, "could not read the history", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"syncs": list})
		}
	case rest == "devices":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.rmmReady(w, r, false) {
			rows, err := s.pg.ListRMMDevices(r.Context(), time.Now().UTC(), 1000)
			if err != nil {
				s.log.Warn("list rmm devices", "err", err)
				http.Error(w, "could not read the devices", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"devices": rows, "generatedAt": time.Now().UTC().Format(time.RFC3339)})
		}
	case strings.HasPrefix(rest, "devices/"):
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.rmmReady(w, r, false) {
			return
		}
		id := strings.TrimPrefix(rest, "devices/")
		if !rmmDeviceIDRe.MatchString(id) {
			http.Error(w, "not an RMM device id", http.StatusBadRequest)
			return
		}
		d, err := s.pg.GetRMMDevice(r.Context(), time.Now().UTC(), id)
		if errors.Is(err, storepg.ErrRMMNotFound) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		if err != nil {
			s.log.Warn("get rmm device", "err", err)
			http.Error(w, "could not read the device", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, d)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) rmmStatus(w http.ResponseWriter, r *http.Request) {
	sum, err := s.pg.RMMSummary(r.Context(), time.Now().UTC())
	if err != nil {
		s.log.Warn("rmm summary", "err", err)
		http.Error(w, "could not read the RMM state", http.StatusInternalServerError)
		return
	}
	s.rmmr.mu.Lock()
	running := s.rmmr.running
	s.rmmr.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":       sum,
		"credentials":   s.rmmCredentialsState(),
		"running":       running,
		"intervalHours": s.rmmInterval().Hours(),
		"scheduled":     strings.ToLower(strings.TrimSpace(os.Getenv("DEFENDSEC_RMM_SCHEDULE"))) != "off",
		"notAssessed":   rmmNotAssessed,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"readOnlyNote":  "DefendSec only ever reads from Datto RMM (GET requests, apart from the token request). It never runs a job, component or script and never changes anything in RMM.",
	})
}

func (s *Server) rmmSites(w http.ResponseWriter, r *http.Request) {
	c, err := s.rmmClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	sites, err := c.Sites(r.Context())
	if err != nil {
		s.log.Warn("rmm sites", "err", err)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": datto.Reason(err), "kind": string(datto.KindOf(err))})
		return
	}
	cur, _ := s.pg.GetRMMSettings(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"sites": sites, "selected": cur.SiteUID})
}

func (s *Server) rmmSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SiteUID        string `json:"siteUid"`
		StaleAfterDays *int   `json:"staleAfterDays"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.SiteUID = strings.TrimSpace(req.SiteUID)
	if req.SiteUID == "" {
		http.Error(w, "siteUid is required: pick one from GET /v1/rmm/sites", http.StatusBadRequest)
		return
	}
	cur, err := s.pg.GetRMMSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	days := cur.StaleAfterDays
	if req.StaleAfterDays != nil {
		days = *req.StaleAfterDays
	}
	if days < 1 || days > 90 {
		http.Error(w, "staleAfterDays must be between 1 and 90", http.StatusBadRequest)
		return
	}
	// The site must come from the live list: a typed UID that RMM does not know is
	// refused, and the name stored is RMM's own.
	c, err := s.rmmClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	sites, err := c.Sites(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": datto.Reason(err), "kind": string(datto.KindOf(err))})
		return
	}
	name := ""
	for _, st := range sites {
		if st.UID == req.SiteUID {
			name = st.Name
		}
	}
	if name == "" {
		http.Error(w, "that site is not in the RMM's site list", http.StatusBadRequest)
		return
	}
	if err := s.pg.SetRMMSettings(r.Context(), s.actorIdentity(r), req.SiteUID, name, days); err != nil {
		s.log.Warn("set rmm settings", "err", err)
		http.Error(w, "could not save the settings", http.StatusInternalServerError)
		return
	}
	got, _ := s.pg.GetRMMSettings(r.Context())
	writeJSON(w, http.StatusOK, got)
}

func (s *Server) rmmInterval() time.Duration {
	s.rmmr.mu.Lock()
	defer s.rmmr.mu.Unlock()
	if s.rmmr.interval > 0 {
		return s.rmmr.interval
	}
	if v := strings.TrimSpace(os.Getenv("DEFENDSEC_RMM_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Hour && d <= 24*time.Hour {
			return d
		}
	}
	return RMMSyncInterval
}

func (s *Server) claimRMM() bool {
	s.rmmr.mu.Lock()
	defer s.rmmr.mu.Unlock()
	if s.rmmr.running {
		return false
	}
	s.rmmr.running = true
	return true
}

func (s *Server) releaseRMM() {
	s.rmmr.mu.Lock()
	s.rmmr.running = false
	s.rmmr.mu.Unlock()
}

// runRMMSync reads the site once; the caller holds the claim.
func (s *Server) runRMMSync(ctx context.Context, trigger string) (storepg.RMMSync, error) {
	c, err := s.rmmClient()
	if err != nil {
		return storepg.RMMSync{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, rmmSyncTimeout)
	defer cancel()
	sy := &rmm.Syncer{Src: c, Store: s.pg, Log: s.log}
	return sy.Sync(ctx, trigger)
}

func (s *Server) rmmSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Wait bool `json:"wait"`
	}
	if r.ContentLength != 0 {
		if err := decodeStrict(r, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	cfg, err := s.pg.GetRMMSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	if !cfg.Configured {
		http.Error(w, "no RMM site is selected: choose one first (PUT /v1/rmm/settings)", http.StatusBadRequest)
		return
	}
	if _, err := s.rmmClient(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !s.claimRMM() {
		http.Error(w, "a read of the RMM is already running", http.StatusConflict)
		return
	}
	actor := s.actorIdentity(r)
	if req.Wait {
		defer s.releaseRMM()
		out, err := s.runRMMSync(r.Context(), "manual:"+actor)
		if err != nil {
			s.log.Warn("rmm sync", "err", err)
			http.Error(w, "the read failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	go func() {
		defer s.releaseRMM()
		if _, err := s.runRMMSync(context.Background(), "manual:"+actor); err != nil {
			s.log.Warn("rmm sync", "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// RunRMMSchedule reads the selected site every interval (6 hours unless
// DEFENDSEC_RMM_INTERVAL says otherwise), checking every `every` whether a read
// is due. With no site selected, or no credentials, it does nothing. It is
// ordinary reading, on the one site the operator selected: it never reaches
// another site.
func (s *Server) RunRMMSchedule(ctx context.Context, every time.Duration) {
	if s.pg == nil {
		return
	}
	timer := time.NewTimer(3 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.rmmScheduleOnce(ctx)
		timer.Reset(every)
	}
}

// rmmScheduleOnce runs one pass of the schedule and reports whether it read.
func (s *Server) rmmScheduleOnce(ctx context.Context) bool {
	cfg, err := s.pg.GetRMMSettings(ctx)
	if err != nil || !cfg.Configured {
		return false
	}
	if last, err := s.pg.LatestRMMSync(ctx); err == nil && last != nil && last.SiteUID == cfg.SiteUID &&
		time.Since(last.FinishedAt) < s.rmmInterval() {
		return false
	}
	if _, err := s.rmmClient(); err != nil {
		s.log.Warn("rmm schedule: not configured", "err", err)
		return false
	}
	if !s.claimRMM() {
		return false
	}
	defer s.releaseRMM()
	if _, err := s.runRMMSync(ctx, "schedule"); err != nil {
		s.log.Warn("scheduled rmm sync", "err", err)
		return false
	}
	return true
}

// rmmRematch re-matches the covered RMM devices against a newer feed snapshot,
// from the update lists already stored. It makes no RMM request.
func (s *Server) rmmRematch(ctx context.Context) {
	if s.pg == nil {
		return
	}
	n, err := rmm.Rematch(ctx, s.pg, time.Now().UTC())
	if err != nil {
		s.log.Warn("rmm rematch", "err", err)
		return
	}
	if n > 0 {
		s.log.Info("rmm rematch", "devices", n)
	}
}
