package control

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"defendsec/internal/autotask"
	"defendsec/internal/autotask/client"
	"defendsec/internal/secret"
	"defendsec/internal/storepg"
)

// Autotask API (slice 14): Fix this week becomes grouped, idempotent tickets.
//
//	GET  /v1/autotask/status       settings, the credentials' state (no secret), the tracked tickets, the latest runs, whether live is unlocked (viewers)
//	PUT  /v1/autotask/settings     the company and how its tickets look (admins). Mode live needs a dry run with these settings behind it
//	GET  /v1/autotask/picklists    the live Autotask picklists and the company, to fill the settings page (admins: it spends API requests)
//	GET  /v1/autotask/companies    ?q= a name search, to find the company's id (admins)
//	POST /v1/autotask/run          {dryRun?, wait?}: reconcile now (admins). A dry run is the default and changes nothing
//	GET  /v1/autotask/runs         ?limit=: the history, without each run's operations (viewers)
//	GET  /v1/autotask/runs/<id>    one run with the exact tickets and notes it showed or sent (viewers)
//	GET  /v1/autotask/tickets      the tickets DefendSec follows (viewers)
//
// The API user's secret and the integration code are never accepted over the API.
// apid reads them each time it talks to Autotask from the files named in
// DEFENDSEC_AUTOTASK_SECRET_FILE and DEFENDSEC_AUTOTASK_CODE_FILE, so rotating
// one is replacing a file. The user's name and the company id are not secrets and
// live in the settings.
//
// What apid sends to Autotask is limited to the calls listed in
// internal/autotask/client: reads, creating a ticket, creating a note and, only if
// the operator switched auto-complete on, changing a ticket's status.

const (
	// AutotaskInterval is how often a live instance reconciles its tickets.
	AutotaskInterval = 6 * time.Hour
	// AutotaskScheduleCheck is how often the scheduler looks whether a run is due.
	AutotaskScheduleCheck = 30 * time.Minute
	autotaskRunTimeout    = 20 * time.Minute
)

type autotaskCredentials struct {
	Configured bool     `json:"configured"`
	Problem    string   `json:"problem,omitempty"`
	Warnings   []string `json:"warnings"`
}

type autotaskRunner struct {
	mu      sync.Mutex
	running bool
	// open builds the Autotask desk for one run. Nil means: from the environment.
	open func(autotask.Settings) (autotask.Desk, error)
	// zones caches discovered zone URLs by API user.
	zones    map[string]zoneCache
	interval time.Duration
}

type zoneCache struct {
	url string
	at  time.Time
}

// SetAutotaskDesk replaces how the Autotask desk is built (tests, or a deployment
// that keeps its credentials somewhere else).
func (s *Server) SetAutotaskDesk(open func(autotask.Settings) (autotask.Desk, error)) {
	s.atkr.mu.Lock()
	defer s.atkr.mu.Unlock()
	s.atkr.open = open
}

func (s *Server) autotaskFiles() (secretValue, codeValue string, cr autotaskCredentials) {
	cr.Warnings = []string{}
	secFile := strings.TrimSpace(os.Getenv("DEFENDSEC_AUTOTASK_SECRET_FILE"))
	codeFile := strings.TrimSpace(os.Getenv("DEFENDSEC_AUTOTASK_CODE_FILE"))
	if secFile == "" || codeFile == "" {
		cr.Problem = "Autotask credentials are not configured: set DEFENDSEC_AUTOTASK_SECRET_FILE (the API user's secret) and DEFENDSEC_AUTOTASK_CODE_FILE (its integration code), each a file holding the one value, for apid"
		return "", "", cr
	}
	sec, w, err := secret.ReadFile(secFile)
	if err != nil {
		cr.Problem = "DEFENDSEC_AUTOTASK_SECRET_FILE: " + err.Error()
		return "", "", cr
	}
	if w != "" {
		cr.Warnings = append(cr.Warnings, w)
	}
	code, w, err := secret.ReadFile(codeFile)
	if err != nil {
		cr.Problem = "DEFENDSEC_AUTOTASK_CODE_FILE: " + err.Error()
		return "", "", cr
	}
	if w != "" {
		cr.Warnings = append(cr.Warnings, w)
	}
	cr.Configured = true
	return sec, code, cr
}

func (s *Server) autotaskZone(ctx context.Context, set autotask.Settings) (string, error) {
	if set.ZoneURL != "" {
		return set.ZoneURL, nil
	}
	s.atkr.mu.Lock()
	if z, ok := s.atkr.zones[set.APIUser]; ok && time.Since(z.at) < time.Hour {
		s.atkr.mu.Unlock()
		return z.url, nil
	}
	s.atkr.mu.Unlock()
	z, err := client.Discover(ctx, nil, client.ZoneDiscoveryURL, set.APIUser, false)
	if err != nil {
		return "", err
	}
	s.atkr.mu.Lock()
	if s.atkr.zones == nil {
		s.atkr.zones = map[string]zoneCache{}
	}
	s.atkr.zones[set.APIUser] = zoneCache{url: z.URL, at: time.Now()}
	s.atkr.mu.Unlock()
	return z.URL, nil
}

// autotaskDesk builds a client for one run. Its text never holds a value.
func (s *Server) autotaskDesk(ctx context.Context, set autotask.Settings) (autotask.Desk, error) {
	s.atkr.mu.Lock()
	open := s.atkr.open
	s.atkr.mu.Unlock()
	if open != nil {
		return open(set)
	}
	if set.APIUser == "" {
		return nil, errors.New("the Autotask API user's name is not set")
	}
	sec, code, cr := s.autotaskFiles()
	if !cr.Configured {
		return nil, errors.New(cr.Problem)
	}
	zone, err := s.autotaskZone(ctx, set)
	if err != nil {
		return nil, errors.New("could not find the Autotask zone: " + err.Error())
	}
	c, err := client.New(client.Config{BaseURL: zone, UserName: set.APIUser, Secret: sec, IntegrationCode: code})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Server) autotaskCredentialsState(set autotask.Settings) autotaskCredentials {
	s.atkr.mu.Lock()
	open := s.atkr.open
	s.atkr.mu.Unlock()
	if open != nil {
		if _, err := open(set); err != nil {
			return autotaskCredentials{Problem: err.Error(), Warnings: []string{}}
		}
		return autotaskCredentials{Configured: true, Warnings: []string{}}
	}
	_, _, cr := s.autotaskFiles()
	if cr.Configured && set.APIUser == "" {
		cr.Configured = false
		cr.Problem = "the API user's name is not set in the settings"
	}
	return cr
}

// HandleAutotask serves /v1/autotask/...
func (s *Server) HandleAutotask(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/autotask"), "/")
	switch {
	case rest == "status":
		if methodOnly(w, r, http.MethodGet) && s.identityReady(w, r, false) {
			s.autotaskStatus(w, r)
		}
	case rest == "settings":
		if methodOnly(w, r, http.MethodPut) && s.identityReady(w, r, true) {
			s.autotaskSettings(w, r)
		}
	case rest == "picklists":
		if methodOnly(w, r, http.MethodGet) && s.identityReady(w, r, true) {
			s.autotaskPicklists(w, r)
		}
	case rest == "companies":
		if methodOnly(w, r, http.MethodGet) && s.identityReady(w, r, true) {
			s.autotaskCompanies(w, r)
		}
	case rest == "run":
		if methodOnly(w, r, http.MethodPost) && s.identityReady(w, r, true) {
			s.autotaskRun(w, r)
		}
	case rest == "runs":
		if !methodOnly(w, r, http.MethodGet) || !s.identityReady(w, r, false) {
			return
		}
		n := 20
		if v := r.URL.Query().Get("limit"); v != "" {
			var err error
			if n, err = strconv.Atoi(v); err != nil || n < 1 || n > 100 {
				http.Error(w, "limit must be 1 to 100", http.StatusBadRequest)
				return
			}
		}
		list, err := s.pg.ListAutotaskRuns(r.Context(), n)
		if err != nil {
			s.log.Warn("list autotask runs", "err", err)
			http.Error(w, "could not read the history", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"runs": list})
	case strings.HasPrefix(rest, "runs/"):
		if !methodOnly(w, r, http.MethodGet) || !s.identityReady(w, r, false) {
			return
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(rest, "runs/"), 10, 64)
		if err != nil || id < 1 {
			http.Error(w, "bad run id", http.StatusBadRequest)
			return
		}
		run, err := s.pg.GetAutotaskRun(r.Context(), id)
		if errors.Is(err, storepg.ErrAutotaskRunNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.log.Warn("get autotask run", "err", err)
			http.Error(w, "could not read the run", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, run)
	case rest == "tickets":
		if methodOnly(w, r, http.MethodGet) && s.identityReady(w, r, false) {
			list, err := s.pg.AutotaskTicketList(r.Context(), 200)
			if err != nil {
				s.log.Warn("list autotask tickets", "err", err)
				http.Error(w, "could not read the tickets", http.StatusInternalServerError)
				return
			}
			out := make([]map[string]any, 0, len(list))
			for _, t := range list {
				out = append(out, map[string]any{"groupKey": t.GroupKey, "generation": t.Generation, "tag": t.Tag, "ticketId": t.TicketID,
					"ticketNumber": t.TicketNumber, "title": t.Title, "state": t.State, "urgency": t.Urgency, "members": len(t.Members),
					"createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt, "resolvedAt": t.ResolvedAt})
			}
			writeJSON(w, http.StatusOK, map[string]any{"tickets": out})
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) autotaskStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	set, err := s.pg.GetAutotaskSettings(ctx)
	if err != nil {
		s.log.Warn("autotask settings", "err", err)
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	counts, err := s.pg.AutotaskTicketCounts(ctx)
	if err != nil {
		http.Error(w, "could not read the tickets", http.StatusInternalServerError)
		return
	}
	latest, err := s.pg.LatestAutotaskRun(ctx)
	if err != nil {
		http.Error(w, "could not read the runs", http.StatusInternalServerError)
		return
	}
	dry, err := s.pg.LatestAutotaskDryRun(ctx)
	if err != nil {
		http.Error(w, "could not read the runs", http.StatusInternalServerError)
		return
	}
	fp, err := s.pg.LatestGoodDryRunFingerprint(ctx)
	if err != nil {
		http.Error(w, "could not read the runs", http.StatusInternalServerError)
		return
	}
	s.atkr.mu.Lock()
	running := s.atkr.running
	s.atkr.mu.Unlock()
	missing := set.Missing()
	if missing == nil {
		missing = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":      set,
		"credentials":   s.autotaskCredentialsState(set.Settings),
		"missing":       missing,
		"fingerprint":   set.Fingerprint(),
		"liveUnlocked":  fp != "" && fp == set.Fingerprint(),
		"counts":        counts,
		"latestRun":     latest,
		"latestDryRun":  dry,
		"running":       running,
		"intervalHours": s.autotaskInterval().Hours(),
		"scheduled":     strings.ToLower(strings.TrimSpace(os.Getenv("DEFENDSEC_AUTOTASK_SCHEDULE"))) != "off",
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"writeNote": "DefendSec creates tickets and notes in the one Autotask company chosen in the settings, and changes a ticket's status only to complete it when auto-complete is on (it is off by default). " +
			"It never deletes anything and never touches another company. A dry run shows the exact tickets and changes nothing.",
	})
}

func (s *Server) autotaskSettings(w http.ResponseWriter, r *http.Request) {
	cur, err := s.pg.GetAutotaskSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	in := cur.Settings
	if err := decodeStrict(r, &in); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.pg.SetAutotaskSettings(r.Context(), s.actorIdentity(r), in); err != nil {
		if errors.Is(err, autotask.ErrBadSettings) {
			http.Error(w, strings.TrimPrefix(err.Error(), autotask.ErrBadSettings.Error()+": "), http.StatusBadRequest)
			return
		}
		s.log.Warn("set autotask settings", "err", err)
		http.Error(w, "could not save the settings", http.StatusInternalServerError)
		return
	}
	got, _ := s.pg.GetAutotaskSettings(r.Context())
	writeJSON(w, http.StatusOK, got)
}

// pickItem is one picklist entry for the settings page.
type pickItem struct {
	Value     string `json:"value"`
	Label     string `json:"label"`
	IsDefault bool   `json:"isDefault"`
	Parent    string `json:"parent,omitempty"`
}

func picks(f client.Fields, name string) []pickItem {
	out := []pickItem{}
	for _, v := range f.Active(name) {
		out = append(out, pickItem{Value: v.Value, Label: v.Label, IsDefault: v.IsDefault, Parent: v.ParentValue})
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label) })
	return out
}

func (s *Server) autotaskPicklists(w http.ResponseWriter, r *http.Request) {
	set, err := s.pg.GetAutotaskSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	desk, err := s.autotaskDesk(r.Context(), set.Settings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	tf, err := desk.TicketFields(ctx)
	if err != nil {
		s.autotaskFail(w, "the ticket picklists", err)
		return
	}
	nf, err := desk.NoteFields(ctx)
	if err != nil {
		s.autotaskFail(w, "the note picklists", err)
		return
	}
	out := map[string]any{
		"queues": picks(tf, "queueID"), "statuses": picks(tf, "status"), "priorities": picks(tf, "priority"), "sources": picks(tf, "source"),
		"issueTypes": picks(tf, "issueType"), "subIssueTypes": picks(tf, "subIssueType"),
		"noteTypes": picks(nf, "noteType"), "notePublish": picks(nf, "publish"),
		"titleLength": tf["title"].Length, "descriptionLength": tf["description"].Length,
		"requests": desk.Requests(),
	}
	if set.CompanyID > 0 {
		co, err := desk.Company(ctx, set.CompanyID)
		if err != nil {
			out["companyProblem"] = errString(err)
		} else {
			out["company"] = map[string]any{"id": co.ID, "name": co.CompanyName, "active": co.IsActive}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func errString(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.Error()
	}
	return "unexpected failure"
}

func (s *Server) autotaskFail(w http.ResponseWriter, what string, err error) {
	s.log.Warn("autotask read", "what", what, "err", errString(err))
	status := http.StatusBadGateway
	if client.IsAuth(err) {
		status = http.StatusForbidden
	}
	http.Error(w, "Autotask could not be read ("+what+"): "+errString(err), status)
}

func (s *Server) autotaskCompanies(w http.ResponseWriter, r *http.Request) {
	set, err := s.pg.GetAutotaskSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	desk, err := s.autotaskDesk(r.Context(), set.Settings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	d, ok := desk.(interface {
		SearchCompanies(context.Context, string) ([]client.Company, error)
	})
	if !ok {
		http.Error(w, "company search is not available", http.StatusNotImplemented)
		return
	}
	list, err := d.SearchCompanies(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		var ce *client.Error
		if errors.As(err, &ce) && ce.Kind == client.KindRejected && ce.Status == 0 {
			http.Error(w, ce.Error(), http.StatusBadRequest)
			return
		}
		s.autotaskFail(w, "the company search", err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, map[string]any{"id": c.ID, "name": c.CompanyName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"companies": out})
}

func (s *Server) autotaskInterval() time.Duration {
	s.atkr.mu.Lock()
	defer s.atkr.mu.Unlock()
	if s.atkr.interval > 0 {
		return s.atkr.interval
	}
	if v := strings.TrimSpace(os.Getenv("DEFENDSEC_AUTOTASK_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Hour && d <= 24*time.Hour {
			return d
		}
	}
	return AutotaskInterval
}

func (s *Server) claimAutotask() bool {
	s.atkr.mu.Lock()
	defer s.atkr.mu.Unlock()
	if s.atkr.running {
		return false
	}
	s.atkr.running = true
	return true
}

func (s *Server) releaseAutotask() {
	s.atkr.mu.Lock()
	s.atkr.running = false
	s.atkr.mu.Unlock()
}

// runAutotask reconciles once and stores the run; the caller holds the claim.
// A dry run needs no credentials (it shows the tickets, marked unverified); a
// live run does, and refuses without a dry run behind it.
func (s *Server) runAutotask(ctx context.Context, trigger string, dryRun bool) (storepg.AutotaskRun, error) {
	started := time.Now().UTC()
	set, err := s.pg.GetAutotaskSettings(ctx)
	if err != nil {
		return storepg.AutotaskRun{}, err
	}
	findings, err := s.pg.AutotaskCandidates(ctx)
	if err != nil {
		return storepg.AutotaskRun{}, err
	}
	fp, err := s.pg.LatestGoodDryRunFingerprint(ctx)
	if err != nil {
		return storepg.AutotaskRun{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, autotaskRunTimeout)
	defer cancel()

	mode := autotask.ModeLive
	if dryRun {
		mode = autotask.ModeDryRun
	}
	eng := &autotask.Engine{Store: s.pg.AutotaskPort(), Actor: trigger, DryRunFingerprint: fp}
	desk, derr := s.autotaskDesk(ctx, set.Settings)
	var res autotask.Result
	switch {
	case derr == nil:
		eng.Desk = desk
		res, err = eng.Run(ctx, set.Settings, findings, mode)
	case dryRun:
		// No credentials: the tickets are still shown, marked unverified.
		res, err = eng.Run(ctx, set.Settings, findings, mode)
		if res.UnverifiedWhy != "" {
			res.UnverifiedWhy = "Autotask was not read: " + derr.Error() + ". The tickets below are exactly what would be sent."
		}
	default:
		res = autotask.Result{Mode: mode, Problems: []string{derr.Error()}, Ops: []autotask.Op{}, Fingerprint: set.Fingerprint()}
	}
	if err != nil {
		return storepg.AutotaskRun{}, err
	}
	run, err := s.pg.RecordAutotaskRun(ctx, trigger, started, res)
	if err != nil {
		return run, err
	}
	s.log.Info("autotask run", "mode", run.Mode, "status", run.Status, "created", run.Created, "noted", run.Noted, "completed", run.Completed,
		"failed", run.Failed, "deferred", run.Deferred, "requests", run.Requests)
	return run, nil
}

func (s *Server) autotaskRun(w http.ResponseWriter, r *http.Request) {
	req := struct {
		DryRun *bool `json:"dryRun"`
		Wait   bool  `json:"wait"`
	}{}
	if r.ContentLength != 0 {
		if err := decodeStrict(r, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	// A dry run is what you get unless you ask for live in so many words.
	dry := req.DryRun == nil || *req.DryRun
	set, err := s.pg.GetAutotaskSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	if !dry && set.Mode != autotask.ModeLive {
		http.Error(w, "the settings are in dry-run mode: save mode live first (it needs a dry run with these settings behind it)", http.StatusConflict)
		return
	}
	if !s.claimAutotask() {
		http.Error(w, "a run is already in progress", http.StatusConflict)
		return
	}
	actor := s.actorIdentity(r)
	s.audit(actor, "autotask_sync", "", map[string]any{"dryRun": dry, "wait": req.Wait, "companyId": set.CompanyID})
	if req.Wait {
		defer s.releaseAutotask()
		run, err := s.runAutotask(r.Context(), "manual:"+actor, dry)
		if err != nil {
			s.log.Warn("autotask run", "err", err)
			http.Error(w, "the run failed: "+errString(err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	go func() {
		defer s.releaseAutotask()
		if _, err := s.runAutotask(context.Background(), "manual:"+actor, dry); err != nil {
			s.log.Warn("autotask run", "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "dryRun": dry})
}

// RunAutotaskSchedule reconciles the tickets every interval (6 hours unless
// DEFENDSEC_AUTOTASK_INTERVAL says otherwise), checking every `every` whether a
// run is due. It does something only for an instance whose settings are in live
// mode, which needs a dry run behind it. A dry-run instance is never touched by
// the schedule: showing the tickets is something a person asks for.
func (s *Server) RunAutotaskSchedule(ctx context.Context, every time.Duration) {
	if s.pg == nil {
		return
	}
	timer := time.NewTimer(6 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.autotaskScheduleOnce(ctx)
		timer.Reset(every)
	}
}

// autotaskScheduleOnce runs one pass of the schedule and reports whether it ran.
func (s *Server) autotaskScheduleOnce(ctx context.Context) bool {
	set, err := s.pg.GetAutotaskSettings(ctx)
	if err != nil || set.Mode != autotask.ModeLive {
		return false
	}
	if last, err := s.pg.LatestAutotaskRunOf(ctx, autotask.ModeLive); err == nil && last != nil && time.Since(last.FinishedAt) < s.autotaskInterval() {
		return false
	}
	if _, err := s.autotaskDesk(ctx, set.Settings); err != nil {
		s.log.Warn("autotask schedule: not configured", "err", errString(err))
		return false
	}
	if !s.claimAutotask() {
		return false
	}
	defer s.releaseAutotask()
	if _, err := s.runAutotask(ctx, "schedule", false); err != nil {
		s.log.Warn("scheduled autotask run", "err", errString(err))
		return false
	}
	return true
}
