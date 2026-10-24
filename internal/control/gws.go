package control

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"defendsec/internal/gws"
	"defendsec/internal/gws/google"
	"defendsec/internal/idposture"
	"defendsec/internal/secret"
	"defendsec/internal/storepg"
)

// Google Workspace identity posture API (slice 13), beside Microsoft 365's:
//
//	GET  /v1/identity/google/status    what is configured, the key's identity (no secret), the counts, the latest run, what is not assessed (viewers)
//	PUT  /v1/identity/google/settings  the administrator to act as and how the domain is judged (admins)
//	POST /v1/identity/google/sync      {wait?}: read the domain now (admins). 202 and a background read, or 200 with the run
//
// Findings and runs are the shared GET /v1/identity/findings and /runs with
// ?provider=google.
//
// The service account's key is never accepted over the API. apid reads it from the
// JSON file named in DEFENDSEC_GWS_KEY_FILE each time it reads, so rotating the key
// is replacing a file. The administrator's address and the Gmail scope are not
// secrets and live in the settings.
//
// Everything the collector does against Google is a GET, apart from the token
// request. No route changes anything in a Workspace account.

const (
	// GWSInterval is how often the domain is read.
	GWSInterval = 6 * time.Hour
	// GWSScheduleCheck is how often the scheduler looks whether a read is due.
	GWSScheduleCheck = 30 * time.Minute
	gwsSyncTimeout   = 30 * time.Minute
)

// gwsCredentials describes the configured service account for the status API,
// without a secret in it.
type gwsCredentials struct {
	Configured bool `json:"configured"`
	// ClientEmail, ClientID, KeyID and ProjectID identify the service account: the
	// operator matches ClientID with the Admin console's domain-wide delegation entry
	// and KeyID with the key the Cloud console lists.
	ClientEmail string   `json:"clientEmail,omitempty"`
	ClientID    string   `json:"clientId,omitempty"`
	KeyID       string   `json:"keyId,omitempty"`
	ProjectID   string   `json:"projectId,omitempty"`
	Problem     string   `json:"problem,omitempty"`
	Warnings    []string `json:"warnings"`
}

type gwsRunner struct {
	mu      sync.Mutex
	running bool
	// open builds the source for one read. Nil means: from the environment.
	open func(storepg.GWSSettings) (gws.Source, error)
	// interval is how often the schedule reads the domain (0 = GWSInterval).
	interval time.Duration
}

// SetGWSSource replaces how the Google Workspace source is built (tests, or a
// deployment that keeps its key somewhere else).
func (s *Server) SetGWSSource(open func(storepg.GWSSettings) (gws.Source, error)) {
	s.gwsr.mu.Lock()
	defer s.gwsr.mu.Unlock()
	s.gwsr.open = open
}

// gwsFromEnv builds a Google-backed source from the settings and the key file. It
// says in plain words what is wrong and never includes a value.
func gwsFromEnv(set storepg.GWSSettings) (*gws.GoogleSource, gwsCredentials, error) {
	cr := gwsCredentials{Warnings: []string{}}
	fail := func(msg string) (*gws.GoogleSource, gwsCredentials, error) {
		cr.Problem = msg
		return nil, cr, errors.New(msg)
	}
	keyFile := strings.TrimSpace(os.Getenv("DEFENDSEC_GWS_KEY_FILE"))
	if keyFile == "" {
		return fail("Google Workspace credentials are not configured: set DEFENDSEC_GWS_KEY_FILE for apid to the service account's JSON key file (0600)")
	}
	data, w, err := secret.ReadJSONFile(keyFile)
	if err != nil {
		return fail("DEFENDSEC_GWS_KEY_FILE: " + err.Error())
	}
	if w != "" {
		cr.Warnings = append(cr.Warnings, w)
	}
	acct, err := google.ParseServiceAccountJSON(data)
	if err != nil {
		return fail("DEFENDSEC_GWS_KEY_FILE: " + err.Error())
	}
	cr.ClientEmail, cr.ClientID, cr.KeyID, cr.ProjectID = acct.Email(), acct.ClientID(), acct.KeyID(), acct.ProjectID()
	if set.AdminEmail == "" {
		return fail("no administrator is set: enter the email address of a super administrator of the domain in the identity settings")
	}
	c, err := google.New(google.Config{Account: acct, AdminEmail: set.AdminEmail, GmailScope: set.GmailScopeURL()})
	if err != nil {
		return fail("Google Workspace client: " + err.Error())
	}
	cr.Configured = true
	cr.Warnings = append(cr.Warnings, "a service account key is a file that lets whoever holds it act as any user of the domain within the delegated scopes: keep it 0600, rotate it, and delete the key in the Cloud console if the server is ever in doubt")
	return gws.NewGoogleSource(c), cr, nil
}

func (s *Server) gwsSource(set storepg.GWSSettings) (gws.Source, error) {
	s.gwsr.mu.Lock()
	open := s.gwsr.open
	s.gwsr.mu.Unlock()
	if open != nil {
		return open(set)
	}
	src, _, err := gwsFromEnv(set)
	if err != nil {
		return nil, err
	}
	return src, nil
}

func (s *Server) gwsCredentialsState(set storepg.GWSSettings) gwsCredentials {
	s.gwsr.mu.Lock()
	open := s.gwsr.open
	s.gwsr.mu.Unlock()
	if open != nil {
		if _, err := open(set); err != nil {
			return gwsCredentials{Problem: err.Error(), Warnings: []string{}}
		}
		return gwsCredentials{Configured: true, Warnings: []string{}}
	}
	_, cr, _ := gwsFromEnv(set)
	return cr
}

func (s *Server) gwsStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	set, err := s.pg.GetGWSSettings(ctx)
	if err != nil {
		s.log.Warn("identity settings", "provider", gws.Provider, "err", err)
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	sum, err := s.pg.IdentityProviderSummary(ctx, gws.Provider)
	if err != nil {
		s.log.Warn("identity summary", "provider", gws.Provider, "err", err)
		http.Error(w, "could not read the identity state", http.StatusInternalServerError)
		return
	}
	run, err := s.pg.LatestIdentityRun(ctx, gws.Provider)
	if err != nil {
		s.log.Warn("identity latest run", "provider", gws.Provider, "err", err)
		http.Error(w, "could not read the identity state", http.StatusInternalServerError)
		return
	}
	notAssessed := gws.StandingNotAssessed
	if run != nil && len(run.NotAssessed) > 0 {
		notAssessed = run.NotAssessed
	}
	s.gwsr.mu.Lock()
	running := s.gwsr.running
	s.gwsr.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":      gws.Provider,
		"settings":      set,
		"credentials":   s.gwsCredentialsState(set),
		"summary":       sum,
		"latestRun":     run,
		"running":       running,
		"intervalHours": s.gwsInterval().Hours(),
		"scheduled":     strings.ToLower(strings.TrimSpace(os.Getenv("DEFENDSEC_GWS_SCHEDULE"))) != "off",
		"notAssessed":   notAssessed,
		"permissions":   gws.Permissions,
		"checkLabels":   gws.CheckLabels,
		"checkOrder":    gws.CheckOrder,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"readOnlyNote":  "DefendSec only ever reads from Google (GET requests, apart from the token request). It reads who is enrolled in 2-Step Verification, who is a super administrator, and each mailbox's auto-forwarding setting and filter definitions. It never reads a message, and it never changes anything in the domain.",
	})
}

func (s *Server) gwsSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AdminEmail     *string   `json:"adminEmail"`
		GmailScope     *string   `json:"gmailScope"`
		SuperAdminMax  *int      `json:"superAdminMax"`
		TrustedDomains *[]string `json:"trustedDomains"`
		FinanceTerms   *[]string `json:"financeTerms"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	cur, err := s.pg.GetGWSSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	if req.AdminEmail != nil {
		cur.AdminEmail = *req.AdminEmail
	}
	if req.GmailScope != nil {
		cur.GmailScope = *req.GmailScope
	}
	if req.SuperAdminMax != nil {
		cur.SuperAdminMax = *req.SuperAdminMax
	}
	if req.TrustedDomains != nil {
		cur.TrustedDomains = *req.TrustedDomains
	}
	if req.FinanceTerms != nil {
		cur.FinanceTerms = *req.FinanceTerms
	}
	if err := s.pg.SetGWSSettings(r.Context(), s.actorIdentity(r), cur); err != nil {
		if errors.Is(err, storepg.ErrBadIdentitySettings) {
			http.Error(w, strings.TrimPrefix(err.Error(), storepg.ErrBadIdentitySettings.Error()+": "), http.StatusBadRequest)
			return
		}
		s.log.Warn("set identity settings", "provider", gws.Provider, "err", err)
		http.Error(w, "could not save the settings", http.StatusInternalServerError)
		return
	}
	// The ledger entry (identity_settings_changed) is written by SetGWSSettings in the same transaction.
	got, _ := s.pg.GetGWSSettings(r.Context())
	writeJSON(w, http.StatusOK, got)
}

func (s *Server) gwsInterval() time.Duration {
	s.gwsr.mu.Lock()
	defer s.gwsr.mu.Unlock()
	if s.gwsr.interval > 0 {
		return s.gwsr.interval
	}
	if v := strings.TrimSpace(os.Getenv("DEFENDSEC_GWS_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Hour && d <= 24*time.Hour {
			return d
		}
	}
	return GWSInterval
}

func (s *Server) claimGWS() bool {
	s.gwsr.mu.Lock()
	defer s.gwsr.mu.Unlock()
	if s.gwsr.running {
		return false
	}
	s.gwsr.running = true
	return true
}

func (s *Server) releaseGWS() {
	s.gwsr.mu.Lock()
	s.gwsr.running = false
	s.gwsr.mu.Unlock()
}

// runGWSSync reads the domain once and stores the result; the caller holds the claim.
func (s *Server) runGWSSync(ctx context.Context, trigger string) (storepg.IdentityRun, error) {
	set, err := s.pg.GetGWSSettings(ctx)
	if err != nil {
		return storepg.IdentityRun{}, err
	}
	if !set.Configured {
		return storepg.IdentityRun{}, errors.New("no administrator is set")
	}
	src, err := s.gwsSource(set)
	if err != nil {
		return storepg.IdentityRun{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, gwsSyncTimeout)
	defer cancel()
	rep := gws.Collect(ctx, src, gws.Options{
		SuperAdminMax: set.SuperAdminMax, TrustedDomains: set.TrustedDomains, ExtraFinanceTerms: set.FinanceTerms,
	})
	run, err := s.pg.RecordIdentityRun(ctx, gws.Provider, domainOf(set.AdminEmail), trigger, rep)
	if err != nil {
		return run, err
	}
	s.log.Info("identity read", "provider", gws.Provider, "status", run.Status, "open", run.Open, "opened", run.Opened, "resolved", run.Resolved, "requests", run.Requests)
	return run, nil
}

// domainOf is the domain of an address: what a Google run records as its "tenant".
func domainOf(addr string) string { return idposture.DomainOf(addr) }

func (s *Server) gwsSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Wait bool `json:"wait"`
	}
	if r.ContentLength != 0 {
		if err := decodeStrict(r, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	set, err := s.pg.GetGWSSettings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	if !set.Configured {
		http.Error(w, "no administrator is set: enter the administrator's email address first (PUT /v1/identity/google/settings)", http.StatusBadRequest)
		return
	}
	if _, err := s.gwsSource(set); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !s.claimGWS() {
		http.Error(w, "a read of the domain is already running", http.StatusConflict)
		return
	}
	actor := s.actorIdentity(r)
	s.audit(actor, "identity_sync", "", map[string]any{"provider": gws.Provider, "adminEmail": set.AdminEmail, "wait": req.Wait})
	if req.Wait {
		defer s.releaseGWS()
		run, err := s.runGWSSync(r.Context(), "manual:"+actor)
		if err != nil {
			s.log.Warn("identity sync", "provider", gws.Provider, "err", err)
			http.Error(w, "the read failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	go func() {
		defer s.releaseGWS()
		if _, err := s.runGWSSync(context.Background(), "manual:"+actor); err != nil {
			s.log.Warn("identity sync", "provider", gws.Provider, "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// RunGWSSchedule reads the domain every interval (6 hours unless
// DEFENDSEC_GWS_INTERVAL says otherwise), checking every `every` whether a read is
// due. With no administrator set, or no key, it does nothing. It is ordinary reading
// of the one domain the operator set: it never reaches another.
func (s *Server) RunGWSSchedule(ctx context.Context, every time.Duration) {
	if s.pg == nil {
		return
	}
	// Offset from the Microsoft 365 schedule so the two do not start together.
	timer := time.NewTimer(6 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.gwsScheduleOnce(ctx)
		timer.Reset(every)
	}
}

// gwsScheduleOnce runs one pass of the schedule and reports whether it read.
func (s *Server) gwsScheduleOnce(ctx context.Context) bool {
	set, err := s.pg.GetGWSSettings(ctx)
	if err != nil || !set.Configured {
		return false
	}
	if last, err := s.pg.LatestIdentityRun(ctx, gws.Provider); err == nil && last != nil &&
		last.Tenant == domainOf(set.AdminEmail) && time.Since(last.FinishedAt) < s.gwsInterval() {
		return false
	}
	if _, err := s.gwsSource(set); err != nil {
		s.log.Warn("identity schedule: not configured", "provider", gws.Provider, "err", err)
		return false
	}
	if !s.claimGWS() {
		return false
	}
	defer s.releaseGWS()
	if _, err := s.runGWSSync(ctx, "schedule"); err != nil {
		s.log.Warn("scheduled identity read", "provider", gws.Provider, "err", err)
		return false
	}
	return true
}
