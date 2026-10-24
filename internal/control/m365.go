package control

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"defendsec/internal/m365"
	"defendsec/internal/m365/graph"
	"defendsec/internal/secret"
	"defendsec/internal/storepg"
)

// Identity posture API (slice 12: Microsoft 365; Google Workspace joins it in
// slice 13):
//
//	GET  /v1/identity/status        what is configured, the credentials' state (no secret), the counts, the latest run, what is not assessed (viewers)
//	PUT  /v1/identity/m365/settings the tenant and how it is judged (admins)
//	POST /v1/identity/m365/sync     {wait?}: read the tenant now (admins). 202 and a background read, or 200 with the run
//	GET  /v1/identity/findings      ?resolved=1&check=: the findings (viewers)
//	GET  /v1/identity/runs?limit=   the history of reads (viewers)
//
// The certificate or client secret is never accepted over the API. apid reads
// it from the file named in DEFENDSEC_M365_CERT_FILE (a PEM file with the RSA
// private key and its certificate; preferred) or DEFENDSEC_M365_SECRET_FILE,
// each time it reads, so rotating a credential is replacing a file. The tenant
// and application IDs are not secrets and live in the settings.
//
// Everything the collector does against Microsoft is a GET, apart from the
// token request. No route changes anything in a tenant.

const (
	// M365Interval is how often the tenant is read.
	M365Interval = 6 * time.Hour
	// M365ScheduleCheck is how often the scheduler looks whether a read is due.
	M365ScheduleCheck = 30 * time.Minute
	m365SyncTimeout   = 30 * time.Minute
)

// m365Credentials describes the configured credentials for the status API,
// without a secret in it.
type m365Credentials struct {
	Configured bool `json:"configured"`
	// Method is "certificate" or "secret".
	Method string `json:"method,omitempty"`
	// Thumbprint (SHA-256, hex) and NotAfter identify a certificate credential: the
	// thumbprint is what the Entra portal shows, so the operator can match them.
	Thumbprint string     `json:"thumbprint,omitempty"`
	NotAfter   *time.Time `json:"notAfter,omitempty"`
	Problem    string     `json:"problem,omitempty"`
	Warnings   []string   `json:"warnings"`
}

type m365Runner struct {
	mu      sync.Mutex
	running bool
	// open builds the source for one read. Nil means: from the environment.
	open func(storepg.M365Settings) (m365.Source, error)
	// interval is how often the schedule reads the tenant (0 = M365Interval).
	interval time.Duration
}

// SetM365Source replaces how the Microsoft 365 source is built (tests, or a
// deployment that keeps its credentials somewhere else).
func (s *Server) SetM365Source(open func(storepg.M365Settings) (m365.Source, error)) {
	s.m365r.mu.Lock()
	defer s.m365r.mu.Unlock()
	s.m365r.open = open
}

// m365FromEnv builds a Graph-backed source from the settings and the credential
// files. It says in plain words what is wrong and never includes a value.
func m365FromEnv(set storepg.M365Settings) (*m365.GraphSource, m365Credentials, error) {
	cr := m365Credentials{Warnings: []string{}}
	fail := func(msg string) (*m365.GraphSource, m365Credentials, error) {
		cr.Problem = msg
		return nil, cr, errors.New(msg)
	}
	certFile := strings.TrimSpace(os.Getenv("DEFENDSEC_M365_CERT_FILE"))
	secFile := strings.TrimSpace(os.Getenv("DEFENDSEC_M365_SECRET_FILE"))
	if certFile == "" && secFile == "" {
		return fail("Microsoft 365 credentials are not configured: set DEFENDSEC_M365_CERT_FILE (a PEM file with the certificate and its RSA private key, preferred) or DEFENDSEC_M365_SECRET_FILE for apid")
	}
	cloud, err := graph.ParseCloud(set.Cloud)
	if err != nil {
		return fail(err.Error())
	}
	cfg := graph.Config{TenantID: set.TenantID, ClientID: set.ClientID, Cloud: cloud}
	if certFile != "" {
		data, w, err := secret.ReadPEMFile(certFile)
		if err != nil {
			return fail("DEFENDSEC_M365_CERT_FILE: " + err.Error())
		}
		if w != "" {
			cr.Warnings = append(cr.Warnings, w)
		}
		cert, err := graph.ParseCertificatePEM(data)
		if err != nil {
			return fail("DEFENDSEC_M365_CERT_FILE: " + err.Error())
		}
		cfg.Cert = cert
		cr.Method, cr.Thumbprint = "certificate", cert.Thumbprint()
		if na := cert.NotAfter(); !na.IsZero() {
			na = na.UTC()
			cr.NotAfter = &na
			if time.Until(na) < 0 {
				return fail("the certificate in DEFENDSEC_M365_CERT_FILE has expired (" + na.Format("2006-01-02") + "): create a new one and upload it to the app registration")
			}
			if time.Until(na) < 30*24*time.Hour {
				cr.Warnings = append(cr.Warnings, "the certificate expires on "+na.Format("2006-01-02")+": renew it before then or reads will stop")
			}
		}
		if secFile != "" {
			cr.Warnings = append(cr.Warnings, "both a certificate and a client secret are configured; the certificate is used")
		}
	} else {
		sec, w, err := secret.ReadFile(secFile)
		if err != nil {
			return fail("DEFENDSEC_M365_SECRET_FILE: " + err.Error())
		}
		if w != "" {
			cr.Warnings = append(cr.Warnings, w)
		}
		cfg.Secret = sec
		cr.Method = "secret"
		cr.Warnings = append(cr.Warnings, "a client secret works but a certificate is safer: a secret can be copied and replayed from anywhere, a private key stays in its file")
	}
	if set.TenantID == "" || set.ClientID == "" {
		return fail("no tenant is set: enter the tenant ID and the application (client) ID in the identity settings")
	}
	c, err := graph.New(cfg)
	if err != nil {
		return fail("Microsoft 365 client: " + err.Error())
	}
	cr.Configured = true
	return m365.NewGraphSource(c), cr, nil
}

func (s *Server) m365Source(set storepg.M365Settings) (m365.Source, error) {
	s.m365r.mu.Lock()
	open := s.m365r.open
	s.m365r.mu.Unlock()
	if open != nil {
		return open(set)
	}
	src, _, err := m365FromEnv(set)
	if err != nil {
		return nil, err
	}
	return src, nil
}

func (s *Server) m365CredentialsState(set storepg.M365Settings) m365Credentials {
	s.m365r.mu.Lock()
	open := s.m365r.open
	s.m365r.mu.Unlock()
	if open != nil {
		if _, err := open(set); err != nil {
			return m365Credentials{Problem: err.Error(), Warnings: []string{}}
		}
		return m365Credentials{Configured: true, Method: "certificate", Warnings: []string{}}
	}
	_, cr, _ := m365FromEnv(set)
	return cr
}

func (s *Server) identityReady(w http.ResponseWriter, r *http.Request, write bool) bool {
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

func methodOnly(w http.ResponseWriter, r *http.Request, m string) bool {
	if r.Method != m {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// HandleIdentity serves /v1/identity/...
func (s *Server) HandleIdentity(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/identity"), "/")
	switch rest {
	case "status":
		if methodOnly(w, r, http.MethodGet) && s.identityReady(w, r, false) {
			s.identityStatus(w, r)
		}
	case "m365/settings":
		if methodOnly(w, r, http.MethodPut) && s.identityReady(w, r, true) {
			s.m365Settings(w, r)
		}
	case "m365/sync":
		if methodOnly(w, r, http.MethodPost) && s.identityReady(w, r, true) {
			s.m365Sync(w, r)
		}
	case "findings":
		if methodOnly(w, r, http.MethodGet) && s.identityReady(w, r, false) {
			s.identityFindings(w, r)
		}
	case "runs":
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
		list, err := s.pg.ListIdentityRuns(r.Context(), m365.Provider, n)
		if err != nil {
			s.log.Warn("list identity runs", "err", err)
			http.Error(w, "could not read the history", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"runs": list})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) identityStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	set, err := s.pg.GetM365Settings(ctx)
	if err != nil {
		s.log.Warn("identity settings", "err", err)
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	sum, err := s.pg.IdentityExposureSummary(ctx)
	if err != nil {
		s.log.Warn("identity summary", "err", err)
		http.Error(w, "could not read the identity state", http.StatusInternalServerError)
		return
	}
	run, err := s.pg.LatestIdentityRun(ctx, m365.Provider)
	if err != nil {
		s.log.Warn("identity latest run", "err", err)
		http.Error(w, "could not read the identity state", http.StatusInternalServerError)
		return
	}
	notAssessed := m365.StandingNotAssessed
	if run != nil && len(run.NotAssessed) > 0 {
		notAssessed = run.NotAssessed
	}
	s.m365r.mu.Lock()
	running := s.m365r.running
	s.m365r.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":      m365.Provider,
		"settings":      set,
		"credentials":   s.m365CredentialsState(set),
		"summary":       sum,
		"latestRun":     run,
		"running":       running,
		"intervalHours": s.m365Interval().Hours(),
		"scheduled":     strings.ToLower(strings.TrimSpace(os.Getenv("DEFENDSEC_M365_SCHEDULE"))) != "off",
		"notAssessed":   notAssessed,
		"permissions":   m365.Permissions,
		"checkLabels":   m365.CheckLabels,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"readOnlyNote":  "DefendSec only ever reads from Microsoft Graph (GET requests, apart from the token request). It reads who has registered MFA, which policies block legacy sign-in, who holds an administrator role and the definitions of inbox rules. It never reads a message, and it never changes anything in the tenant.",
	})
}

func (s *Server) m365Settings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID       *string   `json:"tenantId"`
		ClientID       *string   `json:"clientId"`
		Cloud          *string   `json:"cloud"`
		GlobalAdminMax *int      `json:"globalAdminMax"`
		TrustedDomains *[]string `json:"trustedDomains"`
		FinanceTerms   *[]string `json:"financeTerms"`
		ResolveFolders *bool     `json:"resolveFolders"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	cur, err := s.pg.GetM365Settings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	if req.TenantID != nil {
		cur.TenantID = *req.TenantID
	}
	if req.ClientID != nil {
		cur.ClientID = *req.ClientID
	}
	if req.Cloud != nil {
		cur.Cloud = *req.Cloud
	}
	if req.GlobalAdminMax != nil {
		cur.GlobalAdminMax = *req.GlobalAdminMax
	}
	if req.TrustedDomains != nil {
		cur.TrustedDomains = *req.TrustedDomains
	}
	if req.FinanceTerms != nil {
		cur.FinanceTerms = *req.FinanceTerms
	}
	if req.ResolveFolders != nil {
		cur.ResolveFolders = *req.ResolveFolders
	}
	if err := s.pg.SetM365Settings(r.Context(), s.actorIdentity(r), cur); err != nil {
		if errors.Is(err, storepg.ErrBadIdentitySettings) {
			http.Error(w, strings.TrimPrefix(err.Error(), storepg.ErrBadIdentitySettings.Error()+": "), http.StatusBadRequest)
			return
		}
		s.log.Warn("set identity settings", "err", err)
		http.Error(w, "could not save the settings", http.StatusInternalServerError)
		return
	}
	// The ledger entry (identity_settings_changed) is written by SetM365Settings in the same transaction.
	got, _ := s.pg.GetM365Settings(r.Context())
	writeJSON(w, http.StatusOK, got)
}

func (s *Server) identityFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	flt := storepg.IdentityFindingFilter{Provider: m365.Provider, Resolved: q.Get("resolved") == "1"}
	if c := q.Get("check"); c != "" {
		if _, ok := m365.CheckLabels[c]; !ok {
			http.Error(w, "unknown check", http.StatusBadRequest)
			return
		}
		flt.Check = c
	}
	list, err := s.pg.ListIdentityFindings(r.Context(), flt)
	if err != nil {
		s.log.Warn("list identity findings", "err", err)
		http.Error(w, "could not read the findings", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": list})
}

func (s *Server) m365Interval() time.Duration {
	s.m365r.mu.Lock()
	defer s.m365r.mu.Unlock()
	if s.m365r.interval > 0 {
		return s.m365r.interval
	}
	if v := strings.TrimSpace(os.Getenv("DEFENDSEC_M365_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Hour && d <= 24*time.Hour {
			return d
		}
	}
	return M365Interval
}

func (s *Server) claimM365() bool {
	s.m365r.mu.Lock()
	defer s.m365r.mu.Unlock()
	if s.m365r.running {
		return false
	}
	s.m365r.running = true
	return true
}

func (s *Server) releaseM365() {
	s.m365r.mu.Lock()
	s.m365r.running = false
	s.m365r.mu.Unlock()
}

// runM365Sync reads the tenant once and stores the result; the caller holds the claim.
func (s *Server) runM365Sync(ctx context.Context, trigger string) (storepg.IdentityRun, error) {
	set, err := s.pg.GetM365Settings(ctx)
	if err != nil {
		return storepg.IdentityRun{}, err
	}
	if !set.Configured {
		return storepg.IdentityRun{}, errors.New("no tenant is set")
	}
	src, err := s.m365Source(set)
	if err != nil {
		return storepg.IdentityRun{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, m365SyncTimeout)
	defer cancel()
	rep := m365.Collect(ctx, src, m365.Options{
		GlobalAdminMax: set.GlobalAdminMax, TrustedDomains: set.TrustedDomains, ExtraFinanceTerms: set.FinanceTerms,
		ResolveFolders: set.ResolveFolders,
	})
	run, err := s.pg.RecordIdentityRun(ctx, m365.Provider, set.TenantID, trigger, rep)
	if err != nil {
		return run, err
	}
	s.log.Info("identity read", "provider", m365.Provider, "status", run.Status, "open", run.Open, "opened", run.Opened, "resolved", run.Resolved, "requests", run.Requests)
	return run, nil
}

func (s *Server) m365Sync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Wait bool `json:"wait"`
	}
	if r.ContentLength != 0 {
		if err := decodeStrict(r, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	set, err := s.pg.GetM365Settings(r.Context())
	if err != nil {
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	if !set.Configured {
		http.Error(w, "no tenant is set: enter the tenant ID and the application ID first (PUT /v1/identity/m365/settings)", http.StatusBadRequest)
		return
	}
	if _, err := s.m365Source(set); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !s.claimM365() {
		http.Error(w, "a read of the tenant is already running", http.StatusConflict)
		return
	}
	actor := s.actorIdentity(r)
	s.audit(actor, "identity_sync", "", map[string]any{"provider": m365.Provider, "tenantId": set.TenantID, "wait": req.Wait})
	if req.Wait {
		defer s.releaseM365()
		run, err := s.runM365Sync(r.Context(), "manual:"+actor)
		if err != nil {
			s.log.Warn("identity sync", "err", err)
			http.Error(w, "the read failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	go func() {
		defer s.releaseM365()
		if _, err := s.runM365Sync(context.Background(), "manual:"+actor); err != nil {
			s.log.Warn("identity sync", "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// RunM365Schedule reads the tenant every interval (6 hours unless
// DEFENDSEC_M365_INTERVAL says otherwise), checking every `every` whether a read
// is due. With no tenant set, or no credentials, it does nothing. It is ordinary
// reading of the one tenant the operator set: it never reaches another.
func (s *Server) RunM365Schedule(ctx context.Context, every time.Duration) {
	if s.pg == nil {
		return
	}
	timer := time.NewTimer(4 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.m365ScheduleOnce(ctx)
		timer.Reset(every)
	}
}

// m365ScheduleOnce runs one pass of the schedule and reports whether it read.
func (s *Server) m365ScheduleOnce(ctx context.Context) bool {
	set, err := s.pg.GetM365Settings(ctx)
	if err != nil || !set.Configured {
		return false
	}
	if last, err := s.pg.LatestIdentityRun(ctx, m365.Provider); err == nil && last != nil &&
		last.Tenant == set.TenantID && time.Since(last.FinishedAt) < s.m365Interval() {
		return false
	}
	if _, err := s.m365Source(set); err != nil {
		s.log.Warn("identity schedule: not configured", "err", err)
		return false
	}
	if !s.claimM365() {
		return false
	}
	defer s.releaseM365()
	if _, err := s.runM365Sync(ctx, "schedule"); err != nil {
		s.log.Warn("scheduled identity read", "err", err)
		return false
	}
	return true
}
