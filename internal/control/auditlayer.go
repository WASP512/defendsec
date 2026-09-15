package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/auditlayer"
	"defendsec/internal/controls"
	"defendsec/internal/storepg"
)

// The audit layer's HTTP surface (roadmap 1.9).
//
// Reading an assessment is open to viewers: the person assembling evidence
// before an audit is often not the person allowed to isolate a host. Creating
// periods and accepting deficiencies is admin-only and attributed, because an
// exception is a statement that somebody decided a gap was acceptable, and a
// statement needs a name on it.

func (s *Server) auditStore(w http.ResponseWriter) (*storepg.Store, bool) {
	if s.pg == nil {
		http.Error(w, "the audit layer requires a configured database", http.StatusServiceUnavailable)
		return nil, false
	}
	return s.pg, true
}

// HandleAuditPeriods lists and creates audit periods.
func (s *Server) HandleAuditPeriods(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.adminOK(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		periods, err := pg.ListAuditPeriods(r.Context())
		if err != nil {
			s.log.Warn("list audit periods", "err", err)
			http.Error(w, "could not list audit periods", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"periods": periods})

	case http.MethodPost:
		actor := s.resolveActor(r)
		if !s.requireAdminActor(w, r) {
			return
		}
		var req struct {
			Name      string `json:"name"`
			Framework string `json:"framework"`
			StartsAt  string `json:"startsAt"`
			EndsAt    string `json:"endsAt"`
			Notes     string `json:"notes"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		starts, err1 := time.Parse(time.RFC3339, strings.TrimSpace(req.StartsAt))
		ends, err2 := time.Parse(time.RFC3339, strings.TrimSpace(req.EndsAt))
		if err1 != nil || err2 != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "startsAt and endsAt must be RFC 3339 timestamps",
			})
			return
		}
		id, err := newDeviceID()
		if err != nil {
			http.Error(w, "could not allocate an id", http.StatusInternalServerError)
			return
		}
		p, err := pg.CreateAuditPeriod(r.Context(), auditlayer.Period{
			ID: id, Name: strings.TrimSpace(req.Name), Framework: strings.ToLower(strings.TrimSpace(req.Framework)),
			StartsAt: starts.UTC(), EndsAt: ends.UTC(),
			Notes: strings.TrimSpace(req.Notes), CreatedBy: actor.Identity(),
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		s.audit(actor.Identity(), "audit_period_create", "", map[string]any{
			"periodId": p.ID, "framework": p.Framework,
			"startsAt": p.StartsAt, "endsAt": p.EndsAt,
		})
		writeJSON(w, http.StatusOK, p)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleAuditPeriodClose declares a period final, or reopens it.
func (s *Server) HandleAuditPeriodClose(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := s.resolveActor(r)
	if !s.requireAdminActor(w, r) {
		return
	}
	var req struct {
		PeriodID string `json:"periodId"`
		// Closed is explicit rather than a toggle: a caller that has not seen
		// the current state must not be able to flip it by accident.
		Closed bool `json:"closed"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := pg.CloseAuditPeriod(r.Context(), strings.TrimSpace(req.PeriodID), actor.Identity(), req.Closed)
	if errors.Is(err, storepg.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such audit period"})
		return
	}
	if err != nil {
		s.log.Warn("close audit period", "err", err)
		http.Error(w, "could not update the audit period", http.StatusInternalServerError)
		return
	}
	action := "audit_period_reopen"
	if req.Closed {
		action = "audit_period_close"
	}
	s.audit(actor.Identity(), action, "", map[string]any{"periodId": p.ID})
	writeJSON(w, http.StatusOK, p)
}

// HandleControlExceptions lists, creates and closes documented exceptions.
func (s *Server) HandleControlExceptions(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.adminOK(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		from, to, err := windowFromQuery(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		list, err := pg.ListControlExceptions(r.Context(), from, to)
		if err != nil {
			s.log.Warn("list control exceptions", "err", err)
			http.Error(w, "could not list exceptions", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"exceptions": list})

	case http.MethodPost:
		actor := s.resolveActor(r)
		if !s.requireAdminActor(w, r) {
			return
		}
		var req struct {
			ControlID   string `json:"controlId"`
			PeriodID    string `json:"periodId"`
			Reason      string `json:"reason"`
			Remediation string `json:"remediation"`
			Owner       string `json:"owner"`
			ExpiresAt   string `json:"expiresAt"`
			// Close, with an id, ends an exception early instead of opening one.
			Close string `json:"close"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}

		if id := strings.TrimSpace(req.Close); id != "" {
			e, err := pg.CloseControlException(r.Context(), id, actor.Identity())
			if errors.Is(err, storepg.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such open exception"})
				return
			}
			if err != nil {
				s.log.Warn("close control exception", "err", err)
				http.Error(w, "could not close the exception", http.StatusInternalServerError)
				return
			}
			s.audit(actor.Identity(), "control_exception_close", "", map[string]any{
				"exceptionId": e.ID, "controlId": e.ControlID,
			})
			writeJSON(w, http.StatusOK, e)
			return
		}

		expires, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "expiresAt must be an RFC 3339 timestamp — an exception without an expiry is a permanent excuse",
			})
			return
		}
		id, err := newDeviceID()
		if err != nil {
			http.Error(w, "could not allocate an id", http.StatusInternalServerError)
			return
		}
		e, err := pg.CreateControlException(r.Context(), auditlayer.Exception{
			ID: id, ControlID: strings.TrimSpace(req.ControlID),
			PeriodID:    strings.TrimSpace(req.PeriodID),
			Reason:      strings.TrimSpace(req.Reason),
			Remediation: strings.TrimSpace(req.Remediation),
			Owner:       strings.TrimSpace(req.Owner),
			OpenedAt:    time.Now().UTC(), OpenedBy: actor.Identity(),
			ExpiresAt: expires.UTC(),
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		// Accepting a deficiency is exactly the kind of decision the ledger
		// exists for: it is a person choosing to live with a gap.
		s.audit(actor.Identity(), "control_exception_open", "", map[string]any{
			"exceptionId": e.ID, "controlId": e.ControlID,
			"reason": e.Reason, "expiresAt": e.ExpiresAt,
		})
		writeJSON(w, http.StatusOK, e)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleAuditAssessment renders per-control status for a framework over a
// window — the self-assessment view an agency completes before an assessor
// arrives.
func (s *Server) HandleAuditAssessment(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	q := r.URL.Query()
	var period auditlayer.Period
	if id := strings.TrimSpace(q.Get("periodId")); id != "" {
		p, err := pg.GetAuditPeriod(r.Context(), id)
		if errors.Is(err, storepg.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such audit period"})
			return
		}
		if err != nil {
			s.log.Warn("get audit period", "err", err)
			http.Error(w, "could not load the audit period", http.StatusInternalServerError)
			return
		}
		period = p
	} else {
		from, to, err := windowFromQuery(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		period = auditlayer.Period{
			Name: "Ad-hoc window", StartsAt: from, EndsAt: to,
		}
	}

	framework := controls.Framework(strings.ToLower(strings.TrimSpace(q.Get("framework"))))
	if framework == "" {
		framework = controls.Framework(period.Framework)
	}
	if !controls.KnownFramework(framework) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "framework must be one of " + strings.Join(frameworkIDs(), ", "),
		})
		return
	}

	assessment, err := pg.AssessPeriod(r.Context(), framework, period, time.Now().UTC())
	if err != nil {
		s.log.Warn("assess period", "err", err)
		http.Error(w, "could not assess the period", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, assessment)
}

func frameworkIDs() []string {
	out := make([]string, 0, len(controls.Frameworks()))
	for _, f := range controls.Frameworks() {
		out = append(out, string(f))
	}
	return out
}

// windowFromQuery reads from/to, defaulting to the last 90 days — long enough
// to be a useful default and short enough that nobody mistakes it for a
// statement about a real audit period.
func windowFromQuery(r *http.Request) (time.Time, time.Time, error) {
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -90)

	if raw := strings.TrimSpace(q.Get("from")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("from must be an RFC 3339 timestamp")
		}
		from = t.UTC()
	}
	if raw := strings.TrimSpace(q.Get("to")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("to must be an RFC 3339 timestamp")
		}
		to = t.UTC()
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, errors.New("to must be after from")
	}
	return from, to, nil
}

// decodeJSON reads a small JSON body, answering 400 on anything unreadable.
// The size cap matches the identity handlers: these bodies are a handful of
// short fields, and an unbounded read is a free memory exhaustion.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(dst); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}
