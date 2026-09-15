package control

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/auditlayer"
	"defendsec/internal/controls"
	"defendsec/internal/evidence"
	"defendsec/internal/storepg"
)

// Evidence export (roadmap 1.5, extended by 1.9).
//
// One request produces a signed, timestamped bundle an assessor can verify
// with defendsec-verify while this server is switched off. That is the whole
// point: a verifier that has to ask the system it is checking proves nothing.

// HandleEvidenceExport writes an evidence bundle.
//
// Scoping to a framework and period adds a compliance assessment to the
// bundle. It deliberately does not narrow the audit range: a hash chain
// filtered by content is not a chain, and a bundle that withheld entries to
// look focused would fail its own verification or, worse, pass while
// misrepresenting what it covers.
func (s *Server) HandleEvidenceExport(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Export is admin-only: a bundle is a complete copy of the ledger, and a
	// read-only console role is not the same as permission to walk out with
	// one.
	actor := s.resolveActor(r)
	if !s.requireAdminActor(w, r) {
		return
	}
	if s.signer == nil {
		http.Error(w, "no control signing key is configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	var fromSeq int64
	if raw := strings.TrimSpace(q.Get("fromSeq")); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "fromSeq must be a non-negative integer"})
			return
		}
		fromSeq = n
	}

	pub := string(s.signer.PublicPEM())
	server := strings.TrimSpace(q.Get("server"))
	if server == "" {
		server = r.Host
	}

	var (
		bundle *evidence.Bundle
		err    error
		label  string
	)

	periodID := strings.TrimSpace(q.Get("periodId"))
	framework := controls.Framework(strings.ToLower(strings.TrimSpace(q.Get("framework"))))

	switch {
	case periodID != "":
		p, perr := pg.GetAuditPeriod(r.Context(), periodID)
		if errors.Is(perr, storepg.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such audit period"})
			return
		}
		if perr != nil {
			s.log.Warn("get audit period", "err", perr)
			http.Error(w, "could not load the audit period", http.StatusInternalServerError)
			return
		}
		if framework == "" {
			framework = controls.Framework(p.Framework)
		}
		if !controls.KnownFramework(framework) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown framework"})
			return
		}
		bundle, err = pg.ExportScopedEvidence(r.Context(), pub, server, framework, p, time.Now().UTC())
		label = fmt.Sprintf("%s-%s", framework, p.ID)

	case framework != "":
		if !controls.KnownFramework(framework) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown framework"})
			return
		}
		from, to, werr := windowFromQuery(r)
		if werr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": werr.Error()})
			return
		}
		p := auditlayer.Period{
			Name:     fmt.Sprintf("%s to %s", from.Format("2006-01-02"), to.Format("2006-01-02")),
			StartsAt: from, EndsAt: to, Framework: string(framework),
		}
		bundle, err = pg.ExportScopedEvidence(r.Context(), pub, server, framework, p, time.Now().UTC())
		label = string(framework)

	default:
		bundle, err = pg.ExportEvidence(r.Context(), pub, server, strings.TrimSpace(q.Get("scope")), "", fromSeq)
		label = "audit"
	}

	if err != nil {
		s.log.Warn("export evidence", "err", err)
		http.Error(w, "could not build the evidence bundle", http.StatusInternalServerError)
		return
	}

	// Exporting the ledger is itself an action worth recording: it is how a
	// copy of the evidence leaves the system.
	s.audit(actor.Identity(), "evidence_export", "", map[string]any{
		"scope": bundle.Manifest.Scope, "fromSeq": bundle.Manifest.FromSeq,
		"throughSeq": bundle.Manifest.ThroughSeq, "framework": string(framework),
		"periodId": periodID,
	})

	filename := fmt.Sprintf("defendsec-evidence-%s-%s.json",
		label, time.Now().UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if err := evidence.Write(w, bundle); err != nil {
		s.log.Warn("write evidence bundle", "err", err)
	}
}
