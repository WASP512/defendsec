package control

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/sso"
	"defendsec/internal/storepg"
)

// Single sign-on endpoints (roadmap 5.4).
//
// The browser never talks to these directly. The console calls /start, keeps
// the returned state, nonce and PKCE verifier in a short httpOnly cookie,
// redirects to the identity provider, and on the callback checks the state
// against that cookie before calling /finish. Everything that decides who
// someone is — code exchange, token verification, group-to-role mapping,
// account linking — happens here, where the session store is.

// SetSSO installs the identity provider.
func (s *Server) SetSSO(p *sso.Provider) { s.sso = p }

// HandleSSO serves /v1/sso (status), /v1/sso/start and /v1/sso/finish.
//
// Unauthenticated by design: it is how an operator with no session gets one.
// It can only ever produce a session for an identity the IdP has signed and
// the operator's group mapping admits.
func (s *Server) HandleSSO(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/start") && r.Method == http.MethodPost:
		s.ssoStart(w, r)
	case strings.HasSuffix(r.URL.Path, "/finish") && r.Method == http.MethodPost:
		s.ssoFinish(w, r)
	case r.Method == http.MethodGet:
		if s.sso == nil {
			writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":     s.pg != nil,
			"displayName": s.sso.DisplayName(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) ssoReady(w http.ResponseWriter) bool {
	if s.sso == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "single sign-on is not configured"})
		return false
	}
	if s.pg == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "single sign-on needs a configured database"})
		return false
	}
	return true
}

func (s *Server) ssoStart(w http.ResponseWriter, r *http.Request) {
	if !s.ssoReady(w) {
		return
	}
	flow, err := s.sso.Start(r.Context())
	if err != nil {
		s.log.Warn("sso start", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "The identity provider could not be reached. Local accounts and the admin token still work.",
		})
		return
	}
	writeJSON(w, http.StatusOK, flow)
}

func (s *Server) ssoFinish(w http.ResponseWriter, r *http.Request) {
	if !s.ssoReady(w) {
		return
	}
	var req struct {
		Code          string `json:"code"`
		Verifier      string `json:"verifier"`
		Nonce         string `json:"nonce"`
		ClientAddress string `json:"clientAddress"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	now := time.Now().UTC()

	id, err := s.sso.Finish(r.Context(), req.Code, req.Verifier, req.Nonce)
	if errors.Is(err, sso.ErrNoMappedGroup) {
		// Recorded with the identity: a verified person being turned away
		// is worth knowing about, unlike a malformed callback.
		s.audit("auth", "sso_refused", "", map[string]any{
			"issuer": id.Issuer, "subject": id.Subject, "username": id.Username,
			"groups": id.Groups, "clientAddress": req.ClientAddress,
			"reason": "not a member of any group mapped to a DefendSec role",
		})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "Your identity provider account is not in a group that has access to DefendSec. Ask an administrator to add you.",
		})
		return
	}
	if err != nil {
		s.log.Warn("sso finish", "err", err)
		s.audit("auth", "sso_failed", "", map[string]any{
			"clientAddress": req.ClientAddress, "error": err.Error(),
		})
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "Single sign-on could not be verified. Try again.",
		})
		return
	}

	u, token, err := s.pg.SignInSSO(r.Context(), storepg.SSOIdentity{
		Issuer: id.Issuer, Subject: id.Subject,
		Username: id.Username, DisplayName: id.DisplayName, Role: id.Role,
	}, now)
	switch {
	case errors.Is(err, storepg.ErrUsernameTaken):
		s.audit("auth", "sso_refused", "", map[string]any{
			"issuer": id.Issuer, "subject": id.Subject, "username": id.Username,
			"reason": "username belongs to an existing account not linked to this identity",
		})
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "A DefendSec account named " + id.Username + " already exists and is not linked to your single sign-on identity. Accounts are never linked by name; an administrator must rename or remove the existing one.",
		})
		return
	case errors.Is(err, storepg.ErrInvalidCredentials):
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "This account is disabled in DefendSec."})
		return
	case err != nil:
		s.log.Error("sso sign-in", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Could not open a session."})
		return
	}

	s.audit("user:"+u.Username, "login", "", map[string]any{
		"role": u.Role, "method": "sso", "issuer": id.Issuer,
		"groups": id.Groups, "clientAddress": req.ClientAddress,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": u})
}
