package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/identity"
	"defendsec/internal/storepg"
)

// Per-user identity for the admin API (roadmap 1.0).
//
// The console does not assert who the operator is. It forwards the operator's
// own session token, which this process validates against the database on
// every request, so the identity recorded in the ledger is one the control
// plane established itself rather than one it was told.
//
// The shared admin and viewer tokens still work: they bootstrap the first
// account and are what the installers and scripts use. Actions taken under
// them are recorded as unattributed, because they genuinely cannot be traced
// to a person.

// actorTimeout bounds the session lookup on the request path.
const actorTimeout = 3 * time.Second

// Actor is who the control plane believes is making a request.
type Actor struct {
	Role string // identity.RoleAdmin, identity.RoleViewer, or "" when unauthenticated
	User *identity.User
	// Attributed is false for the shared bootstrap tokens.
	Attributed bool
}

// Identity is the string recorded on commands and audit entries.
func (a Actor) Identity() string { return identity.ActorIdentity(a.User, a.Attributed) }

// resolveActor identifies the caller. A session token is tried first, then the
// shared tokens, so an installed script keeps working while a console session
// gets a named identity.
func (s *Server) resolveActor(r *http.Request) Actor {
	token := s.bearerToken(r)
	if token == "" {
		return Actor{}
	}

	if s.pg != nil {
		ctx, cancel := context.WithTimeout(r.Context(), actorTimeout)
		u, sess, err := s.pg.LookupSession(ctx, token, time.Now().UTC())
		cancel()
		if err == nil {
			user := u
			return Actor{Role: u.Role, User: &user, Attributed: sess.Attributed}
		}
		if err != nil && !errors.Is(err, storepg.ErrInvalidCredentials) {
			// A database problem must not silently downgrade to the shared
			// token path, or an outage would turn attributed requests into
			// unattributed ones.
			s.log.Warn("session lookup", "err", err)
			return Actor{}
		}
	}

	switch s.tokenRole(token) {
	case "admin":
		return Actor{Role: identity.RoleAdmin, Attributed: false}
	case "viewer":
		return Actor{Role: identity.RoleViewer, Attributed: false}
	}
	return Actor{}
}

// actorIdentity is the ledger string for a request.
func (s *Server) actorIdentity(r *http.Request) string {
	return s.resolveActor(r).Identity()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// HandleLogin exchanges a username, password and optional second-factor code
// for a session token.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pg == nil {
		http.Error(w, "accounts require a configured database", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totpCode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u, token, err := s.pg.Authenticate(ctx, req.Username, req.Password, req.TOTPCode, time.Now().UTC())
	switch {
	case errors.Is(err, storepg.ErrTOTPRequired):
		// Told apart from a failure so the console can prompt for a code,
		// which is already observable to whoever holds the password.
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "second factor required", "totpRequired": true,
		})
		return
	case errors.Is(err, storepg.ErrAccountLocked):
		s.audit("auth", "login_locked", "", map[string]any{"username": identity.NormalizeUsername(req.Username)})
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "account temporarily locked"})
		return
	case errors.Is(err, storepg.ErrInvalidCredentials):
		// One message for every failure mode, so the response cannot be used
		// to work out which accounts exist.
		s.audit("auth", "login_failed", "", map[string]any{"username": identity.NormalizeUsername(req.Username)})
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	case err != nil:
		s.log.Error("authenticate", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	s.audit("user:"+u.Username, "login", "", map[string]any{"role": u.Role})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": time.Now().UTC().Add(identity.SessionTTL),
		"user":      u,
	})
}

// HandleLogout ends the calling session.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	token := s.bearerToken(r)
	actor := s.resolveActor(r)
	if err := s.pg.DeleteSession(r.Context(), token); err != nil {
		s.log.Warn("delete session", "err", err)
	}
	if actor.User != nil {
		s.audit(actor.Identity(), "logout", "", map[string]any{})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// HandleSession reports who the caller is, so the console can render the
// operator's name and role without holding a second copy of that state.
func (s *Server) HandleSession(w http.ResponseWriter, r *http.Request) {
	actor := s.resolveActor(r)
	if actor.Role == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	body := map[string]any{
		"role":       actor.Role,
		"attributed": actor.Attributed,
		"identity":   actor.Identity(),
	}
	if actor.User != nil {
		body["user"] = actor.User
	}
	// Tells the console to offer first-account setup rather than a login form.
	if s.pg != nil {
		if n, err := s.pg.CountUsers(r.Context()); err == nil {
			body["accountsExist"] = n > 0
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// HandleUsers lists and creates accounts.
//
// Creation is open only while no account exists — that is the bootstrap, and
// it is what lets the shared token hand over to a named administrator. After
// that it requires an authenticated admin.
func (s *Server) HandleUsers(w http.ResponseWriter, r *http.Request) {
	if s.pg == nil {
		http.Error(w, "accounts require a configured database", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireAdminActor(w, r) {
			return
		}
		users, err := s.pg.ListUsers(r.Context())
		if err != nil {
			s.log.Error("list users", "err", err)
			http.Error(w, "list users", http.StatusInternalServerError)
			return
		}
		if users == nil {
			users = []identity.User{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})

	case http.MethodPost:
		count, err := s.pg.CountUsers(r.Context())
		if err != nil {
			http.Error(w, "count users", http.StatusInternalServerError)
			return
		}
		actor := s.resolveActor(r)
		firstAccount := count == 0
		if !firstAccount && actor.Role != identity.RoleAdmin {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if firstAccount && actor.Role == "" {
			// Even the bootstrap requires the shared token; an unauthenticated
			// caller must not be able to claim the first account.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Username    string `json:"username"`
			DisplayName string `json:"displayName"`
			Role        string `json:"role"`
			Password    string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Role == "" {
			req.Role = identity.RoleAdmin
		}
		id, err := newDeviceID()
		if err != nil {
			http.Error(w, "id", http.StatusInternalServerError)
			return
		}
		u, err := s.pg.CreateUser(r.Context(), id, req.Username, req.DisplayName, req.Role, req.Password)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		u.PasswordHash = ""
		s.audit(actor.Identity(), "user_created", "", map[string]any{
			"username": u.Username, "role": u.Role, "firstAccount": firstAccount,
		})
		writeJSON(w, http.StatusCreated, map[string]any{"user": u})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleUserUpdate changes a password or enables/disables an account.
func (s *Server) HandleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pg == nil {
		http.Error(w, "accounts require a configured database", http.StatusServiceUnavailable)
		return
	}
	actor := s.resolveActor(r)

	var req struct {
		UserID   string `json:"userId"`
		Password string `json:"password"`
		Disabled *bool  `json:"disabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		http.Error(w, "userId is required", http.StatusBadRequest)
		return
	}

	// An operator may always change their own password. Anything else, and
	// anyone else's account, needs admin.
	ownPassword := actor.User != nil && actor.User.ID == req.UserID && req.Password != "" && req.Disabled == nil
	if !ownPassword && actor.Role != identity.RoleAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	target, err := s.pg.GetUser(r.Context(), req.UserID)
	if err != nil {
		http.Error(w, "unknown user", http.StatusNotFound)
		return
	}

	if req.Password != "" {
		if err := s.pg.SetUserPassword(r.Context(), req.UserID, req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		s.audit(actor.Identity(), "user_password_changed", "", map[string]any{"username": target.Username})
	}
	if req.Disabled != nil {
		// Refusing self-disable keeps an administrator from locking everyone
		// out of their own console in one click.
		if actor.User != nil && actor.User.ID == req.UserID && *req.Disabled {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "you cannot disable your own account"})
			return
		}
		if err := s.pg.SetUserDisabled(r.Context(), req.UserID, *req.Disabled); err != nil {
			http.Error(w, "update user", http.StatusInternalServerError)
			return
		}
		action := "user_enabled"
		if *req.Disabled {
			action = "user_disabled"
		}
		s.audit(actor.Identity(), action, "", map[string]any{"username": target.Username})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// HandleTOTP begins and confirms second-factor enrollment.
//
// Enrollment is two steps on purpose: the secret is only stored once the
// operator has proved their authenticator produces a matching code, so a
// mis-scanned QR code cannot lock them out of their own account.
func (s *Server) HandleTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pg == nil {
		http.Error(w, "accounts require a configured database", http.StatusServiceUnavailable)
		return
	}
	actor := s.resolveActor(r)
	if actor.User == nil {
		// Only a named session can enroll a factor; the shared token has no
		// account to attach one to.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Step   string `json:"step"` // "begin" or "confirm"
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	switch req.Step {
	case "begin":
		secret, err := identity.NewTOTPSecret()
		if err != nil {
			http.Error(w, "generate secret", http.StatusInternalServerError)
			return
		}
		// Returned to the browser and handed back on confirm. Nothing is
		// stored until a code proves it works.
		writeJSON(w, http.StatusOK, map[string]any{
			"secret": secret,
			"uri":    identity.TOTPEnrollmentURI("DefendSec", actor.User.Username, secret),
		})

	case "confirm":
		res := identity.VerifyTOTP(req.Secret, req.Code, time.Now().Unix(), 0)
		if !res.Valid {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "that code did not match — check the time on your device"})
			return
		}
		// The confirming code is spent immediately, so it cannot also be used
		// to log in.
		if err := s.pg.EnrollTOTP(r.Context(), actor.User.ID, req.Secret, res.Counter); err != nil {
			s.log.Error("enroll totp", "err", err)
			http.Error(w, "enroll", http.StatusInternalServerError)
			return
		}
		s.audit(actor.Identity(), "totp_enrolled", "", map[string]any{"username": actor.User.Username})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		http.Error(w, `step must be "begin" or "confirm"`, http.StatusBadRequest)
	}
}

// requireAdminActor writes a 401 and reports false unless the caller is an admin.
func (s *Server) requireAdminActor(w http.ResponseWriter, r *http.Request) bool {
	if s.resolveActor(r).Role != identity.RoleAdmin {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// HandleCryptoPosture reports what cryptography is actually in force
// (roadmap 1.8).
//
// An assessor asking "is this FIPS mode?" is asking a question the deployment
// cannot answer from its own configuration: GODEBUG=fips140=on routes stdlib
// crypto through the validated module but rejects nothing, so a system can
// look compliant while hashing passwords with an unapproved algorithm. This
// reports the runtime state and names the deviations, rather than leaving
// them to be inferred from silence.
//
// Admin-only. The posture is not secret, but it tells an attacker which
// algorithms to expect, and there is no reason to publish it.
func (s *Server) HandleCryptoPosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminActor(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, identity.Status())
}
