package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/identity"
	"defendsec/internal/storepg"
)

// First-run setup: creating the first administrator without the shared token.
//
// # The problem this solves
//
// A fresh install previously required the operator to find the admin token
// on the server, paste it into a hidden field, and then find the Accounts
// page to create themselves an account. Every step of that was a place to
// get stuck, and the login page did not even offer it: it asked the control
// plane whether accounts existed without being signed in, got a 401, and
// assumed they did.
//
// # The risk it has to avoid
//
// A form that lets anyone create the first administrator hands the fleet to
// whoever reaches it first. On a LAN that is usually the owner, but "usually"
// is not a property a security product gets to rely on.
//
// # The design
//
// Setup is open only while no account exists, and only for a window after the
// control plane starts — thirty minutes by default. That is the pattern
// Portainer uses, and it moves the proof of ownership to where it belongs: an
// operator who misses the window reopens it by restarting defendsec-apid,
// which requires access to the server. Somebody who merely reached the
// console's port cannot restart anything.
//
// The window closes the moment the first account exists, whatever the clock
// says, and the account is created under an advisory lock so two people
// submitting at once cannot both become administrator. The shared token keeps
// working throughout as the fallback, including for installs that set the
// window to zero and want no open setup at all.

// DefaultSetupWindow is how long first-run setup stays open after start.
const DefaultSetupWindow = 30 * time.Minute

// OpenSetupWindow opens first-run setup until now+d. A zero or negative
// duration leaves it closed, so the shared token is the only way to create
// the first account.
func (s *Server) OpenSetupWindow(now time.Time, d time.Duration) {
	if d <= 0 {
		s.setupOpenUntil = time.Time{}
		return
	}
	s.setupOpenUntil = now.Add(d)
}

// SetupStatus is what the login page needs to decide what to show.
type SetupStatus struct {
	// DatabaseConfigured is false when accounts are impossible, in which
	// case the shared token is the only way in.
	DatabaseConfigured bool `json:"databaseConfigured"`
	AccountsExist      bool `json:"accountsExist"`
	// SetupOpen is true when a first administrator can be created now,
	// without the token.
	SetupOpen bool `json:"setupOpen"`
	// SecondsRemaining is how long setup stays open, so the page can say so.
	SecondsRemaining int    `json:"secondsRemaining,omitempty"`
	// ViaInvite is true when setup is open because the request carried a
	// valid first-admin invite from `defendsec-apid bootstrap-admin`.
	ViaInvite bool `json:"viaInvite,omitempty"`
	// InviteInvalid is true when an invite was presented and refused, so
	// the page can say so rather than silently showing the closed state.
	InviteInvalid bool   `json:"inviteInvalid,omitempty"`
	Detail        string `json:"detail"`
}

// setupStatus reports the current first-run state.
func (s *Server) setupStatus(ctx context.Context, now time.Time, invite string) (SetupStatus, error) {
	if s.pg == nil {
		return SetupStatus{
			Detail: "No database is configured, so named accounts are unavailable. Sign in with the admin token.",
		}, nil
	}
	n, err := s.pg.CountUsers(ctx)
	if err != nil {
		return SetupStatus{}, err
	}
	st := SetupStatus{DatabaseConfigured: true, AccountsExist: n > 0}
	inviteOK := false
	if invite = strings.TrimSpace(invite); invite != "" && !st.AccountsExist {
		ok, err := s.pg.SetupInviteValid(ctx, identity.HashSessionToken(invite))
		if err != nil {
			return SetupStatus{}, err
		}
		inviteOK, st.InviteInvalid = ok, !ok
	}
	switch {
	case st.AccountsExist:
		st.Detail = "Accounts exist. Sign in with yours."
	case inviteOK:
		st.SetupOpen, st.ViaInvite = true, true
		st.Detail = "This setup link was issued on the server. Create the first administrator."
	case !s.setupOpenUntil.IsZero() && now.Before(s.setupOpenUntil):
		st.SetupOpen = true
		st.SecondsRemaining = int(s.setupOpenUntil.Sub(now).Seconds())
		st.Detail = "No accounts exist yet. Create the first administrator."
	default:
		st.Detail = "No accounts exist yet, and first-run setup has closed. Run defendsec-apid bootstrap-admin on the server for a one-time setup link."
	}
	return st, nil
}

// HandleSetup serves first-run setup.
//
// Deliberately unauthenticated: its whole purpose is to work before any
// credential exists. Everything it can do is bounded by the checks above —
// no accounts, window open — and it can do nothing once an account exists.
func (s *Server) HandleSetup(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	switch r.Method {
	case http.MethodGet:
		st, err := s.setupStatus(r.Context(), now, r.URL.Query().Get("invite"))
		if err != nil {
			s.log.Warn("setup status", "err", err)
			http.Error(w, "could not read setup status", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, st)

	case http.MethodPost:
		s.createFirstAdmin(w, r, now)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) createFirstAdmin(w http.ResponseWriter, r *http.Request, now time.Time) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
		Password    string `json:"password"`
		// ClientAddress is the browser's address as the console saw it.
		// Reported, not verified — the console is the only thing that talks
		// to this port — and recorded so the audit log says where the first
		// administrator was created from.
		ClientAddress string `json:"clientAddress"`
		// Invite is a one-time link token from bootstrap-admin.
		Invite string `json:"invite"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	st, err := s.setupStatus(r.Context(), now, req.Invite)
	if err != nil {
		s.log.Warn("setup status", "err", err)
		http.Error(w, "could not read setup status", http.StatusInternalServerError)
		return
	}
	if !st.SetupOpen {
		// Refused with the reason, so the console can tell the operator what
		// to do rather than showing a bare failure.
		msg := st.Detail
		if st.InviteInvalid {
			msg = storepg.ErrInviteInvalid.Error()
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": msg, "status": st})
		return
	}
	inviteHash := ""
	if st.ViaInvite {
		inviteHash = identity.HashSessionToken(strings.TrimSpace(req.Invite))
	}

	id, err := newDeviceID()
	if err != nil {
		http.Error(w, "id", http.StatusInternalServerError)
		return
	}
	u, err := s.pg.CreateFirstUserWithInvite(r.Context(), id,
		req.Username, strings.TrimSpace(req.DisplayName), req.Password, inviteHash)
	if errors.Is(err, storepg.ErrInviteInvalid) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	if errors.Is(err, storepg.ErrAccountsExist) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "An account was created a moment ago, so setup has closed. Sign in with that account.",
		})
		return
	}
	if err != nil {
		// Validation errors (username rules, password length) are the
		// operator's to fix and are returned as written.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// Signed straight in, through the ordinary login path so the session is
	// created exactly as any other would be.
	_, token, err := s.pg.Authenticate(r.Context(), u.Username, req.Password, "", now)
	if err != nil {
		s.log.Error("sign in after setup", "err", err)
		writeJSON(w, http.StatusCreated, map[string]any{
			"user":   u,
			"detail": "Your account was created. Sign in with it.",
		})
		return
	}

	// Its own audit action, so "how did the first administrator come to
	// exist" is answerable by filtering the ledger.
	via := "first-run setup"
	if st.ViaInvite {
		via = "one-time setup link from bootstrap-admin"
	}
	s.audit("user:"+u.Username, "first_admin_created", "", map[string]any{
		"via":           via,
		"clientAddress": strings.TrimSpace(req.ClientAddress),
		"detail": setupAuditDetail(st.ViaInvite, s.setupOpenUntil),
	})
	u.PasswordHash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "token": token})
}

func setupAuditDetail(viaInvite bool, openUntil time.Time) string {
	if viaInvite {
		return "Created with a one-time setup link printed on the server by bootstrap-admin. No shared token was used."
	}
	return fmt.Sprintf("Created through first-run setup, open until %s. No shared token was used.", openUntil.Format(time.RFC3339))
}

// InviteTTL is how long a bootstrap-admin link stays valid.
const InviteTTL = time.Hour

// IssueSetupInvite creates a one-time first-admin invite and returns the
// token to put in the link. Refused once an account exists: the invite's
// only purpose is to create the first one.
func IssueSetupInvite(ctx context.Context, pg *storepg.Store, now time.Time) (string, time.Time, error) {
	n, err := pg.CountUsers(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if n > 0 {
		return "", time.Time{}, storepg.ErrAccountsExist
	}
	token, hash, err := identity.NewSessionToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := now.Add(InviteTTL)
	if err := pg.CreateSetupInvite(ctx, hash, expires); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}
