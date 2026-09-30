package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	Detail           string `json:"detail"`
}

// setupStatus reports the current first-run state.
func (s *Server) setupStatus(ctx context.Context, now time.Time) (SetupStatus, error) {
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
	switch {
	case st.AccountsExist:
		st.Detail = "Accounts exist. Sign in with yours."
	case !s.setupOpenUntil.IsZero() && now.Before(s.setupOpenUntil):
		st.SetupOpen = true
		st.SecondsRemaining = int(s.setupOpenUntil.Sub(now).Seconds())
		st.Detail = "No accounts exist yet. Create the first administrator."
	default:
		st.Detail = "No accounts exist yet, and first-run setup has closed. Restart defendsec-apid to reopen it, or sign in with the admin token."
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
		st, err := s.setupStatus(r.Context(), now)
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
	st, err := s.setupStatus(r.Context(), now)
	if err != nil {
		s.log.Warn("setup status", "err", err)
		http.Error(w, "could not read setup status", http.StatusInternalServerError)
		return
	}
	if !st.SetupOpen {
		// Refused with the reason, so the console can tell the operator what
		// to do rather than showing a bare failure.
		writeJSON(w, http.StatusForbidden, map[string]any{"error": st.Detail, "status": st})
		return
	}

	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
		Password    string `json:"password"`
		// ClientAddress is the browser's address as the console saw it.
		// Reported, not verified — the console is the only thing that talks
		// to this port — and recorded so the audit log says where the first
		// administrator was created from.
		ClientAddress string `json:"clientAddress"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	id, err := newDeviceID()
	if err != nil {
		http.Error(w, "id", http.StatusInternalServerError)
		return
	}
	u, err := s.pg.CreateFirstUser(r.Context(), id,
		req.Username, strings.TrimSpace(req.DisplayName), req.Password)
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
	s.audit("user:"+u.Username, "first_admin_created", "", map[string]any{
		"via":           "first-run setup",
		"clientAddress": strings.TrimSpace(req.ClientAddress),
		"detail": fmt.Sprintf(
			"Created through first-run setup, open until %s. No shared token was used.",
			s.setupOpenUntil.Format(time.RFC3339)),
	})
	u.PasswordHash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "token": token})
}
