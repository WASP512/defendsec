package control

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/cmdlog"
)

// Retention posture (roadmap 5.5).
//
// The compliance view claims to evidence audit retention. That claim is only
// as good as the numbers actually in force, and those live in three different
// places: an environment variable, a default in main, and — until this phase —
// a hard-coded record count nobody could see. This reports what is really
// configured, the same way /v1/crypto-posture reports what cryptography is
// really in force.
//
// An assessor asking "how long do you keep this?" should get a number from the
// running process, not a sentence from a document.

// RetentionStatus describes what is kept and for how long.
type RetentionStatus struct {
	// CommandHistoryDays is how long the file-backed command log keeps
	// privileged actions. Negative means indefinitely.
	CommandHistoryDays int `json:"commandHistoryDays"`
	// CommandHistoryStore names where the authoritative history lives.
	CommandHistoryStore string `json:"commandHistoryStore"`
	// AuditLedgerDays is how long the hash-chained ledger is kept. It is not
	// pruned at all, which is the honest answer rather than a large number.
	AuditLedgerPruned bool `json:"auditLedgerPruned"`
	// AlertRetentionDays applies to resolved findings only; open ones are
	// never pruned.
	AlertRetentionDays int `json:"alertRetentionDays"`
	// LiveQueryRetentionDays applies to query output.
	LiveQueryRetentionDays int `json:"liveQueryRetentionDays"`
	// MeetsCJISMinimum reports whether the configured windows reach the one
	// year CJIS Policy Area 4 requires.
	MeetsCJISMinimum bool `json:"meetsCjisMinimum"`
	// OldestLedgerEntry is when the earliest chained entry was written. This
	// is what an assessor actually wants: not the configured window, but how
	// much history is really held. A one-year policy on a system installed
	// last month evidences one month.
	OldestLedgerEntry *time.Time `json:"oldestLedgerEntry,omitempty"`
	// LedgerCoverageDays is the span that entry implies.
	LedgerCoverageDays int `json:"ledgerCoverageDays,omitempty"`
	// Notes state the deviations plainly, so nothing is implied by silence.
	Notes []string `json:"notes"`
}

// cjisMinimumDays is the retention CJIS Policy Area 4 requires.
const cjisMinimumDays = 365

func envDays(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// RetentionPosture reports the windows actually in force.
func (s *Server) RetentionPosture(ctx context.Context) RetentionStatus {
	st := RetentionStatus{
		CommandHistoryDays:     cmdlog.DefaultRetentionDays,
		CommandHistoryStore:    "json file",
		AlertRetentionDays:     envDays("DEFENDSEC_ALERT_RETENTION_DAYS", 365),
		LiveQueryRetentionDays: envDays("DEFENDSEC_LIVE_QUERY_RETENTION_DAYS", 30),
	}
	if s.commands != nil {
		st.CommandHistoryDays = s.commands.RetentionDays()
	}
	if s.pg != nil {
		// Postgres holds the authoritative command history and never prunes
		// it, so the file window bounds a cache rather than the record.
		st.CommandHistoryStore = "postgres (authoritative) with a json cache"
	}

	meets := func(days int) bool { return days < 0 || days >= cjisMinimumDays }
	st.MeetsCJISMinimum = meets(st.CommandHistoryDays) && meets(st.AlertRetentionDays)

	if s.pg != nil {
		st.Notes = append(st.Notes,
			"Command history and the hash-chained audit ledger are held in Postgres and are never pruned. The window below bounds the local JSON cache, not the record.")
	} else {
		st.Notes = append(st.Notes,
			"No database is configured, so the JSON file is the only copy of command history. Configure Postgres: the file is capped for size and a busy fleet can reach that cap.")
	}
	st.Notes = append(st.Notes,
		"The audit ledger is never pruned by retention. Removing entries would break the hash chain, which is the point of it.")
	st.Notes = append(st.Notes,
		"Alert retention applies to resolved findings only. An open finding is never deleted on age.")

	if at, ok := s.auditLedgerDepth(ctx); ok {
		st.OldestLedgerEntry = &at
		st.LedgerCoverageDays = int(time.Since(at).Hours() / 24)
		if st.LedgerCoverageDays < cjisMinimumDays {
			// Said plainly, because a configured window is not evidence. A
			// one-year policy on a system installed last month evidences one
			// month, and an assessor will ask.
			st.Notes = append(st.Notes, fmt.Sprintf(
				"The ledger currently holds %d days of history, starting %s. Retention configuration does not create history that was never recorded.",
				st.LedgerCoverageDays, at.Format("2006-01-02")))
		}
	}

	if !st.MeetsCJISMinimum {
		st.Notes = append(st.Notes,
			"At least one window is shorter than the year CJIS Policy Area 4 requires. Raise DEFENDSEC_ALERT_RETENTION_DAYS and DEFENDSEC_COMMAND_RETENTION_DAYS, or record the shortfall as a documented exception.")
	}
	return st
}

// HandleRetention serves the posture.
//
// Admin-only, matching the cryptographic posture endpoint: it is not secret,
// but it tells an attacker how long they have before evidence ages out.
func (s *Server) HandleRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminActor(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.RetentionPosture(r.Context()))
}

// auditLedgerDepth reports the oldest chained entry, so the posture can be
// checked against reality rather than configuration.
func (s *Server) auditLedgerDepth(ctx context.Context) (time.Time, bool) {
	if s.pg == nil {
		return time.Time{}, false
	}
	at, ok, err := s.pg.OldestChainedEntry(ctx)
	if err != nil {
		s.log.Warn("read oldest chained entry", "err", err)
		return time.Time{}, false
	}
	return at, ok
}
