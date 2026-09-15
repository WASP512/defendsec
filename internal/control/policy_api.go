package control

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/policy"
)

// HandlePolicy reports the policy in force.
//
// Readable by any authenticated caller, viewers included. Knowing what the
// rules are is not a privilege — an operator who cannot see why a command
// would be refused opens a ticket instead of reading the rule.
func (s *Server) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	doc := s.policy.Document()
	if doc == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"loaded": false,
			"detail": "No policy is loaded. DefendSec denies every command by default, so no host action can be issued until DEFENDSEC_POLICY_FILE is set.",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"loaded":   true,
		"name":     doc.Name,
		"hash":     doc.Hash,
		"source":   doc.Source,
		"timezone": doc.Timezone,
		"rules":    doc.Rules,
		"limits":   doc.Limits,
		"detail":   "Deny by default: a command is refused unless a rule permits it, and an explicit deny always wins.",
	})
}

// HandlePolicyDecisions lists recorded evaluations.
//
// Denials are the interesting half and are filterable on their own: "did
// anyone try" is the question asked after an incident, and it is the one a
// deny-by-default engine can actually answer.
func (s *Server) HandlePolicyDecisions(w http.ResponseWriter, r *http.Request) {
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

	effect := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("effect")))
	switch effect {
	case "", string(policy.EffectPermit), string(policy.EffectDeny), string(policy.EffectRequireApproval):
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "effect must be permit, deny or require-approval",
		})
		return
	}
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}

	decisions, err := pg.ListPolicyDecisions(r.Context(), effect, limit)
	if err != nil {
		s.log.Warn("list policy decisions", "err", err)
		http.Error(w, "could not list policy decisions", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": decisions})
}

// HandleBreakGlass opens, lists and closes emergency bypasses (roadmap 2.4).
func (s *Server) HandleBreakGlass(w http.ResponseWriter, r *http.Request) {
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
		now := time.Now().UTC()
		list, err := pg.ListBreakGlass(r.Context(), 100)
		if err != nil {
			s.log.Warn("list break-glass", "err", err)
			http.Error(w, "could not list break-glass records", http.StatusInternalServerError)
			return
		}
		active, err := pg.ActiveBreakGlass(r.Context(), now)
		if err != nil {
			s.log.Warn("read active break-glass", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": active, "history": list})

	case http.MethodPost:
		actor := s.resolveActor(r)
		if !s.requireAdminActor(w, r) {
			return
		}
		var req struct {
			Justification string `json:"justification"`
			// Minutes bounds the bypass. Required, and capped, because an
			// emergency that lasts a week is not an emergency.
			Minutes int `json:"minutes"`
			// Close, with an id, ends a bypass early.
			Close string `json:"close"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}

		if id := strings.TrimSpace(req.Close); id != "" {
			if err := pg.CloseBreakGlass(r.Context(), id, actor.Identity()); err != nil {
				s.notFoundOrError(w, err, "could not close the bypass")
				return
			}
			s.audit(actor.Identity(), "break_glass_close", "", map[string]any{"breakGlassId": id})
			writeJSON(w, http.StatusOK, map[string]any{"status": "closed", "id": id})
			return
		}

		justification := strings.TrimSpace(req.Justification)
		if len(justification) < 20 {
			// A one-word justification is not a justification. The whole
			// control rests on somebody having to write down why, in terms
			// that will be read back to them.
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "break-glass requires a written justification of at least 20 characters, which will be recorded and shown to every administrator",
			})
			return
		}
		minutes := req.Minutes
		if minutes <= 0 {
			minutes = 30
		}
		if minutes > maxBreakGlassMinutes {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "a break-glass bypass may last at most " +
					strconv.Itoa(maxBreakGlassMinutes) + " minutes; open another if the emergency continues",
			})
			return
		}

		id, err := newDeviceID()
		if err != nil {
			http.Error(w, "could not allocate an id", http.StatusInternalServerError)
			return
		}
		now := time.Now().UTC()
		bg, err := pg.OpenBreakGlass(r.Context(), policy.BreakGlass{
			ID: id, Justification: justification, OpenedBy: actor.Identity(),
			OpenedAt: now, ExpiresAt: now.Add(time.Duration(minutes) * time.Minute),
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}

		// Recorded with maximum prominence: a ledger entry and a
		// high-severity alert, because an unlogged emergency is how audits
		// fail and a silent one is how a bypass becomes routine.
		s.audit(actor.Identity(), "break_glass_open", "", map[string]any{
			"breakGlassId": id, "justification": justification,
			"expiresAt": bg.ExpiresAt.Format(time.RFC3339),
		})
		s.announceBreakGlass(bg)

		writeJSON(w, http.StatusOK, bg)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// maxBreakGlassMinutes caps a bypass at four hours. An emergency that lasts
// longer is a situation, and a situation should have a policy rule.
const maxBreakGlassMinutes = 240

// HandleHostClasses sets the tags policy rules match on (roadmap 2.2).
func (s *Server) HandleHostClasses(w http.ResponseWriter, r *http.Request) {
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
		DeviceID string   `json:"deviceId"`
		Classes  []string `json:"classes"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "deviceId is required"})
		return
	}

	classes := make([]string, 0, len(req.Classes))
	seen := map[string]bool{}
	for _, c := range req.Classes {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		// Classes are matched against policy rules, so a class containing a
		// comma or a wildcard would be a rule that means something other than
		// it reads.
		if strings.ContainsAny(c, ",*\n\t ") {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "a host class must be a single word without spaces, commas or wildcards: " + c,
			})
			return
		}
		seen[c] = true
		classes = append(classes, c)
	}

	if err := pg.SetDeviceClasses(r.Context(), deviceID, classes); err != nil {
		s.notFoundOrError(w, err, "could not set host classes")
		return
	}
	// Reclassifying a host changes what policy permits against it, so it is
	// an authorisation change and belongs in the ledger.
	s.audit(actor.Identity(), "host_classes_set", deviceID, map[string]any{"classes": classes})
	writeJSON(w, http.StatusOK, map[string]any{"deviceId": deviceID, "classes": classes})
}

// announceBreakGlass makes a bypass impossible to miss.
//
// It is deliberately not raised as an alert row. Alerts are per-host by
// construction — the table has a foreign key to devices — and a break-glass
// bypass is fleet-wide, so it would have to be attached to an arbitrary host
// or to all of them, and either reads as a finding about that host rather than
// a statement about the whole system.
//
// Instead it is recorded in the tamper-evident ledger, logged at error level
// so it reaches whatever collects logs, and surfaced by the API as a standing
// banner for every administrator until it expires. A banner nobody can dismiss
// is more prominent than one alert row among hundreds.
func (s *Server) announceBreakGlass(bg policy.BreakGlass) {
	s.log.Error("BREAK-GLASS OPENED — policy limits are bypassed",
		"id", bg.ID,
		"openedBy", bg.OpenedBy,
		"justification", bg.Justification,
		"expiresAt", bg.ExpiresAt.Format(time.RFC3339))
}
