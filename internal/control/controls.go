package control

import (
	"net/http"
	"strings"

	"defendsec/internal/controls"
)

// The control catalog endpoint (roadmap 1.7).
//
// This is the honest-coverage view §3.10 asks for: every control, including
// the ones DefendSec cannot evidence, each with the reason. It deliberately
// does not compute a coverage percentage — a percentage is where a control
// nobody ever looked at disappears into a rounding error.

type controlCatalogResponse struct {
	Framework  string             `json:"framework,omitempty"`
	Title      string             `json:"title,omitempty"`
	Frameworks []frameworkSummary `json:"frameworks"`
	Controls   []controls.Control `json:"controls"`
}

type frameworkSummary struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Counts per coverage level. Reported as counts rather than a percentage
	// on purpose: "9 evidenced, 14 partial, 6 not evidenced" is a sentence an
	// assessor can act on, and "62% compliant" is not.
	Evidenced    int `json:"evidenced"`
	Partial      int `json:"partial"`
	NotEvidenced int `json:"notEvidenced"`
	Total        int `json:"total"`
}

func frameworkSummaries() []frameworkSummary {
	out := make([]frameworkSummary, 0, len(controls.Frameworks()))
	for _, f := range controls.Frameworks() {
		s := frameworkSummary{ID: string(f), Title: controls.FrameworkTitle(f)}
		for _, c := range controls.ForFramework(f) {
			s.Total++
			switch c.Coverage {
			case controls.CoverageEvidenced:
				s.Evidenced++
			case controls.CoveragePartial:
				s.Partial++
			default:
				s.NotEvidenced++
			}
		}
		out = append(out, s)
	}
	return out
}

// HandleControls serves the catalog, optionally narrowed to one framework.
//
// Readable by any authenticated caller, viewers included: knowing which
// controls the product claims to evidence is not privileged, and a viewer
// preparing for an audit is exactly who needs it.
func (s *Server) HandleControls(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	body := controlCatalogResponse{Frameworks: frameworkSummaries()}

	if raw := strings.TrimSpace(r.URL.Query().Get("framework")); raw != "" {
		f := controls.Framework(strings.ToLower(raw))
		if !controls.KnownFramework(f) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "unknown framework " + raw,
			})
			return
		}
		body.Framework = string(f)
		body.Title = controls.FrameworkTitle(f)
		body.Controls = controls.ForFramework(f)
	} else {
		body.Controls = controls.Catalog()
	}

	// A nil slice would marshal as null and make a caller distinguish it from
	// an empty catalog for no reason.
	if body.Controls == nil {
		body.Controls = []controls.Control{}
	}
	writeJSON(w, http.StatusOK, body)
}
