package control

import (
	"net/http"
	"sort"
	"strings"

	"defendsec/internal/controls"
	"defendsec/internal/sca"
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

// HandleCheckCoverage reports what the shipped packs actually check
// (roadmap 3.7, §3.7).
//
// Published as a fraction with its denominator, never as a percentage or a
// claim of completeness. DefendSec ships a few dozen host checks; a CIS Linux
// Benchmark is 150-400 per platform. Reporting "CIS coverage" without that
// denominator is the claim §3.1 says not to make, and an assessor who later
// discovers the gap discounts everything else the product says.
func (s *Server) HandleCheckCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	packs, err := sca.LoadDir(sca.PacksDir())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"packs": []any{},
			"error": err.Error(),
			"detail": "The configuration packs failed to load, so no baseline checks are running. " +
				"This is not the same as every check passing.",
		})
		return
	}

	type packSummary struct {
		ID       string         `json:"id"`
		Name     string         `json:"name"`
		Checks   int            `json:"checks"`
		ByType   map[string]int `json:"byType"`
		Controls []string       `json:"controls"`
	}

	out := make([]packSummary, 0, len(packs))
	controlSet := map[string]bool{}
	total := 0
	byType := map[string]int{}

	for _, pack := range packs {
		cov := sca.Describe(pack)
		total += cov.Total
		for t, n := range cov.ByType {
			byType[t] += n
		}
		packControls := map[string]bool{}
		for _, c := range pack.Checks {
			for _, id := range c.Controls {
				packControls[id] = true
				controlSet[id] = true
			}
		}
		ids := make([]string, 0, len(packControls))
		for id := range packControls {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, packSummary{
			ID: pack.ID, Name: pack.Name, Checks: cov.Total,
			ByType: cov.ByType, Controls: ids,
		})
	}

	touched := make([]string, 0, len(controlSet))
	for id := range controlSet {
		touched = append(touched, id)
	}
	sort.Strings(touched)

	writeJSON(w, http.StatusOK, map[string]any{
		"packs":               out,
		"totalChecks":         total,
		"byType":              byType,
		"controlsTouched":     touched,
		"supportedCheckTypes": sca.KnownCheckTypes(),
		"detail": "These are the host checks DefendSec ships, not a benchmark. A CIS Linux " +
			"Benchmark is 150-400 checks per platform; DefendSec does not claim benchmark " +
			"coverage and is not a certified benchmark scanner. Use this alongside " +
			"/v1/controls, which states per control what DefendSec can and cannot evidence.",
	})
}
