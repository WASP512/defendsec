package control

import (
	"net/http"
	"time"
)

type osReleaseJSON struct {
	Product  string `json:"product"`
	Cycle    string `json:"cycle"`
	Label    string `json:"label"`
	EoasFrom string `json:"eoasFrom"`
	EolFrom  string `json:"eolFrom"`
	EoesFrom string `json:"eoesFrom"`
	IsLTS    bool   `json:"isLts"`
	// Latest is the newest build of the cycle ("10.0.14393"): how a host's
	// build number finds its cycle.
	Latest string `json:"latest"`
}

type osCalendarResponse struct {
	Releases    []osReleaseJSON `json:"releases"`
	FeedDate    *string         `json:"feedDate"`
	GeneratedAt string          `json:"generatedAt"`
}

// osCalendarProducts are the operating systems whose support dates come from
// the endoflife.date calendar (the Supported OS policy, Windows).
var osCalendarProducts = []string{"windows", "windows-server"}

// HandleOSCalendar serves GET /v1/lifecycle/os: the Windows release calendar
// the console's Supported OS policy judges hosts against. It reports what the
// endoflife feed has loaded; an empty list (feed never loaded) tells the
// console the support state is unknown, not that every host is supported.
func (s *Server) HandleOSCalendar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.pg == nil {
		http.Error(w, "postgres not configured", http.StatusServiceUnavailable)
		return
	}
	rels, err := s.pg.EOLReleases(r.Context(), osCalendarProducts)
	if err != nil {
		s.log.Warn("read os calendar", "err", err)
		http.Error(w, "could not read the release calendar", http.StatusInternalServerError)
		return
	}
	resp := osCalendarResponse{Releases: make([]osReleaseJSON, 0, len(rels)), GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, rel := range rels {
		resp.Releases = append(resp.Releases, osReleaseJSON{
			Product: rel.Product, Cycle: rel.Cycle, Label: rel.Label, EoasFrom: rel.EoasFrom, EolFrom: rel.EolFrom,
			EoesFrom: rel.EoesFrom, IsLTS: rel.IsLTS, Latest: rel.Latest,
		})
		if rel.FeedDate != nil {
			d := rel.FeedDate.UTC().Format(time.RFC3339)
			resp.FeedDate = &d
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
