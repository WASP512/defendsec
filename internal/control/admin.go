package control

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) HandleAudit(w http.ResponseWriter, r *http.Request) {
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
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.pg.ListAudit(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": rows})
}

func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		DeviceID    string `json:"deviceId"`
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.Fingerprint = strings.TrimSpace(req.Fingerprint)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		req.Reason = "revoked by admin"
	}
	if req.Fingerprint == "" && req.DeviceID != "" {
		if dev, ok := s.store.Get(req.DeviceID); ok {
			req.Fingerprint = dev.CertFingerprint
		}
	}
	if req.Fingerprint == "" || req.DeviceID == "" {
		http.Error(w, "deviceId and fingerprint required", http.StatusBadRequest)
		return
	}
	if err := s.pg.Revoke(r.Context(), req.Fingerprint, req.DeviceID, req.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.store.SetConnected(req.DeviceID, false)
	s.audit("admin", "cert_revoke", req.DeviceID, map[string]any{
		"fingerprint": req.Fingerprint,
		"reason":      req.Reason,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) HandleAdvisories(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.pg == nil {
		http.Error(w, "postgres not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.pg.ListAdvisories(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"advisories": rows})
	case http.MethodPost:
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req struct {
			Advisories []struct {
				ID       string `json:"id"`
				CVE      string `json:"cve"`
				Package  string `json:"package"`
				Below    string `json:"below"`
				Severity string `json:"severity"`
				Summary  string `json:"summary"`
				Source   string `json:"source"`
			} `json:"advisories"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		n := 0
		for _, a := range req.Advisories {
			if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Package) == "" || strings.TrimSpace(a.Below) == "" {
				continue
			}
			src := a.Source
			if src == "" {
				src = "import"
			}
			if err := s.pg.UpsertAdvisory(r.Context(), a.ID, a.CVE, a.Package, a.Below, a.Severity, a.Summary, src); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			n++
		}
		s.audit("admin", "advisories_import", "", map[string]any{"count": n})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": n})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) HandleAgentReleases(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.pg == nil {
		http.Error(w, "postgres not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		channel := r.URL.Query().Get("channel")
		if channel == "" {
			channel = "stable"
		}
		version, url, sha256, notes, err := s.pg.LatestAgentRelease(r.Context(), channel)
		if err != nil {
			http.Error(w, "no release", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": version, "channel": channel, "url": url, "sha256": sha256, "notes": notes,
		})
	case http.MethodPost:
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req struct {
			Version string `json:"version"`
			Channel string `json:"channel"`
			URL     string `json:"url"`
			SHA256  string `json:"sha256"`
			Notes   string `json:"notes"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Channel == "" {
			req.Channel = "stable"
		}
		if req.Version == "" || req.URL == "" || req.SHA256 == "" {
			http.Error(w, "version, url, sha256 required", http.StatusBadRequest)
			return
		}
		if err := s.pg.PublishAgentRelease(r.Context(), req.Version, req.Channel, req.URL, req.SHA256, req.Notes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit("admin", "agent_release_publish", "", map[string]any{"version": req.Version, "channel": req.Channel})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
