package control

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"defendsec/internal/savedqueries"
)

func (s *Server) HandleSavedQueries(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listSavedQueries(w, r)
	case http.MethodPost:
		if !s.adminWriteOK(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.createSavedQuery(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listSavedQueries(w http.ResponseWriter, r *http.Request) {
	if s.pg != nil {
		rows, err := s.pg.ListSavedQueries(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]map[string]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, map[string]string{
				"id": row.ID, "name": row.Name, "query": row.Query, "createdAt": row.CreatedAt,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"queries": out, "source": "postgres"})
		return
	}
	file := savedqueries.NewFile(s.savedQueriesPath())
	rows, err := file.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"queries": rows, "source": "file"})
}

func (s *Server) createSavedQuery(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		Name  string `json:"name"`
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Query = strings.TrimSpace(strings.ToLower(req.Query))
	if req.Name == "" || req.Query == "" {
		http.Error(w, "name and query required", http.StatusBadRequest)
		return
	}
	if s.pg != nil {
		id, err := newDeviceID()
		if err != nil {
			http.Error(w, "id", http.StatusInternalServerError)
			return
		}
		if err := s.pg.InsertSavedQuery(r.Context(), id, req.Name, req.Query); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit("admin", "saved_query_create", "", map[string]any{"id": id, "name": req.Name, "query": req.Query})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "name": req.Name, "query": req.Query,
		})
		return
	}
	file := savedqueries.NewFile(s.savedQueriesPath())
	rec, err := file.Append(req.Name, req.Query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("admin", "saved_query_create", "", map[string]any{"id": rec.ID, "name": rec.Name, "query": rec.Query})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

func (s *Server) savedQueriesPath() string {
	return s.dataDir + "/saved-queries.json"
}
