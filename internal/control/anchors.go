package control

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/anchor"
	"defendsec/internal/storepg"
)

// Transparency anchoring over HTTP (roadmap 1.6).

// HandleAnchors reports anchor status and, on POST, publishes now.
//
// The GET is the comparison, not a list. A count of anchors written proves
// nothing; whether they still match the chain is the only question worth
// asking, so that is what the endpoint answers.
func (s *Server) HandleAnchors(w http.ResponseWriter, r *http.Request) {
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
		limit := 200
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		verifications, summary, err := pg.VerifyAnchors(r.Context(), limit)
		if err != nil {
			s.log.Warn("verify anchors", "err", err)
			http.Error(w, "could not verify anchors", http.StatusInternalServerError)
			return
		}
		peers, err := pg.ListPeerAnchors(r.Context(), limit)
		if err != nil {
			s.log.Warn("list peer anchors", "err", err)
			peers = nil
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"summary":       summary,
			"verifications": verifications,
			"peerAnchors":   peers,
			"targets":       s.anchorTargetSummary(),
		})

	case http.MethodPost:
		actor := s.resolveActor(r)
		if !s.requireAdminActor(w, r) {
			return
		}
		if s.anchors == nil || len(s.anchors.Targets) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "no anchor targets are configured; set DEFENDSEC_ANCHOR_TARGETS",
			})
			return
		}
		records, anchored, err := s.anchorNow(r.Context())
		if err != nil {
			s.log.Warn("anchor now", "err", err)
			http.Error(w, "could not anchor", http.StatusInternalServerError)
			return
		}
		if !anchored {
			writeJSON(w, http.StatusOK, map[string]any{
				"anchored": false,
				"detail":   "every signed checkpoint is already anchored; nothing to publish",
			})
			return
		}
		s.audit(actor.Identity(), "audit_anchor_publish", "", map[string]any{
			"throughSeq": records[0].ThroughSeq, "targets": len(records),
		})
		writeJSON(w, http.StatusOK, map[string]any{"anchored": true, "records": records})

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// anchorTargetSummary describes what is configured without leaking the peer
// tokens, which are shared secrets.
func (s *Server) anchorTargetSummary() []map[string]string {
	if s.anchors == nil {
		return []map[string]string{}
	}
	out := make([]map[string]string, 0, len(s.anchors.Targets))
	for _, t := range s.anchors.Targets {
		out = append(out, map[string]string{"kind": string(t.Kind), "target": t.Ref})
	}
	return out
}

// anchorNow publishes the newest checkpoint that is not yet anchored.
func (s *Server) anchorNow(ctx context.Context) ([]anchor.Record, bool, error) {
	cp, found, err := s.pg.LatestUnanchoredCheckpoint(ctx)
	if err != nil || !found {
		return nil, false, err
	}
	records := s.anchors.Publish(ctx, cp)
	for i := range records {
		id, err := newDeviceID()
		if err != nil {
			return nil, false, err
		}
		records[i].ID = id
	}
	if err := s.pg.RecordAnchors(ctx, records); err != nil {
		return nil, false, err
	}
	return records, true, nil
}

// HandleAnchorReceive accepts a checkpoint from a peer instance.
//
// Peers authenticate with a shared token. Without one an anchor store is a
// public write endpoint, and an attacker who wanted to bury a real mismatch
// could simply flood it.
func (s *Server) HandleAnchorReceive(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.peerAnchorToken == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "this instance does not accept peer anchors",
		})
		return
	}
	presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.peerAnchorToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	var req anchor.PeerAnchorRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ThroughSeq <= 0 || strings.TrimSpace(req.EntryHash) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "throughSeq and entryHash are required",
		})
		return
	}

	id, err := newDeviceID()
	if err != nil {
		http.Error(w, "could not allocate an id", http.StatusInternalServerError)
		return
	}
	stored := storepg.PeerAnchor{
		ID: id, Peer: strings.TrimSpace(req.Server),
		ThroughSeq: req.ThroughSeq, EntryHash: strings.TrimSpace(req.EntryHash),
		SigningKeyID: req.SigningKeyID, Signature: req.Signature,
	}
	if at, err := time.Parse(time.RFC3339, req.At); err == nil {
		stored.CheckpointAt = at.UTC()
	}
	if err := pg.StorePeerAnchor(r.Context(), stored); err != nil {
		s.log.Warn("store peer anchor", "err", err)
		http.Error(w, "could not store the anchor", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, anchor.PeerAnchorReceipt{
		ID: id, ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// AnchorLatest publishes the newest unanchored checkpoint. It is exported for
// the background loop; the HTTP handler uses the same path, so a manual
// "anchor now" and the scheduled run cannot drift apart.
func (s *Server) AnchorLatest(ctx context.Context) ([]anchor.Record, bool, error) {
	if s.pg == nil || s.anchors == nil || len(s.anchors.Targets) == 0 {
		return nil, false, nil
	}
	return s.anchorNow(ctx)
}
