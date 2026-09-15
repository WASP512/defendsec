package storepg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/anchor"
	"defendsec/internal/auditchain"
)

// Storage for transparency anchors (roadmap 1.6).

// RecordAnchors stores the outcome of publishing a checkpoint, successes and
// failures alike.
func (s *Store) RecordAnchors(ctx context.Context, records []anchor.Record) error {
	for _, r := range records {
		var external any
		if !r.ExternalTime.IsZero() {
			external = r.ExternalTime
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO audit_anchors
				(id, through_seq, entry_hash, kind, target, anchored_at, external_time, proof, reference, error)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (id) DO NOTHING
		`, r.ID, r.ThroughSeq, r.EntryHash, string(r.Kind), r.Target,
			r.AnchoredAt, external, r.Proof, r.Reference, r.Error); err != nil {
			return err
		}
	}
	return nil
}

// ListAnchors returns anchors, newest sequence first.
func (s *Store) ListAnchors(ctx context.Context, limit int) ([]anchor.Record, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, through_seq, entry_hash, kind, target, anchored_at,
		       external_time, proof, reference, error
		FROM audit_anchors
		ORDER BY through_seq DESC, anchored_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []anchor.Record{}
	for rows.Next() {
		var r anchor.Record
		var kind string
		var external *time.Time
		if err := rows.Scan(&r.ID, &r.ThroughSeq, &r.EntryHash, &kind, &r.Target,
			&r.AnchoredAt, &external, &r.Proof, &r.Reference, &r.Error); err != nil {
			return nil, err
		}
		r.Kind = anchor.Kind(kind)
		r.AnchoredAt = r.AnchoredAt.UTC()
		if external != nil {
			r.ExternalTime = external.UTC()
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ChainHashesAt returns the chain's current entry hash for each sequence in
// seqs. A sequence missing from the result no longer exists in the chain,
// which is itself a finding: anchored history has been truncated.
func (s *Store) ChainHashesAt(ctx context.Context, seqs []int64) (map[int64]string, error) {
	out := map[int64]string{}
	if len(seqs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT seq, entry_hash FROM audit_log WHERE seq = ANY($1)`, seqs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var hash string
		if err := rows.Scan(&seq, &hash); err != nil {
			return nil, err
		}
		out[seq] = hash
	}
	return out, rows.Err()
}

// VerifyAnchors compares every stored anchor against the chain as it stands.
//
// This is the step that gives anchoring its value, and the one products skip:
// writing anchors and never comparing them detects nothing at all.
func (s *Store) VerifyAnchors(ctx context.Context, limit int) ([]anchor.Verification, anchor.Summary, error) {
	records, err := s.ListAnchors(ctx, limit)
	if err != nil {
		return nil, anchor.Summary{}, err
	}
	seqs := make([]int64, 0, len(records))
	for _, r := range records {
		if r.OK() {
			seqs = append(seqs, r.ThroughSeq)
		}
	}
	current, err := s.ChainHashesAt(ctx, seqs)
	if err != nil {
		return nil, anchor.Summary{}, err
	}
	vs := anchor.VerifyAgainst(records, current)
	return vs, anchor.Summarise(vs), nil
}

// LatestUnanchoredCheckpoint returns the newest signed checkpoint that has no
// successful anchor yet, so the scheduler anchors what is missing rather than
// re-anchoring the same checkpoint on every tick.
func (s *Store) LatestUnanchoredCheckpoint(ctx context.Context) (auditchain.Checkpoint, bool, error) {
	var cp auditchain.Checkpoint
	err := s.pool.QueryRow(ctx, `
		SELECT c.at, c.through_seq, c.entry_hash, c.signing_key_id, c.signature
		FROM audit_checkpoints c
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_anchors a
			WHERE a.through_seq = c.through_seq AND a.error = ''
		)
		ORDER BY c.through_seq DESC
		LIMIT 1
	`).Scan(&cp.At, &cp.ThroughSeq, &cp.EntryHash, &cp.SigningKeyID, &cp.Signature)
	if err == pgx.ErrNoRows {
		return auditchain.Checkpoint{}, false, nil
	}
	if err != nil {
		return auditchain.Checkpoint{}, false, err
	}
	cp.At = cp.At.UTC()
	return cp, true, nil
}

// PeerAnchor is a checkpoint another instance asked this one to hold.
type PeerAnchor struct {
	ID           string    `json:"id"`
	Peer         string    `json:"peer"`
	ThroughSeq   int64     `json:"throughSeq"`
	EntryHash    string    `json:"entryHash"`
	SigningKeyID string    `json:"signingKeyId,omitempty"`
	Signature    string    `json:"signature,omitempty"`
	CheckpointAt time.Time `json:"checkpointAt,omitempty"`
	ReceivedAt   time.Time `json:"receivedAt"`
}

// StorePeerAnchor holds a peer's checkpoint.
//
// Peer anchors live in their own table. They are somebody else's evidence held
// on their behalf, and mixing them with this instance's own would let a
// compromised peer's claims be read as ours.
func (s *Store) StorePeerAnchor(ctx context.Context, a PeerAnchor) error {
	var at any
	if !a.CheckpointAt.IsZero() {
		at = a.CheckpointAt
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO peer_anchors (id, peer, through_seq, entry_hash, signing_key_id, signature, checkpoint_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO NOTHING
	`, a.ID, a.Peer, a.ThroughSeq, a.EntryHash, a.SigningKeyID, a.Signature, at)
	return err
}

// ListPeerAnchors returns held peer anchors, newest first.
func (s *Store) ListPeerAnchors(ctx context.Context, limit int) ([]PeerAnchor, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, peer, through_seq, entry_hash, signing_key_id, signature, checkpoint_at, received_at
		FROM peer_anchors ORDER BY received_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PeerAnchor{}
	for rows.Next() {
		var a PeerAnchor
		var at *time.Time
		if err := rows.Scan(&a.ID, &a.Peer, &a.ThroughSeq, &a.EntryHash,
			&a.SigningKeyID, &a.Signature, &at, &a.ReceivedAt); err != nil {
			return nil, err
		}
		if at != nil {
			a.CheckpointAt = at.UTC()
		}
		a.ReceivedAt = a.ReceivedAt.UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}
