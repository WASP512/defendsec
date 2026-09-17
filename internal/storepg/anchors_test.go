package storepg

import (
	"context"
	"strings"
	"testing"
	"time"

	"defendsec/internal/anchor"
	"defendsec/internal/sign"
)

// resetAnchors clears the anchor tables and leaves checkpoints alone.
//
// Safe to call mid-test: a test that anchors a checkpoint, then wants to
// re-test it as unanchored, needs the checkpoint to survive.
func resetAnchors(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `TRUNCATE audit_anchors, peer_anchors`); err != nil {
		t.Fatalf("reset anchors: %v", err)
	}
}

// resetCheckpoints additionally clears the checkpoint table, for a test that
// asserts something about "the newest checkpoint".
//
// That assertion only means anything if this test created it. Other packages
// share this database and leave checkpoints of their own behind, so without
// this these tests pass alone and fail in a full run — which is the worst way
// for a test to be wrong, because it reads like a flake.
func resetCheckpoints(t *testing.T, s *Store) {
	t.Helper()
	resetAnchors(t, s)
	if _, err := s.pool.Exec(context.Background(), `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatalf("reset checkpoints: %v", err)
	}
}

func TestRecordAndListAnchors(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAnchors(t, s)

	now := time.Now().UTC().Truncate(time.Second)
	records := []anchor.Record{
		{
			ID: randID(t), ThroughSeq: 5, EntryHash: strings.Repeat("ab", 32),
			Kind: anchor.KindTSA, Target: "https://tsa.example", AnchoredAt: now,
			ExternalTime: now.Add(time.Second), Proof: []byte{1, 2, 3}, Reference: "serial-1",
		},
		{
			ID: randID(t), ThroughSeq: 5, EntryHash: strings.Repeat("ab", 32),
			Kind: anchor.KindFile, Target: "/tmp/anchors", AnchoredAt: now,
			Error: "disk full",
		},
	}
	if err := s.RecordAnchors(ctx, records); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListAnchors(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("stored %d anchors, want 2", len(got))
	}

	var sawFailure, sawProof bool
	for _, r := range got {
		if r.Error == "disk full" {
			sawFailure = true
		}
		if len(r.Proof) == 3 && r.Reference == "serial-1" && !r.ExternalTime.IsZero() {
			sawProof = true
		}
	}
	// Failures are stored, not discarded. A run of them is the interesting
	// signal, and a history with them dropped looks healthier than it is.
	if !sawFailure {
		t.Error("the failed anchor was not stored")
	}
	if !sawProof {
		t.Error("the proof, reference and external time did not round trip")
	}
}

// The comparison is the point. Writing anchors and never checking them
// detects nothing.
func TestVerifyAnchorsAgainstTheRealChain(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAnchors(t, s)

	if err := s.Audit(ctx, "user:alice", "command_issue", "", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	var seq int64
	var hash string
	if err := s.pool.QueryRow(ctx,
		`SELECT seq, entry_hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1`,
	).Scan(&seq, &hash); err != nil {
		t.Fatal(err)
	}

	// An anchor over the real hash must match.
	if err := s.RecordAnchors(ctx, []anchor.Record{{
		ID: randID(t), ThroughSeq: seq, EntryHash: hash,
		Kind: anchor.KindFile, AnchoredAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	vs, summary, err := s.VerifyAnchors(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Matching != 1 || summary.Mismatched != 0 {
		t.Fatalf("summary = %+v", summary)
	}
	if !vs[0].Matches {
		t.Errorf("an intact anchor did not match: %s", vs[0].Detail)
	}

	// Now simulate the attack the whole feature exists for: the chain is
	// rebuilt by someone who also holds the signing key, so every signature
	// still verifies — but the anchored hash no longer matches.
	resetAnchors(t, s)
	if err := s.RecordAnchors(ctx, []anchor.Record{{
		ID: randID(t), ThroughSeq: seq, EntryHash: strings.Repeat("99", 32),
		Kind: anchor.KindTSA, AnchoredAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	vs, summary, err = s.VerifyAnchors(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Mismatched != 1 {
		t.Fatalf("a rebuilt chain passed the anchor comparison: %+v", summary)
	}
	if vs[0].Matches {
		t.Error("the mismatched anchor reported a match")
	}

	// And an anchor over a sequence the chain no longer reaches: anchored
	// history has been truncated.
	resetAnchors(t, s)
	if err := s.RecordAnchors(ctx, []anchor.Record{{
		ID: randID(t), ThroughSeq: seq + 1_000_000, EntryHash: strings.Repeat("77", 32),
		Kind: anchor.KindTSA, AnchoredAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	_, summary, err = s.VerifyAnchors(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Missing != 1 {
		t.Fatalf("truncated anchored history was not detected: %+v", summary)
	}
}

// The scheduler must anchor what is missing rather than re-anchoring the same
// checkpoint on every tick.
func TestLatestUnanchoredCheckpoint(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetCheckpoints(t, s)

	key, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Audit(ctx, "user:alice", "command_issue", "", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	cp, ok, err := s.AppendCheckpoint(ctx, key.Private, key.KeyID())
	if err != nil || !ok {
		t.Fatalf("append checkpoint: %v, %v", ok, err)
	}

	got, found, err := s.LatestUnanchoredCheckpoint(ctx)
	if err != nil || !found {
		t.Fatalf("no unanchored checkpoint found: %v, %v", found, err)
	}
	if got.ThroughSeq != cp.ThroughSeq {
		t.Errorf("found seq %d, want the newest, %d", got.ThroughSeq, cp.ThroughSeq)
	}

	// Once anchored successfully it must not come back.
	if err := s.RecordAnchors(ctx, []anchor.Record{{
		ID: randID(t), ThroughSeq: cp.ThroughSeq, EntryHash: cp.EntryHash,
		Kind: anchor.KindFile, AnchoredAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	got, found, err = s.LatestUnanchoredCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if found && got.ThroughSeq == cp.ThroughSeq {
		t.Error("an already-anchored checkpoint was offered again")
	}

	// A failed attempt must not count as anchored, or a broken target would
	// silently mean that checkpoint is never published.
	resetAnchors(t, s)
	if err := s.RecordAnchors(ctx, []anchor.Record{{
		ID: randID(t), ThroughSeq: cp.ThroughSeq, EntryHash: cp.EntryHash,
		Kind: anchor.KindTSA, AnchoredAt: time.Now().UTC(), Error: "unreachable",
	}}); err != nil {
		t.Fatal(err)
	}
	got, found, err = s.LatestUnanchoredCheckpoint(ctx)
	if err != nil || !found {
		t.Fatalf("a failed anchor marked the checkpoint as done: %v, %v", found, err)
	}
	if got.ThroughSeq != cp.ThroughSeq {
		t.Errorf("found seq %d, want %d", got.ThroughSeq, cp.ThroughSeq)
	}
}

func TestPeerAnchorsAreHeldSeparately(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAnchors(t, s)

	at := time.Now().UTC().Truncate(time.Second)
	if err := s.StorePeerAnchor(ctx, PeerAnchor{
		ID: randID(t), Peer: "agency-b", ThroughSeq: 12,
		EntryHash: strings.Repeat("cd", 32), SigningKeyID: "key-b",
		Signature: "sig-b", CheckpointAt: at,
	}); err != nil {
		t.Fatal(err)
	}

	peers, err := s.ListPeerAnchors(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Peer != "agency-b" || peers[0].Signature != "sig-b" {
		t.Fatalf("peer anchor = %+v", peers)
	}

	// A peer's evidence must never appear among this instance's own anchors,
	// or a compromised peer's claims could be read as ours.
	own, err := s.ListAnchors(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 0 {
		t.Fatalf("a peer anchor leaked into this instance's anchors: %+v", own)
	}
}
