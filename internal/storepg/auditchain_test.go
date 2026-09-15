package storepg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"defendsec/internal/auditchain"
	"defendsec/internal/cmdlog"
	"defendsec/internal/evidence"
	"defendsec/internal/sign"
)

// Integration tests against a real Postgres, skipped unless TEST_DATABASE_URL
// is set — same convention as store_test.go.
//
// Unlike the alert tests, these cannot isolate themselves with random ids: the
// chain is a single global sequence, so each test starts from a clean log.
// Note that running this package concurrently with db/migrations against the
// same database can deadlock, since migration DDL takes ACCESS EXCLUSIVE on
// audit_log while an append holds it — run the packages one at a time.

func resetAuditChain(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `TRUNCATE audit_log, audit_checkpoints RESTART IDENTITY`); err != nil {
		t.Fatalf("reset audit chain: %v", err)
	}
}

func TestAuditChainVerifiesAndDetectsTampering(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	for _, a := range []struct{ actor, action, device string }{
		{"admin", "command_issue", "device-1"},
		{"admin", "alert_status", "device-1"},
		{"viewer", "login", ""},
		{"admin", "command_issue", "device-2"},
		{"admin", "cert_revoke", "device-2"},
	} {
		if err := s.Audit(ctx, a.actor, a.action, a.device, map[string]any{"k": a.action}); err != nil {
			t.Fatalf("audit append: %v", err)
		}
	}

	if err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("freshly written chain should verify, got %v", err)
	}

	entries, err := s.ListAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 5 {
		t.Fatalf("want at least 5 chained entries, got %d", len(entries))
	}

	// Rewrite a row exactly as someone with database access would: change the
	// recorded actor and leave everything else, including the hashes, intact.
	target := entries[2]
	if _, err := s.pool.Exec(ctx,
		`UPDATE audit_log SET actor='not-the-real-actor' WHERE seq=$1`, target.Seq); err != nil {
		t.Fatal(err)
	}

	err = s.VerifyAuditChain(ctx)
	if err == nil {
		t.Fatal("an edited row must break the chain")
	}
	var te *auditchain.TamperError
	if !errors.As(err, &te) {
		t.Fatalf("want *auditchain.TamperError, got %T: %v", err, err)
	}
	if te.Seq != target.Seq {
		t.Errorf("break localised to entry %d, want %d", te.Seq, target.Seq)
	}
	t.Logf("detected: %v", err)
}

func TestAuditChainDetectsDeletedRow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	for i := 0; i < 4; i++ {
		if err := s.Audit(ctx, "admin", "command_issue", "device-1", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.ListAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	victim := entries[len(entries)-2]
	if _, err := s.pool.Exec(ctx, `DELETE FROM audit_log WHERE seq=$1`, victim.Seq); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAuditChain(ctx); err == nil {
		t.Fatal("a deleted row must break the chain")
	}
}

// The detail column is jsonb, which Postgres normalizes on input. The hash has
// to cover the stored rendering, or a row would fail to verify on read-back
// through no fault of an attacker.
func TestAuditChainSurvivesJSONBNormalization(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	detail := map[string]any{"zebra": 1, "alpha": "two", "nested": map[string]any{"b": true, "a": []int{3, 1, 2}}}
	if err := s.Audit(ctx, "admin", "command_issue", "device-1", detail); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("key reordering by jsonb must not break verification, got %v", err)
	}
}

func TestAuditCheckpointCoversTheChain(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sign.PublicKeyID(pub)

	if _, ok, err := s.AppendCheckpoint(ctx, priv, keyID); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("an empty chain has nothing to checkpoint")
	}

	for i := 0; i < 3; i++ {
		if err := s.Audit(ctx, "admin", "command_issue", "device-1", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}

	cp, ok, err := s.AppendCheckpoint(ctx, priv, keyID)
	if err != nil || !ok {
		t.Fatalf("AppendCheckpoint = %v, %v", ok, err)
	}
	if err := auditchain.VerifyCheckpoint(pub, cp); err != nil {
		t.Fatalf("checkpoint should verify: %v", err)
	}

	stored, ok, err := s.LatestCheckpoint(ctx)
	if err != nil || !ok {
		t.Fatalf("LatestCheckpoint = %v, %v", ok, err)
	}
	if stored.EntryHash != cp.EntryHash || stored.ThroughSeq != cp.ThroughSeq {
		t.Errorf("stored checkpoint %+v does not match %+v", stored, cp)
	}
	if err := auditchain.VerifyCheckpoint(pub, stored); err != nil {
		t.Fatalf("checkpoint must survive a round trip through Postgres: %v", err)
	}

	entries, err := s.ListAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditchain.VerifyAgainstCheckpoint(pub, auditchain.Genesis, entries, stored); err != nil {
		t.Fatalf("chain should match its signed checkpoint: %v", err)
	}

	// Truncating the tail leaves an internally consistent chain, which is
	// exactly what the checkpoint exists to catch.
	if err := auditchain.VerifyAgainstCheckpoint(pub, auditchain.Genesis, entries[:len(entries)-1], stored); err == nil {
		t.Fatal("truncation must be detected against the checkpoint")
	}
}

// Phase 1.1: the signature is retained and the stored row verifies on its own.
func TestCommandProofRoundTripAndVerifies(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	device := randID(t)

	dir := t.TempDir()
	key, err := sign.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}

	env := sign.Envelope{
		DeviceID:    device,
		CommandID:   randID(t),
		Type:        "isolate",
		IssuedUnix:  1789200000,
		ExpiresUnix: 1789200120,
		Payload:     []byte(`{"reason":"test"}`),
	}
	rec := cmdlog.Record{
		ID: env.CommandID, DeviceID: env.DeviceID, Hostname: "host-1", Type: env.Type,
		Payload: string(env.Payload), Status: "queued", Message: "queued",
		CreatedAt: "2026-09-15T08:00:00Z", UpdatedAt: "2026-09-15T08:00:00Z",
		Signature:    base64.StdEncoding.EncodeToString(key.Sign(env)),
		SigningKeyID: key.KeyID(), IssuedUnix: env.IssuedUnix, ExpiresUnix: env.ExpiresUnix,
		ActorIdentity: "shared-admin-token",
	}
	if err := s.AppendCommand(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListCommands(ctx, device)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 command, got %d", len(got))
	}
	stored := got[0]
	if stored.Signature != rec.Signature || stored.SigningKeyID != key.KeyID() {
		t.Fatalf("proof did not survive the round trip: %+v", stored)
	}
	if stored.ActorIdentity != "shared-admin-token" {
		t.Errorf("actor identity = %q", stored.ActorIdentity)
	}

	// Verify straight from the stored columns, rebuilding the canonical bytes
	// rather than trusting anything the server kept alongside them.
	if err := sign.VerifyStored(key.Public, stored.DeviceID, stored.ID, stored.Type,
		stored.IssuedUnix, stored.ExpiresUnix, []byte(stored.Payload), stored.Signature); err != nil {
		t.Fatalf("stored command should verify: %v", err)
	}

	// A payload edited in the database no longer matches the retained
	// signature, which is the whole point of keeping it.
	if _, err := s.pool.Exec(ctx, `UPDATE commands SET payload='{"reason":"tampered"}' WHERE id=$1`, rec.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.ListCommands(ctx, device)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.VerifyStored(key.Public, again[0].DeviceID, again[0].ID, again[0].Type,
		again[0].IssuedUnix, again[0].ExpiresUnix, []byte(again[0].Payload), again[0].Signature); err == nil {
		t.Fatal("an edited payload must fail signature verification")
	}
}

// Regression for the paging bypass: VerifyAuditChain used to read a single
// default 1000-row page, so anything past sequence 1000 was reported intact no
// matter what had been done to it. A database actor only had to wait out the
// first thousand events.
func TestVerifyAuditChainCoversBeyondOnePage(t *testing.T) {
	if testing.Short() {
		t.Skip("writes more than a page of audit entries")
	}
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	const total = auditChainPage + 25
	for i := 0; i < total; i++ {
		if err := s.Audit(ctx, "admin", "command_issue", "device-1", map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("an intact chain longer than one page should verify: %v", err)
	}

	// Tamper past the old cut-off. This previously went undetected.
	victim := int64(auditChainPage + 10)
	if _, err := s.pool.Exec(ctx,
		`UPDATE audit_log SET actor='not-the-real-actor' WHERE seq=$1`, victim); err != nil {
		t.Fatal(err)
	}

	err := s.VerifyAuditChain(ctx)
	if err == nil {
		t.Fatalf("tampering at sequence %d must be detected", victim)
	}
	var te *auditchain.TamperError
	if !errors.As(err, &te) {
		t.Fatalf("want *auditchain.TamperError, got %T: %v", err, err)
	}
	if te.Seq != victim {
		t.Errorf("break localised to entry %d, want %d", te.Seq, victim)
	}
	t.Logf("detected past the page boundary: %v", err)
}

// Regression for the export bypass: ExportEvidence reused ListCommands, which
// is hard-capped at 200 rows for console display, so a bundle silently omitted
// older commands while claiming to cover them.
func TestExportEvidenceDoesNotTruncateCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("writes more than the console command cap")
	}
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	key, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := randID(t)

	const total = 250 // above the 200-row console cap
	for i := 0; i < total; i++ {
		id := randID(t)
		env := sign.Envelope{
			DeviceID: device, CommandID: id, Type: "isolate",
			IssuedUnix: 1789200000, ExpiresUnix: 1789200120,
			Payload: []byte(`{"reason":"test"}`),
		}
		if err := s.AppendCommand(ctx, cmdlog.Record{
			ID: id, DeviceID: device, Hostname: "host", Type: env.Type,
			Payload: string(env.Payload), Status: "sent",
			CreatedAt: "2026-09-15T08:00:00Z", UpdatedAt: "2026-09-15T08:00:00Z",
			Signature:    base64.StdEncoding.EncodeToString(key.Sign(env)),
			SigningKeyID: key.KeyID(), IssuedUnix: env.IssuedUnix, ExpiresUnix: env.ExpiresUnix,
		}); err != nil {
			t.Fatal(err)
		}
	}

	b, err := s.ExportEvidence(ctx, string(key.PublicPEM()), "srv", "scope", device, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Commands) != total {
		t.Fatalf("bundle carries %d commands, want all %d — the export truncated", len(b.Commands), total)
	}
	if r := evidence.Verify(b); !r.OK() {
		t.Fatalf("exported bundle should verify: %+v", r.Checks)
	}
	if r := evidence.Verify(b); r.CommandsVerified != total {
		t.Errorf("verified %d commands, want %d", r.CommandsVerified, total)
	}
}

// A bundle exported from a chain longer than one page must carry the whole
// range, not a silently truncated prefix.
func TestExportEvidenceDoesNotTruncateAuditChain(t *testing.T) {
	if testing.Short() {
		t.Skip("writes more than a page of audit entries")
	}
	s := testStore(t)
	ctx := context.Background()
	resetAuditChain(t, s)

	key, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const total = auditChainPage + 15
	for i := 0; i < total; i++ {
		if err := s.Audit(ctx, "admin", "command_issue", "device-1", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, err := s.AppendCheckpoint(ctx, key.Private, key.KeyID()); err != nil || !ok {
		t.Fatalf("checkpoint: %v %v", ok, err)
	}

	b, err := s.ExportEvidence(ctx, string(key.PublicPEM()), "srv", "scope", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Audit) != total {
		t.Fatalf("bundle carries %d audit entries, want all %d", len(b.Audit), total)
	}
	// The checkpoint sits at the tip, so coverage must line up exactly.
	r := evidence.Verify(b)
	if !r.OK() {
		t.Fatalf("a full-range export should verify: %+v", r.Checks)
	}
}
