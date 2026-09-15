package auditchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func buildChain(t *testing.T, n int) []Entry {
	t.Helper()
	base := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	var out []Entry
	prev := Genesis
	for i := 1; i <= n; i++ {
		e := Entry{
			Seq:      int64(i),
			At:       base.Add(time.Duration(i) * time.Minute),
			Actor:    "admin",
			Action:   "command_issue",
			DeviceID: "device-1",
			Detail:   `{"type":"isolate"}`,
		}
		e = Link(prev, e)
		prev = e.EntryHash
		out = append(out, e)
	}
	return out
}

func TestVerifyAcceptsIntactChain(t *testing.T) {
	if err := Verify(buildChain(t, 10)); err != nil {
		t.Fatalf("intact chain should verify, got %v", err)
	}
	if err := Verify(nil); err != nil {
		t.Fatalf("empty chain should verify, got %v", err)
	}
}

// The core claim of Phase 1.2: editing a stored row is detected, and the
// failure names the row.
func TestVerifyDetectsModifiedRow(t *testing.T) {
	mutations := map[string]func(*Entry){
		"actor":     func(e *Entry) { e.Actor = "someone-else" },
		"action":    func(e *Entry) { e.Action = "command_issue_benign" },
		"device":    func(e *Entry) { e.DeviceID = "device-2" },
		"detail":    func(e *Entry) { e.Detail = `{"type":"release"}` },
		"timestamp": func(e *Entry) { e.At = e.At.Add(-48 * time.Hour) },
		"sequence":  func(e *Entry) { e.Seq = 99 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			chain := buildChain(t, 10)
			mutate(&chain[4]) // entry with Seq 5

			err := Verify(chain)
			if err == nil {
				t.Fatal("a modified row must break the chain")
			}
			var te *TamperError
			if !errors.As(err, &te) {
				t.Fatalf("want *TamperError, got %T: %v", err, err)
			}
			// The break is localised to the edited row. Mutating the sequence
			// is caught one row earlier, as a gap.
			if te.Seq != 5 && te.Seq != 99 && te.Seq != 6 {
				t.Errorf("break reported at entry %d, want the edited row", te.Seq)
			}
		})
	}
}

func TestVerifyDetectsDeletedRow(t *testing.T) {
	chain := buildChain(t, 10)
	shortened := append(append([]Entry{}, chain[:4]...), chain[5:]...) // drop Seq 5

	err := Verify(shortened)
	if err == nil {
		t.Fatal("a deleted row must break the chain")
	}
	var te *TamperError
	if !errors.As(err, &te) {
		t.Fatalf("want *TamperError, got %T: %v", err, err)
	}
	if te.Seq != 6 {
		t.Errorf("break reported at entry %d, want 6 (the row after the deletion)", te.Seq)
	}
}

func TestVerifyDetectsReorderedRows(t *testing.T) {
	chain := buildChain(t, 10)
	chain[3], chain[4] = chain[4], chain[3]
	if err := Verify(chain); err == nil {
		t.Fatal("reordered rows must break the chain")
	}
}

// Re-chaining after an edit still fails, because the tail no longer matches
// what was there before. Without a checkpoint this only holds if the attacker
// cannot rewrite every later row; the checkpoint test below closes that gap.
func TestVerifyDetectsTruncation(t *testing.T) {
	chain := buildChain(t, 10)
	if err := Verify(chain[:6]); err != nil {
		t.Fatalf("a prefix is internally consistent on its own, got %v", err)
	}
	// It is only detectable against a checkpoint that covers the full range.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp := SignCheckpoint(priv, Checkpoint{
		ThroughSeq:   chain[9].Seq,
		EntryHash:    chain[9].EntryHash,
		At:           time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC),
		SigningKeyID: "test-key",
	})
	if err := VerifyAgainstCheckpoint(pub, Genesis, chain[:6], cp); err == nil {
		t.Fatal("truncation must be detected against a signed checkpoint")
	}
}

func TestVerifyFromRange(t *testing.T) {
	chain := buildChain(t, 10)
	if err := VerifyFrom(chain[3].EntryHash, chain[4:]); err != nil {
		t.Fatalf("a mid-chain range should verify against its predecessor, got %v", err)
	}
	if err := VerifyFrom("0000", chain[4:]); err == nil {
		t.Fatal("a range must not verify against the wrong predecessor")
	}
}

func TestVerifyRejectsChainNotStartingAtOne(t *testing.T) {
	if err := Verify(buildChain(t, 10)[2:]); err == nil {
		t.Fatal("Verify must require the chain to start at sequence 1")
	}
}

func TestCheckpointSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := buildChain(t, 5)
	cp := SignCheckpoint(priv, Checkpoint{
		ThroughSeq:   5,
		EntryHash:    chain[4].EntryHash,
		At:           time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC),
		SigningKeyID: "test-key",
	})

	if err := VerifyCheckpoint(pub, cp); err != nil {
		t.Fatalf("a freshly signed checkpoint should verify, got %v", err)
	}
	if err := VerifyAgainstCheckpoint(pub, Genesis, chain, cp); err != nil {
		t.Fatalf("chain should match its checkpoint, got %v", err)
	}

	tampered := cp
	tampered.ThroughSeq = 4
	if err := VerifyCheckpoint(pub, tampered); err == nil {
		t.Error("an edited checkpoint must not verify")
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpoint(otherPub, cp); err == nil {
		t.Error("a checkpoint must not verify under the wrong key")
	}

	cp.Signature = "not base64!!"
	if err := VerifyCheckpoint(pub, cp); err == nil {
		t.Error("a malformed signature must not verify")
	}
}

// Length prefixing means no combination of field contents can be rearranged
// into the same byte stream as a different combination.
func TestCanonicalIsUnambiguous(t *testing.T) {
	at := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	a := Entry{Seq: 1, At: at, Actor: "ab", Action: "c", DeviceID: "d", Detail: "{}"}
	b := Entry{Seq: 1, At: at, Actor: "a", Action: "bc", DeviceID: "d", Detail: "{}"}
	if ComputeHash(Genesis, a) == ComputeHash(Genesis, b) {
		t.Error("field boundaries must be unambiguous")
	}

	// A field containing the delimiter must not be able to forge one either.
	c := Entry{Seq: 1, At: at, Actor: "a\n1:b", Action: "", DeviceID: "d", Detail: "{}"}
	d := Entry{Seq: 1, At: at, Actor: "a", Action: "b", DeviceID: "d", Detail: "{}"}
	if ComputeHash(Genesis, c) == ComputeHash(Genesis, d) {
		t.Error("embedded delimiters must not forge a field boundary")
	}
}

func TestSameContentDifferentPositionHashesDifferently(t *testing.T) {
	chain := buildChain(t, 3)
	// Entries 1..3 carry identical payloads; only Seq, At and the chain
	// position differ, and each hash must still be distinct.
	seen := map[string]bool{}
	for _, e := range chain {
		if seen[e.EntryHash] {
			t.Fatal("identical payloads at different positions must hash differently")
		}
		seen[e.EntryHash] = true
	}
}

// Regression: a valid checkpoint presented with no entries must fail. Wiping
// audit_log while leaving audit_checkpoints in place is precisely the attack
// checkpoints exist to catch, and returning success there made the control
// worthless against a database actor.
func TestVerifyAgainstCheckpointRejectsEmptyRange(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := buildChain(t, 5)
	cp := SignCheckpoint(priv, Checkpoint{
		ThroughSeq:   chain[4].Seq,
		EntryHash:    chain[4].EntryHash,
		At:           time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC),
		SigningKeyID: "test-key",
	})

	err = VerifyAgainstCheckpoint(pub, Genesis, nil, cp)
	if err == nil {
		t.Fatal("a wiped chain must not verify against a still-valid checkpoint")
	}
	var te *TamperError
	if !errors.As(err, &te) {
		t.Fatalf("want *TamperError, got %T: %v", err, err)
	}
	if te.Seq != cp.ThroughSeq {
		t.Errorf("failure should name the attested sequence %d, got %d", cp.ThroughSeq, te.Seq)
	}

	if err := VerifyAgainstCheckpoint(pub, Genesis, []Entry{}, cp); err == nil {
		t.Fatal("an empty (non-nil) slice must fail the same way")
	}
}
