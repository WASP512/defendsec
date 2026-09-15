// Package auditchain turns the audit log into a tamper-evident sequence.
//
// Each entry carries the hash of the entry before it, so any edit, deletion or
// reordering breaks the chain at that point and at every point after it. A
// checkpoint signed by the control key lets a verifier validate a whole range
// from a single signature.
//
// The package deliberately depends on nothing but the standard library. The
// offline verifier (roadmap 1.4) has to reach the same conclusions without a
// database, a server, or any of this project's other packages — a verifier
// that trusts the system it is checking proves nothing.
package auditchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Domain separates audit hashing from every other hash this project computes.
const Domain = "defendsec-audit-v1"

// checkpointDomain separates checkpoint signatures from command signatures,
// which use their own domain in internal/sign.
const checkpointDomain = "defendsec-audit-checkpoint-v1"

// Genesis is the previous-hash value of the first entry in a chain.
const Genesis = ""

// Entry is one audit record. Seq is dense and starts at 1; the chain relies on
// that to detect a deleted row rather than merely a modified one.
type Entry struct {
	Seq      int64
	At       time.Time
	Actor    string
	Action   string
	DeviceID string
	Detail   string // JSON, stored verbatim so the hash covers exactly what is kept

	PrevHash  string
	EntryHash string
}

// writeField length-prefixes a value so that no combination of field contents
// can produce the same byte stream as a different combination.
func writeField(b *bytes.Buffer, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
	b.WriteByte('\n')
}

// Canonical renders the hashed form of an entry. It covers the sequence
// number and timestamp as well as the payload, so a row cannot be moved or
// back-dated without detection.
func Canonical(e Entry) []byte {
	var b bytes.Buffer
	b.WriteString(Domain)
	b.WriteByte('\n')
	writeField(&b, strconv.FormatInt(e.Seq, 10))
	writeField(&b, e.At.UTC().Format(time.RFC3339Nano))
	writeField(&b, e.Actor)
	writeField(&b, e.Action)
	writeField(&b, e.DeviceID)
	writeField(&b, e.Detail)
	return b.Bytes()
}

// ComputeHash returns the entry hash that chains e onto prevHash.
func ComputeHash(prevHash string, e Entry) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(Canonical(e))
	return hex.EncodeToString(h.Sum(nil))
}

// Link fills in PrevHash and EntryHash for an entry being appended after
// prevHash.
func Link(prevHash string, e Entry) Entry {
	e.PrevHash = prevHash
	e.EntryHash = ComputeHash(prevHash, e)
	return e
}

// TamperError localises a break in the chain. It names the entry where
// verification failed so an operator or assessor can go straight to it.
type TamperError struct {
	Seq    int64
	Actor  string
	Action string
	At     time.Time
	Reason string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("audit chain broken at entry %d (%s by %s at %s): %s",
		e.Seq, e.Action, e.Actor, e.At.UTC().Format(time.RFC3339), e.Reason)
}

// VerifyFrom checks a contiguous range of entries that follows prevHash.
// Entries must be ordered by sequence.
func VerifyFrom(prevHash string, entries []Entry) error {
	prev := prevHash
	var last int64
	for i, e := range entries {
		if i > 0 && e.Seq != last+1 {
			return &TamperError{
				Seq: e.Seq, Actor: e.Actor, Action: e.Action, At: e.At,
				Reason: fmt.Sprintf("sequence jumped from %d, so an entry was removed", last),
			}
		}
		if e.PrevHash != prev {
			return &TamperError{
				Seq: e.Seq, Actor: e.Actor, Action: e.Action, At: e.At,
				Reason: "previous hash does not match the entry before it",
			}
		}
		if want := ComputeHash(prev, e); e.EntryHash != want {
			return &TamperError{
				Seq: e.Seq, Actor: e.Actor, Action: e.Action, At: e.At,
				Reason: "entry hash does not match its contents, so the row was modified",
			}
		}
		prev = e.EntryHash
		last = e.Seq
	}
	return nil
}

// Verify checks a chain from its beginning. Use VerifyFrom to check a range
// that starts partway through.
func Verify(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if entries[0].Seq != 1 {
		return &TamperError{
			Seq: entries[0].Seq, Actor: entries[0].Actor, Action: entries[0].Action, At: entries[0].At,
			Reason: "chain does not start at sequence 1",
		}
	}
	return VerifyFrom(Genesis, entries)
}

// Checkpoint attests that the chain held through ThroughSeq, so a verifier can
// validate that much of the log from one signature.
type Checkpoint struct {
	ThroughSeq   int64
	EntryHash    string
	At           time.Time
	SigningKeyID string
	Signature    string // base64
}

// CanonicalCheckpoint renders the signed form of a checkpoint.
func CanonicalCheckpoint(c Checkpoint) []byte {
	var b bytes.Buffer
	b.WriteString(checkpointDomain)
	b.WriteByte('\n')
	writeField(&b, strconv.FormatInt(c.ThroughSeq, 10))
	writeField(&b, c.EntryHash)
	writeField(&b, c.At.UTC().Format(time.RFC3339Nano))
	writeField(&b, c.SigningKeyID)
	return b.Bytes()
}

// SignCheckpoint returns c with its Signature populated.
func SignCheckpoint(priv ed25519.PrivateKey, c Checkpoint) Checkpoint {
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, CanonicalCheckpoint(c)))
	return c
}

// VerifyCheckpoint checks a checkpoint signature against the control key.
func VerifyCheckpoint(pub ed25519.PublicKey, c Checkpoint) error {
	raw, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("checkpoint %d: signature is not valid base64: %w", c.ThroughSeq, err)
	}
	if !ed25519.Verify(pub, CanonicalCheckpoint(c), raw) {
		return fmt.Errorf("checkpoint %d: signature does not verify", c.ThroughSeq)
	}
	return nil
}

// VerifyAgainstCheckpoint checks entries and confirms they arrive at the state
// the signed checkpoint attests to. This is the combination an assessor cares
// about: the rows are internally consistent *and* they match what the server
// committed to at the time.
func VerifyAgainstCheckpoint(pub ed25519.PublicKey, prevHash string, entries []Entry, c Checkpoint) error {
	if err := VerifyCheckpoint(pub, c); err != nil {
		return err
	}
	if err := VerifyFrom(prevHash, entries); err != nil {
		return err
	}
	// An empty range can never reach a checkpoint. Treating it as a match
	// would pass exactly the wholesale deletion that checkpoints exist to
	// catch: wipe audit_log, leave audit_checkpoints, and every signature
	// still verifies against nothing.
	if len(entries) == 0 {
		return &TamperError{
			Seq:    c.ThroughSeq,
			At:     c.At,
			Reason: fmt.Sprintf("checkpoint attests the chain through sequence %d, but no entries were supplied", c.ThroughSeq),
		}
	}
	last := entries[len(entries)-1]
	if last.Seq != c.ThroughSeq {
		return fmt.Errorf("checkpoint covers sequence %d but the range ends at %d", c.ThroughSeq, last.Seq)
	}
	if last.EntryHash != c.EntryHash {
		return &TamperError{
			Seq: last.Seq, Actor: last.Actor, Action: last.Action, At: last.At,
			Reason: "range does not reach the hash the signed checkpoint attests to",
		}
	}
	return nil
}
