// Package evidence defines the portable proof bundle and verifies it.
//
// A bundle is everything an auditor or incident responder needs to check what
// DefendSec did, and nothing that requires trusting DefendSec to check it: the
// chained audit entries, the signed checkpoints, the retained command
// signatures, and the control public key they were signed under.
//
// Like internal/auditchain, this package depends only on the standard library
// and internal/auditchain and internal/sign. It must stay runnable with no
// server, no database and no network — a verifier that has to ask the system
// it is checking proves nothing.
package evidence

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"defendsec/internal/auditchain"
	"defendsec/internal/sign"
)

// FormatVersion identifies the bundle layout.
const FormatVersion = "defendsec-evidence-v1"

// Manifest describes the range a bundle covers.
type Manifest struct {
	FormatVersion string    `json:"formatVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Server        string    `json:"server,omitempty"`
	Scope         string    `json:"scope,omitempty"`

	// FromSeq and ThroughSeq bound the audit range. PrevHash is the entry
	// hash immediately before FromSeq, which is what lets a partial range be
	// verified without shipping the whole chain. It is empty when the bundle
	// starts at the beginning of the chain.
	FromSeq    int64  `json:"fromSeq"`
	ThroughSeq int64  `json:"throughSeq"`
	PrevHash   string `json:"prevHash"`
}

// CommandProof is a stored command together with the signature that
// authorised it. The canonical bytes are not carried: they rebuild from these
// fields, which is what makes the record self-verifying.
type CommandProof struct {
	ID            string `json:"id"`
	DeviceID      string `json:"deviceId"`
	Hostname      string `json:"hostname,omitempty"`
	Type          string `json:"type"`
	Payload       string `json:"payload"`
	Status        string `json:"status,omitempty"`
	Accepted      bool   `json:"accepted,omitempty"`
	ActorIdentity string `json:"actorIdentity,omitempty"`

	Signature    string `json:"signature"`
	SigningKeyID string `json:"signingKeyId"`
	IssuedUnix   int64  `json:"issuedUnix"`
	ExpiresUnix  int64  `json:"expiresUnix"`
}

// Bundle is the portable unit of proof.
type Bundle struct {
	Manifest            Manifest                `json:"manifest"`
	ControlPublicKeyPEM string                  `json:"controlPublicKeyPem"`
	Audit               []auditchain.Entry      `json:"audit"`
	Checkpoints         []auditchain.Checkpoint `json:"checkpoints"`
	Commands            []CommandProof          `json:"commands"`
}

// Write serialises a bundle.
func Write(w io.Writer, b *Bundle) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// Read parses a bundle.
func Read(r io.Reader) (*Bundle, error) {
	var b Bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if b.Manifest.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("unsupported bundle format %q, want %q", b.Manifest.FormatVersion, FormatVersion)
	}
	return &b, nil
}

// Check is one verification outcome.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Report is the result of verifying a bundle. Unattested counts matter as much
// as failures: a bundle that silently skips what it cannot check would be
// worse than useless to an assessor.
type Report struct {
	Checks []Check `json:"checks"`

	AuditEntries       int `json:"auditEntries"`
	CheckpointsChecked int `json:"checkpointsChecked"`
	CommandsVerified   int `json:"commandsVerified"`
	CommandsUnsigned   int `json:"commandsUnsigned"`
	CommandsFailed     int `json:"commandsFailed"`
}

// OK reports whether every check passed.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return true
}

func (r *Report) add(name string, ok bool, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
}

// Verify checks a bundle end to end using only its own contents.
func Verify(b *Bundle) Report {
	var rep Report
	rep.AuditEntries = len(b.Audit)

	pub, err := sign.ParsePublicPEM([]byte(b.ControlPublicKeyPEM))
	if err != nil {
		rep.add("control key", false, "cannot parse the control public key: %v", err)
		return rep
	}
	keyID := sign.PublicKeyID(pub)
	rep.add("control key", true, "Ed25519 public key %s", keyID)

	verifyAuditChain(b, &rep)
	verifyCheckpoints(b, pub, &rep)
	verifyCommands(b, pub, keyID, &rep)
	return rep
}

func verifyAuditChain(b *Bundle, rep *Report) {
	if len(b.Audit) == 0 {
		rep.add("audit chain", true, "no audit entries in this bundle")
		return
	}
	if err := auditchain.VerifyFrom(b.Manifest.PrevHash, b.Audit); err != nil {
		rep.add("audit chain", false, "%v", err)
		return
	}

	first, last := b.Audit[0], b.Audit[len(b.Audit)-1]
	if first.Seq != b.Manifest.FromSeq || last.Seq != b.Manifest.ThroughSeq {
		rep.add("audit chain", false,
			"entries cover %d-%d but the manifest claims %d-%d",
			first.Seq, last.Seq, b.Manifest.FromSeq, b.Manifest.ThroughSeq)
		return
	}
	rep.add("audit chain", true, "%d entries intact across sequence %d-%d", len(b.Audit), first.Seq, last.Seq)
}

func verifyCheckpoints(b *Bundle, pub ed25519.PublicKey, rep *Report) {
	if len(b.Checkpoints) == 0 {
		// Not a failure, but the bundle is weaker: without a checkpoint the
		// chain is only internally consistent, so a truncated tail cannot be
		// distinguished from a shorter log.
		rep.add("checkpoints", true, "none in this bundle; tail truncation is not detectable without one")
		return
	}

	byTip := make(map[int64]string, len(b.Audit))
	for _, e := range b.Audit {
		byTip[e.Seq] = e.EntryHash
	}

	for _, cp := range b.Checkpoints {
		if err := auditchain.VerifyCheckpoint(pub, cp); err != nil {
			rep.add("checkpoints", false, "%v", err)
			return
		}
		// A valid signature over a hash the entries do not reach means the
		// range was altered after the server committed to it.
		if hash, ok := byTip[cp.ThroughSeq]; ok && hash != cp.EntryHash {
			rep.add("checkpoints", false,
				"checkpoint %d attests hash %s but entry %d in this bundle hashes to %s",
				cp.ThroughSeq, short(cp.EntryHash), cp.ThroughSeq, short(hash))
			return
		}
		rep.CheckpointsChecked++
	}
	rep.add("checkpoints", true, "%d signed checkpoint(s) verified", rep.CheckpointsChecked)

	// Guard against a bundle that drops entries after its last checkpoint.
	if len(b.Audit) > 0 {
		highest := int64(0)
		for _, cp := range b.Checkpoints {
			if cp.ThroughSeq > highest {
				highest = cp.ThroughSeq
			}
		}
		if highest > b.Manifest.ThroughSeq {
			rep.add("coverage", false,
				"a checkpoint attests through sequence %d but the bundle stops at %d, so entries are missing",
				highest, b.Manifest.ThroughSeq)
			return
		}
	}
}

func verifyCommands(b *Bundle, pub ed25519.PublicKey, keyID string, rep *Report) {
	if len(b.Commands) == 0 {
		rep.add("command signatures", true, "no commands in this bundle")
		return
	}
	var failures []string
	var wrongKey int
	for _, c := range b.Commands {
		if c.Signature == "" {
			// Written before migration 005, so no proof was ever retained.
			// Counted rather than passed over.
			rep.CommandsUnsigned++
			continue
		}
		if c.SigningKeyID != "" && c.SigningKeyID != keyID {
			wrongKey++
			continue
		}
		if err := sign.VerifyStored(pub, c.DeviceID, c.ID, c.Type,
			c.IssuedUnix, c.ExpiresUnix, []byte(c.Payload), c.Signature); err != nil {
			rep.CommandsFailed++
			if len(failures) < 5 {
				failures = append(failures, fmt.Sprintf("%s (%s on %s)", c.ID, c.Type, c.DeviceID))
			}
			continue
		}
		rep.CommandsVerified++
	}

	if rep.CommandsFailed > 0 {
		rep.add("command signatures", false,
			"%d of %d commands do not match their retained signature: %v",
			rep.CommandsFailed, len(b.Commands), failures)
		return
	}
	detail := fmt.Sprintf("%d of %d commands verified", rep.CommandsVerified, len(b.Commands))
	if rep.CommandsUnsigned > 0 {
		detail += fmt.Sprintf("; %d carry no signature and cannot be attested", rep.CommandsUnsigned)
	}
	if wrongKey > 0 {
		detail += fmt.Sprintf("; %d were signed by a different control key and need its public half", wrongKey)
	}
	rep.add("command signatures", true, "%s", detail)
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
