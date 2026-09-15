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
	"strings"
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
	// Message is the result the endpoint reported. The acknowledgement
	// signature covers its hash, so without the text itself a reader would be
	// checking a digest whose preimage they do not have — and anyone able to
	// edit the stored message could change what an assessor reads without
	// breaking verification.
	Message string `json:"message,omitempty"`

	Signature    string `json:"signature"`
	SigningKeyID string `json:"signingKeyId"`
	IssuedUnix   int64  `json:"issuedUnix"`
	ExpiresUnix  int64  `json:"expiresUnix"`

	// The endpoint's signed claim that it ran the command. Without these the
	// bundle can prove what was authorised but not what was carried out.
	AckSignature    string `json:"ackSignature,omitempty"`
	AckResultHash   string `json:"ackResultHash,omitempty"`
	AckExecutedUnix int64  `json:"ackExecutedUnix,omitempty"`
}

// Bundle is the portable unit of proof.
type Bundle struct {
	Manifest            Manifest `json:"manifest"`
	ControlPublicKeyPEM string   `json:"controlPublicKeyPem"`
	// AgentPublicKeys maps device id to the PEM public half of that device's
	// enrolled certificate key, so acknowledgement signatures verify without
	// the agent or the server being reachable.
	AgentPublicKeys map[string]string `json:"agentPublicKeys,omitempty"`

	Audit       []auditchain.Entry      `json:"audit"`
	Checkpoints []auditchain.Checkpoint `json:"checkpoints"`
	Commands    []CommandProof          `json:"commands"`

	// Compliance is present when the bundle was scoped to a control or a
	// framework (roadmap 1.9). It is partly verifiable and says so; see
	// compliance.go for exactly which part.
	Compliance *ComplianceScope `json:"compliance,omitempty"`
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

	AcksVerified   int `json:"acksVerified"`
	AcksUnattested int `json:"acksUnattested"`
	AcksFailed     int `json:"acksFailed"`

	// ComplianceControls is how many controls a scoped bundle asserts. Zero
	// means the bundle carries no assessment, not that it passed one.
	ComplianceControls int `json:"complianceControls"`
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
	verifyAcks(b, &rep)
	verifyComplianceScope(b, &rep)
	return rep
}

// verifyComplianceScope reports on a scoped bundle's assessment: the part that
// can be recomputed is checked, and the part that cannot is named. A reader
// must never be left to assume the whole section carries the chain's weight.
func verifyComplianceScope(b *Bundle, rep *Report) {
	if b.Compliance == nil {
		return
	}
	rep.ComplianceControls = len(b.Compliance.Controls)

	if problems := b.verifyCompliance(); len(problems) > 0 {
		rep.add("compliance assessment", false, "%s", strings.Join(problems, "; "))
		return
	}
	rep.add("compliance assessment", true,
		"%d controls for %s over %s..%s; audit-entry counts recomputed from the chain and matched. "+
			"Alert and command counts are derived from records outside the chain and are not verified here.",
		len(b.Compliance.Controls), b.Compliance.FrameworkTitle,
		b.Compliance.From.Format("2006-01-02"), b.Compliance.To.Format("2006-01-02"))
}

// verifyAcks checks each endpoint's signed claim that it executed a command.
// A command whose authorisation verifies still tells you only what was
// ordered; this is what separates that from what was done.
func verifyAcks(b *Bundle, rep *Report) {
	var acked int
	var failures []string
	for _, c := range b.Commands {
		// A record claiming execution counts even with no proof attached.
		// Legacy agents and pre-migration rows still say "acked", and skipping
		// them would show an assessor a clean result while leaving those
		// execution claims silently unattestable.
		claimsExecution := c.AckSignature != "" || c.AckExecutedUnix != 0 ||
			strings.EqualFold(strings.TrimSpace(c.Status), "acked")
		if !claimsExecution {
			continue
		}
		acked++

		pubPEM := b.AgentPublicKeys[c.DeviceID]
		if c.AckSignature == "" || pubPEM == "" {
			rep.AcksUnattested++
			continue
		}
		// The signature covers the result hash, so the hash has to be checked
		// against the result actually carried here. Otherwise the proof is
		// vacuous: a valid signature over a digest of text nobody can see.
		if sign.HashResult(c.Message) != c.AckResultHash {
			rep.AcksFailed++
			if len(failures) < 5 {
				failures = append(failures, fmt.Sprintf("%s (%s on %s: reported result does not match the signed hash)",
					c.ID, c.Type, c.DeviceID))
			}
			continue
		}
		if err := sign.VerifyAckStored(pubPEM, c.ID, c.DeviceID, c.Accepted,
			c.AckResultHash, c.AckExecutedUnix, c.AckSignature); err != nil {
			rep.AcksFailed++
			if len(failures) < 5 {
				failures = append(failures, fmt.Sprintf("%s (%s on %s)", c.ID, c.Type, c.DeviceID))
			}
			continue
		}
		rep.AcksVerified++
	}

	if acked == 0 {
		rep.add("acknowledgements", true, "no acknowledged commands in this bundle")
		return
	}
	if rep.AcksFailed > 0 {
		rep.add("acknowledgements", false,
			"%d of %d acknowledgements do not match their signature: %v",
			rep.AcksFailed, acked, failures)
		return
	}
	detail := fmt.Sprintf("%d of %d acknowledgements verified", rep.AcksVerified, acked)
	if rep.AcksUnattested > 0 {
		detail += fmt.Sprintf("; %d carry no signature or no enrolled key and cannot be attested", rep.AcksUnattested)
	}
	rep.add("acknowledgements", true, "%s", detail)
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
		// A checkpoint is only evidence if the entries it attests are here to
		// compare against. Accepting one whose sequence is absent would pass
		// the wholesale-deletion case checkpoints exist to catch: drop every
		// audit row, keep the checkpoints, and each signature still verifies
		// against nothing.
		hash, present := byTip[cp.ThroughSeq]
		if !present {
			rep.add("checkpoints", false,
				"checkpoint attests the chain through sequence %d, but no entry with that sequence is in this bundle",
				cp.ThroughSeq)
			return
		}
		if hash != cp.EntryHash {
			rep.add("checkpoints", false,
				"checkpoint %d attests hash %s but entry %d in this bundle hashes to %s",
				cp.ThroughSeq, short(cp.EntryHash), cp.ThroughSeq, short(hash))
			return
		}
		rep.CheckpointsChecked++
	}
	rep.add("checkpoints", true, "%d signed checkpoint(s) verified against the entries present", rep.CheckpointsChecked)

	// Guard against a bundle that drops entries after its last checkpoint.
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
