package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"defendsec/internal/auditchain"
	"defendsec/internal/sign"
)

func testBundle(t *testing.T) (*Bundle, *sign.Key) {
	t.Helper()
	key, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	var entries []auditchain.Entry
	prev := auditchain.Genesis
	for i := 1; i <= 6; i++ {
		e := auditchain.Link(prev, auditchain.Entry{
			Seq: int64(i), At: base.Add(time.Duration(i) * time.Minute),
			Actor: "admin", Action: "command_issue", DeviceID: "device-1",
			Detail: `{"type": "isolate"}`,
		})
		prev = e.EntryHash
		entries = append(entries, e)
	}

	cp := auditchain.SignCheckpoint(key.Private, auditchain.Checkpoint{
		ThroughSeq:   entries[len(entries)-1].Seq,
		EntryHash:    entries[len(entries)-1].EntryHash,
		At:           base.Add(time.Hour),
		SigningKeyID: key.KeyID(),
	})

	env := sign.Envelope{
		DeviceID: "device-1", CommandID: "cmd-1", Type: "isolate",
		IssuedUnix: 1789200000, ExpiresUnix: 1789200120,
		Payload: []byte(`{"reason":"test"}`),
	}
	cmd := CommandProof{
		ID: env.CommandID, DeviceID: env.DeviceID, Hostname: "host-1", Type: env.Type,
		Payload: string(env.Payload), Status: "sent", ActorIdentity: "shared-admin-token",
		Signature:    base64.StdEncoding.EncodeToString(key.Sign(env)),
		SigningKeyID: key.KeyID(), IssuedUnix: env.IssuedUnix, ExpiresUnix: env.ExpiresUnix,
	}

	return &Bundle{
		Manifest: Manifest{
			FormatVersion: FormatVersion, GeneratedAt: base.Add(2 * time.Hour),
			Server: "defendsec.example", Scope: "device-1",
			FromSeq: 1, ThroughSeq: 6, PrevHash: auditchain.Genesis,
		},
		ControlPublicKeyPEM: string(key.PublicPEM()),
		Audit:               entries,
		Checkpoints:         []auditchain.Checkpoint{cp},
		Commands:            []CommandProof{cmd},
	}, key
}

func failing(t *testing.T, r Report) Check {
	t.Helper()
	for _, c := range r.Checks {
		if !c.OK {
			return c
		}
	}
	t.Fatalf("expected a failing check, got %+v", r.Checks)
	return Check{}
}

func TestVerifyAcceptsIntactBundle(t *testing.T) {
	b, _ := testBundle(t)
	r := Verify(b)
	if !r.OK() {
		t.Fatalf("intact bundle should verify: %+v", failing(t, r))
	}
	if r.AuditEntries != 6 || r.CheckpointsChecked != 1 || r.CommandsVerified != 1 {
		t.Errorf("unexpected counts: %+v", r)
	}
}

func TestBundleSurvivesJSONRoundTrip(t *testing.T) {
	b, _ := testBundle(t)
	var buf bytes.Buffer
	if err := Write(&buf, b); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	// Timestamps are part of the hashed form, so a round trip that loses
	// precision would break verification.
	if r := Verify(got); !r.OK() {
		t.Fatalf("bundle should verify after a round trip: %+v", failing(t, r))
	}
}

func TestVerifyDetectsEditedAuditEntry(t *testing.T) {
	b, _ := testBundle(t)
	b.Audit[3].Actor = "someone-else"

	r := Verify(b)
	if r.OK() {
		t.Fatal("an edited audit entry must fail verification")
	}
	c := failing(t, r)
	if c.Name != "audit chain" || !strings.Contains(c.Detail, "entry 4") {
		t.Errorf("failure should localise to entry 4, got %+v", c)
	}
}

// Rewriting an entry and re-chaining every entry after it leaves a
// self-consistent chain. The signed checkpoint is what catches it.
func TestVerifyDetectsRechainedTail(t *testing.T) {
	b, _ := testBundle(t)
	b.Audit[3].Actor = "someone-else"
	prev := b.Audit[2].EntryHash
	for i := 3; i < len(b.Audit); i++ {
		b.Audit[i] = auditchain.Link(prev, b.Audit[i])
		prev = b.Audit[i].EntryHash
	}

	if err := auditchain.VerifyFrom(b.Manifest.PrevHash, b.Audit); err != nil {
		t.Fatalf("the rewritten chain is internally consistent by construction: %v", err)
	}
	r := Verify(b)
	if r.OK() {
		t.Fatal("the checkpoint must catch a rewritten tail")
	}
	if c := failing(t, r); c.Name != "checkpoints" {
		t.Errorf("want the checkpoint check to fail, got %+v", c)
	}
}

func TestVerifyDetectsTruncatedTail(t *testing.T) {
	b, _ := testBundle(t)
	b.Audit = b.Audit[:4]
	b.Manifest.ThroughSeq = 4

	r := Verify(b)
	if r.OK() {
		t.Fatal("dropping entries the checkpoint covers must fail")
	}
	// The checkpoint check now catches this first and more precisely: the
	// attested sequence is simply not present. Either integrity check is a
	// correct place to fail, so long as it fails.
	c := failing(t, r)
	if c.Name != "checkpoints" && c.Name != "coverage" {
		t.Errorf("want an integrity check to fail, got %+v", c)
	}
	if !strings.Contains(c.Detail, "6") {
		t.Errorf("failure should name the attested sequence, got %q", c.Detail)
	}
}

// Regression for the wholesale-deletion bypass: dropping every audit entry
// while leaving the signed checkpoints in place must not verify. Each
// signature still checks out on its own, so the only thing standing between
// an assessor and a false pass is requiring the attested entries to be here.
func TestVerifyDetectsWipedAuditLogWithCheckpointsIntact(t *testing.T) {
	b, _ := testBundle(t)
	b.Audit = nil
	b.Manifest.FromSeq = 0
	b.Manifest.ThroughSeq = 0

	r := Verify(b)
	if r.OK() {
		t.Fatal("a wiped audit log with checkpoints intact must not verify")
	}
	c := failing(t, r)
	if c.Name != "checkpoints" {
		t.Errorf("want the checkpoints check to fail, got %+v", c)
	}
}

// The same wipe, but with the checkpoints dropped too. There is then nothing
// left attesting the log existed, which is exactly why a bundle without
// checkpoints is reported as weaker rather than as proof.
func TestBundleWithoutCheckpointsSaysSo(t *testing.T) {
	b, _ := testBundle(t)
	b.Checkpoints = nil

	r := Verify(b)
	if !r.OK() {
		t.Fatalf("a bundle with no checkpoints is not itself a failure: %+v", failing(t, r))
	}
	var detail string
	for _, c := range r.Checks {
		if c.Name == "checkpoints" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "not detectable") {
		t.Errorf("the weaker guarantee must be stated, got %q", detail)
	}
}

func TestVerifyDetectsManifestRangeMismatch(t *testing.T) {
	b, _ := testBundle(t)
	b.Manifest.ThroughSeq = 99

	r := Verify(b)
	if r.OK() {
		t.Fatal("a manifest that misstates its range must fail")
	}
	if c := failing(t, r); c.Name != "audit chain" {
		t.Errorf("want the audit chain check to fail, got %+v", c)
	}
}

func TestVerifyDetectsEditedCommandPayload(t *testing.T) {
	b, _ := testBundle(t)
	b.Commands[0].Payload = `{"reason":"tampered"}`

	r := Verify(b)
	if r.OK() {
		t.Fatal("an edited command payload must fail verification")
	}
	c := failing(t, r)
	if c.Name != "command signatures" || !strings.Contains(c.Detail, "cmd-1") {
		t.Errorf("failure should name the command, got %+v", c)
	}
}

// Swapping in an attacker's key must not let a re-signed bundle pass: the
// bundle carries the key it claims, so the check is only meaningful against a
// key the verifier already trusts. Surfacing the fingerprint is what makes
// that comparison possible.
func TestVerifyReportsTheKeyFingerprint(t *testing.T) {
	b, key := testBundle(t)
	r := Verify(b)
	var detail string
	for _, c := range r.Checks {
		if c.Name == "control key" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, key.KeyID()) {
		t.Errorf("control key check should report the fingerprint %s, got %q", key.KeyID(), detail)
	}
}

func TestVerifyCountsUnsignedCommands(t *testing.T) {
	b, _ := testBundle(t)
	b.Commands = append(b.Commands, CommandProof{
		ID: "legacy-1", DeviceID: "device-1", Type: "isolate", Payload: "{}",
	})

	r := Verify(b)
	if !r.OK() {
		t.Fatalf("an unsigned legacy row is not a failure: %+v", failing(t, r))
	}
	if r.CommandsUnsigned != 1 {
		t.Errorf("unsigned commands = %d, want 1", r.CommandsUnsigned)
	}
	var detail string
	for _, c := range r.Checks {
		if c.Name == "command signatures" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "cannot be attested") {
		t.Errorf("an unsigned row must be reported, not passed over silently: %q", detail)
	}
}

func TestVerifyRejectsBadControlKey(t *testing.T) {
	b, _ := testBundle(t)
	b.ControlPublicKeyPEM = "not a pem"
	if Verify(b).OK() {
		t.Fatal("an unparseable control key must fail")
	}
}

func TestReadRejectsUnknownFormat(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"manifest":{"formatVersion":"something-else"}}`)); err == nil {
		t.Fatal("an unknown bundle format must be rejected")
	}
}

// --- Phase 1.3: acknowledgement proof -----------------------------------

// withAck returns the fixture bundle with a signed acknowledgement attached,
// plus the agent key that signed it.
func withAck(t *testing.T) (*Bundle, *ecdsa.PrivateKey) {
	t.Helper()
	b, _ := testBundle(t)
	agent, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &b.Commands[0]
	c.Accepted = true
	c.Message = "isolated"
	c.AckResultHash = sign.HashResult("isolated")
	c.AckExecutedUnix = 1789200030
	sig, err := sign.SignAck(agent, sign.AckEnvelope{
		CommandID: c.ID, DeviceID: c.DeviceID, Accepted: c.Accepted,
		ResultHash: c.AckResultHash, ExecutedUnix: c.AckExecutedUnix,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.AckSignature = base64.StdEncoding.EncodeToString(sig)

	pemBytes, err := sign.ECDSAPublicPEM(&agent.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b.AgentPublicKeys = map[string]string{c.DeviceID: string(pemBytes)}
	return b, agent
}

func TestVerifyAcceptsSignedAcknowledgement(t *testing.T) {
	b, _ := withAck(t)
	r := Verify(b)
	if !r.OK() {
		t.Fatalf("a signed acknowledgement should verify: %+v", failing(t, r))
	}
	if r.AcksVerified != 1 || r.AcksUnattested != 0 {
		t.Errorf("unexpected ack counts: %+v", r)
	}
}

func TestVerifyDetectsEditedAcknowledgementResult(t *testing.T) {
	b, _ := withAck(t)
	// Rewrite what the endpoint reported, as someone with database access would.
	b.Commands[0].AckResultHash = sign.HashResult("nothing happened")

	r := Verify(b)
	if r.OK() {
		t.Fatal("an edited acknowledgement result must fail verification")
	}
	if c := failing(t, r); c.Name != "acknowledgements" {
		t.Errorf("want the acknowledgements check to fail, got %+v", c)
	}
}

// Flipping accepted is the interesting forgery: it turns a refusal into a
// success without touching anything else.
func TestVerifyDetectsFlippedAcceptance(t *testing.T) {
	b, _ := withAck(t)
	b.Commands[0].Accepted = false
	if Verify(b).OK() {
		t.Fatal("flipping the accepted flag must fail verification")
	}
}

func TestVerifyDetectsAcknowledgementFromWrongAgent(t *testing.T) {
	b, _ := withAck(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := sign.ECDSAPublicPEM(&other.PublicKey)
	b.AgentPublicKeys[b.Commands[0].DeviceID] = string(pemBytes)

	if Verify(b).OK() {
		t.Fatal("an acknowledgement must not verify under another device's key")
	}
}

// An agent that predates signed acknowledgements, or a device enrolled before
// its key was retained, is counted as unattested rather than passed over or
// treated as a failure.
func TestVerifyCountsUnattestedAcknowledgements(t *testing.T) {
	b, _ := withAck(t)
	b.AgentPublicKeys = nil

	r := Verify(b)
	if !r.OK() {
		t.Fatalf("a missing agent key is not a verification failure: %+v", failing(t, r))
	}
	if r.AcksUnattested != 1 || r.AcksVerified != 0 {
		t.Errorf("unexpected ack counts: %+v", r)
	}
	var detail string
	for _, c := range r.Checks {
		if c.Name == "acknowledgements" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "cannot be attested") {
		t.Errorf("unattested acknowledgements must be reported: %q", detail)
	}
}

func TestAcknowledgementSurvivesJSONRoundTrip(t *testing.T) {
	b, _ := withAck(t)
	var buf bytes.Buffer
	if err := Write(&buf, b); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	r := Verify(got)
	if !r.OK() || r.AcksVerified != 1 {
		t.Fatalf("acknowledgement must survive a round trip: %+v", r)
	}
}

// Regression: the acknowledgement signature covers a hash of the result, so
// the result text has to travel with it and be checked. Otherwise anyone able
// to edit commands.message changes what an assessor reads while verification
// still passes — the bundle would confirm a digest whose preimage nobody has.
func TestVerifyDetectsResultTextNotMatchingSignedHash(t *testing.T) {
	b, _ := withAck(t)
	b.Commands[0].Message = "isolated"
	if r := Verify(b); !r.OK() {
		t.Fatalf("matching result text should verify: %+v", failing(t, r))
	}

	b.Commands[0].Message = "nothing happened"
	r := Verify(b)
	if r.OK() {
		t.Fatal("a result that does not match the signed hash must fail")
	}
	c := failing(t, r)
	if c.Name != "acknowledgements" || !strings.Contains(c.Detail, "does not match the signed hash") {
		t.Errorf("failure should name the mismatch, got %+v", c)
	}
}

// Regression: a legacy row that claims execution without proof must be
// counted as unattested, not skipped as if it were never acknowledged.
func TestVerifyCountsLegacyAckedCommandsAsUnattested(t *testing.T) {
	b, _ := testBundle(t)
	b.Commands[0].Status = "acked"
	b.Commands[0].Accepted = true
	// No AckSignature, no AckExecutedUnix — exactly what a pre-1.3 agent leaves.

	r := Verify(b)
	if !r.OK() {
		t.Fatalf("a legacy acknowledgement is not a verification failure: %+v", failing(t, r))
	}
	if r.AcksUnattested != 1 {
		t.Fatalf("unattested acknowledgements = %d, want 1 — a claim of execution was skipped", r.AcksUnattested)
	}
	var detail string
	for _, c := range r.Checks {
		if c.Name == "acknowledgements" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "cannot be attested") {
		t.Errorf("the unattestable claim must be reported, got %q", detail)
	}
}

// A scoped bundle's assessment must not become an unverifiable claim sitting
// beside verifiable ones. The audit-entry half is recomputed from the chain;
// editing the summary alone must be caught.
func scopedBundle(t *testing.T) *Bundle {
	t.Helper()
	b, _ := testBundle(t)

	from := b.Audit[0].At.Add(-time.Second)
	to := b.Audit[len(b.Audit)-1].At.Add(time.Second)

	counts := b.auditCountsByControl(from, to)
	var summaries []ControlSummary
	for id, n := range counts {
		summaries = append(summaries, ControlSummary{
			ID: id, Title: "t", Coverage: "evidenced", Status: "satisfied",
			Statement: "held", AuditEntries: n,
		})
	}
	SortControlSummaries(summaries)

	b.Compliance = &ComplianceScope{
		Framework: "cis-v8", FrameworkTitle: "CIS Controls v8",
		From: from, To: to, Controls: summaries,
		Provenance: ComplianceProvenance,
	}
	return b
}

func TestScopedBundleVerifies(t *testing.T) {
	b := scopedBundle(t)
	if len(b.Compliance.Controls) == 0 {
		t.Fatal("the fixture produced no control summaries; the audit actions are untagged")
	}
	rep := Verify(b)
	if !rep.OK() {
		t.Fatalf("scoped bundle failed: %+v", rep.Checks)
	}
	if rep.ComplianceControls != len(b.Compliance.Controls) {
		t.Errorf("reported %d controls, bundle has %d", rep.ComplianceControls, len(b.Compliance.Controls))
	}

	// The report must say plainly which half is not verified, or a reader
	// will take the whole section as proven.
	var detail string
	for _, c := range rep.Checks {
		if c.Name == "compliance assessment" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "not verified") {
		t.Errorf("the report does not disclose the unverified half: %q", detail)
	}
}

func TestScopedBundleDetectsInflatedCounts(t *testing.T) {
	b := scopedBundle(t)
	b.Compliance.Controls[0].AuditEntries += 7
	rep := Verify(b)
	if rep.OK() {
		t.Fatal("an inflated audit-entry count verified")
	}
}

// Editing the provenance note is an attempt to present derived numbers as
// proven ones, and must fail.
func TestScopedBundleDetectsEditedProvenance(t *testing.T) {
	b := scopedBundle(t)
	b.Compliance.Provenance = "Everything in this bundle is cryptographically verified."
	if Verify(b).OK() {
		t.Fatal("an edited provenance statement verified")
	}
}

// A window reaching back before a partial bundle's first entry means entries
// inside it are missing, so the counts are understated. That must be reported.
func TestScopedBundleRejectsWindowStartingBeforeAPartialRange(t *testing.T) {
	b := scopedBundle(t)
	// Make the bundle a partial range rather than one starting at the chain's
	// beginning, which is the case where the omission is detectable.
	b.Manifest.FromSeq = 40
	b.Manifest.PrevHash = "not-the-genesis-hash"
	b.Compliance.From = b.Audit[0].At.Add(-365 * 24 * time.Hour)
	if Verify(b).OK() {
		t.Fatal("a window reaching before a partial bundle's range verified")
	}
}

// A bundle that starts at the beginning of the chain has nothing before its
// first entry, so an earlier window start is not an omission.
func TestScopedBundleAllowsEarlyWindowFromChainStart(t *testing.T) {
	b := scopedBundle(t)
	b.Compliance.From = b.Audit[0].At.Add(-365 * 24 * time.Hour)
	rep := Verify(b)
	for _, c := range rep.Checks {
		if c.Name == "compliance assessment" && !c.OK {
			t.Fatalf("a full-chain bundle was rejected: %s", c.Detail)
		}
	}
}

// The bundle carries an assessment but no entries at all: the recomputable
// half has nothing to stand on.
func TestScopedBundleRejectsAssessmentWithNoEntries(t *testing.T) {
	b := scopedBundle(t)
	b.Audit = nil
	if Verify(b).OK() {
		t.Fatal("an assessment with no audit entries verified")
	}
}

func TestUnscopedBundleReportsNoComplianceControls(t *testing.T) {
	b, _ := testBundle(t)
	rep := Verify(b)
	if !rep.OK() {
		t.Fatalf("plain bundle failed: %+v", rep.Checks)
	}
	if rep.ComplianceControls != 0 {
		t.Errorf("complianceControls = %d on an unscoped bundle", rep.ComplianceControls)
	}
	for _, c := range rep.Checks {
		if c.Name == "compliance assessment" {
			t.Error("an unscoped bundle produced a compliance check")
		}
	}
}
