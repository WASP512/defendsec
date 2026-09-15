package evidence

import (
	"bytes"
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
	if c := failing(t, r); c.Name != "coverage" {
		t.Errorf("want the coverage check to fail, got %+v", c)
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
