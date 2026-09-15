package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testAck() AckEnvelope {
	return AckEnvelope{
		CommandID: "cmd-1", DeviceID: "device-1", Accepted: true,
		ResultHash: HashResult("isolated"), ExecutedUnix: 1789200030,
	}
}

func TestAckSignAndVerify(t *testing.T) {
	key := testKey(t)
	env := testAck()
	sig, err := SignAck(key, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAck(&key.PublicKey, env, sig); err != nil {
		t.Fatalf("a freshly signed ack should verify: %v", err)
	}
	if err := VerifyAck(&testKey(t).PublicKey, env, sig); err == nil {
		t.Error("an ack must not verify under another agent's key")
	}
	if err := VerifyAck(&key.PublicKey, env, nil); err == nil {
		t.Error("an unsigned ack must not verify")
	}
}

// Every field is covered, so none of them can be rewritten after the fact.
func TestAckSignatureCoversEveryField(t *testing.T) {
	key := testKey(t)
	env := testAck()
	sig, err := SignAck(key, env)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*AckEnvelope){
		"command":  func(e *AckEnvelope) { e.CommandID = "cmd-2" },
		"device":   func(e *AckEnvelope) { e.DeviceID = "device-2" },
		"accepted": func(e *AckEnvelope) { e.Accepted = false },
		"result":   func(e *AckEnvelope) { e.ResultHash = HashResult("something else") },
		"executed": func(e *AckEnvelope) { e.ExecutedUnix = 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := testAck()
			mutate(&tampered)
			if err := VerifyAck(&key.PublicKey, tampered, sig); err == nil {
				t.Errorf("editing %s must invalidate the signature", name)
			}
		})
	}
}

// Replaying one host's acknowledgement as another's must fail, since the
// device is inside the signed content.
func TestAckIsBoundToItsDevice(t *testing.T) {
	key := testKey(t)
	env := testAck()
	sig, _ := SignAck(key, env)
	replayed := env
	replayed.DeviceID = "another-device"
	if err := VerifyAck(&key.PublicKey, replayed, sig); err == nil {
		t.Fatal("an ack must not replay onto a different device")
	}
}

func TestCanonicalAckIsUnambiguous(t *testing.T) {
	a := AckEnvelope{CommandID: "ab", DeviceID: "c"}
	b := AckEnvelope{CommandID: "a", DeviceID: "bc"}
	if string(CanonicalAck(a)) == string(CanonicalAck(b)) {
		t.Error("field boundaries must be unambiguous")
	}
	c := AckEnvelope{CommandID: "a\n1:b", DeviceID: ""}
	d := AckEnvelope{CommandID: "a", DeviceID: "b"}
	if string(CanonicalAck(c)) == string(CanonicalAck(d)) {
		t.Error("embedded delimiters must not forge a field boundary")
	}
}

func TestAckPublicKeyPEMRoundTrip(t *testing.T) {
	key := testKey(t)
	pemBytes, err := ECDSAPublicPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseECDSAPublicPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Error("public key did not survive the PEM round trip")
	}
	if _, err := ParseECDSAPublicPEM([]byte("not a pem")); err == nil {
		t.Error("malformed PEM must be rejected")
	}
}

func TestVerifyAckStored(t *testing.T) {
	key := testKey(t)
	env := testAck()
	sig, _ := SignAck(key, env)
	pemBytes, _ := ECDSAPublicPEM(&key.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(sig)

	if err := VerifyAckStored(string(pemBytes), env.CommandID, env.DeviceID,
		env.Accepted, env.ResultHash, env.ExecutedUnix, b64); err != nil {
		t.Fatalf("stored ack should verify: %v", err)
	}
	// A result edited in the database no longer matches the hash that was signed.
	if err := VerifyAckStored(string(pemBytes), env.CommandID, env.DeviceID,
		env.Accepted, HashResult("tampered"), env.ExecutedUnix, b64); err == nil {
		t.Error("an edited result must fail verification")
	}
	if err := VerifyAckStored(string(pemBytes), env.CommandID, env.DeviceID,
		env.Accepted, env.ResultHash, env.ExecutedUnix, "not base64!!"); err == nil {
		t.Error("a malformed signature must fail verification")
	}
}

func TestHashResultIsStable(t *testing.T) {
	if HashResult("isolated") != HashResult("isolated") {
		t.Fatal("HashResult must be deterministic")
	}
	if HashResult("a") == HashResult("b") {
		t.Fatal("distinct results must hash differently")
	}
	if !strings.HasPrefix(HashResult(""), "e3b0c442") {
		t.Errorf("empty result should hash to the SHA-256 of empty, got %s", HashResult(""))
	}
}
