package sign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadNeverCreates(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("Load on an empty directory must fail, not mint a key")
	}
	if _, err := os.Stat(filepath.Join(dir, "control-ed25519.key")); err == nil {
		t.Fatal("Load created a key file")
	}
	made, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.PublicPEM()) != string(made.PublicPEM()) {
		t.Fatal("Load returned a different key than LoadOrCreate wrote")
	}
}

func TestBlobSignatures(t *testing.T) {
	key, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abc  feeds/kev/data\n")
	sig := key.SignBlob("test-domain-v1", msg)

	if err := VerifyBlob(key.Public, "test-domain-v1", msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	for name, fn := range map[string]func() error{
		"tampered message": func() error { return VerifyBlob(key.Public, "test-domain-v1", append([]byte("x"), msg...), sig) },
		"other domain":     func() error { return VerifyBlob(key.Public, "other-domain-v1", msg, sig) },
		"other key":        func() error { return VerifyBlob(other.Public, "test-domain-v1", msg, sig) },
		"empty signature":  func() error { return VerifyBlob(key.Public, "test-domain-v1", msg, nil) },
		"short signature":  func() error { return VerifyBlob(key.Public, "test-domain-v1", msg, sig[:10]) },
	} {
		if err := fn(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A feed-bundle signature must not verify as a command signature, or the other
// way round, even over identical bytes.
func TestBlobSignatureIsNotACommandSignature(t *testing.T) {
	key, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{DeviceID: "d", CommandID: "c", Type: "t", Payload: []byte("p")}
	blobSig := key.SignBlob("defendsec-feeds-v1", Canonical(e))
	if err := Verify(key.Public, e, blobSig, time.Now()); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("blob signature verified as a command: %v", err)
	}
	cmdSig := key.Sign(e)
	if err := VerifyBlob(key.Public, "defendsec-feeds-v1", Canonical(e), cmdSig); err == nil {
		t.Fatal("command signature verified as a feed bundle signature")
	}
}
