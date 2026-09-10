package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func TestLoadOrCreateAndSignCSR(t *testing.T) {
	dir := t.TempDir()
	bundle, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreate(dir, []string{"other"})
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(bundle.CACert) != Fingerprint(again.CACert) {
		t.Fatal("CA should persist on disk")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "host-a"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := bundle.SignCSR(csrDER, "dev-1", "host-a", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("expected PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "dev-1" {
		t.Fatalf("CN=%s", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(bundle.CACert); err != nil {
		t.Fatal(err)
	}
}
