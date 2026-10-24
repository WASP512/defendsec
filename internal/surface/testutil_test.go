package surface

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testScanner is a Scanner on a fake zone. Nothing here touches the network.
func testScanner(f *FakeResolver) *Scanner {
	return &Scanner{
		Resolver: f, Validating: f,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, fmt.Errorf("test dialled the network unexpectedly")
		},
		FIPS: func() bool { return false },
	}
}

func domainAsset(v string) Asset { return Asset{Kind: KindDomain, Value: v, Authorised: true} }

// run executes one check against a fresh run of the scanner.
func newRun(s *Scanner, a Asset) *run {
	return &run{s: s, a: a, ctx: context.Background()}
}

func ids(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID+"|"+f.Subject)
	}
	sort.Strings(out)
	return out
}

func find(t *testing.T, res CheckResult, id string) Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %q in %v (assessed=%v reason=%q)", id, ids(res.Findings), res.Assessed, res.Reason)
	return Finding{}
}

func noFinding(t *testing.T, res CheckResult, id string) {
	t.Helper()
	for _, f := range res.Findings {
		if f.ID == id {
			t.Fatalf("unexpected finding %q: %+v", id, f)
		}
	}
}

func wantSeverity(t *testing.T, f Finding, sev Severity) {
	t.Helper()
	if f.Severity != sev {
		t.Fatalf("%s severity = %s, want %s", f.ID, f.Severity, sev)
	}
}

func txt(name, value string) string {
	return fmt.Sprintf("%s. 300 IN TXT %q", name, value)
}

// dkimKey returns a base64 SubjectPublicKeyInfo for an RSA key of the given size.
// Sizes under 1024 are fabricated moduli (the scanner only reads their length).
func dkimKey(t *testing.T, bits int) string {
	t.Helper()
	var der []byte
	if bits >= 1024 {
		k, err := rsaGenerate(bits)
		if err != nil {
			t.Fatal(err)
		}
		der = k
	} else {
		der = fakeRSASPKI(bits)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// --- certificates ----------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue makes a leaf signed by ca with the given validity relative to now.
func (ca *testCA) issue(t *testing.T, names []string, notBefore, notAfter time.Duration) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames:  names,
		NotBefore: time.Now().Add(notBefore), NotAfter: time.Now().Add(notAfter),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// intermediate makes a sub-CA signed by ca and a leaf signed by it. The chain
// returned sends leaf only (withIntermediate=false) or leaf + intermediate.
func (ca *testCA) chain(t *testing.T, names []string, withIntermediate bool) tls.Certificate {
	t.Helper()
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	itmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ider, err := x509.CreateCertificate(rand.Reader, itmpl, ca.cert, &ikey.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	icert, _ := x509.ParseCertificate(ider)
	lkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ltmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(80 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	lder, err := x509.CreateCertificate(rand.Reader, ltmpl, icert, &lkey.PublicKey, ikey)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Certificate{Certificate: [][]byte{lder}, PrivateKey: lkey}
	if withIntermediate {
		c.Certificate = append(c.Certificate, ider)
	}
	return c
}

func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	ca := newCA(t, name)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	_ = ca
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer listens on 127.0.0.1 and completes handshakes with cfg until the
// test ends. It returns the listener's address.
func tlsServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

// toLocal makes the scanner's dials land on addr whatever address was asked for.
func toLocal(addr string) DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

// hostZone is a zone where host resolves to a documentation address.
func hostZone(host string) *FakeResolver {
	return NewFakeResolver().Add(host + ". 300 IN A 192.0.2.10")
}

func joinTXT(parts ...string) string { return strings.Join(parts, " ") }

var _ = dns.TypeA

func rsaGenerate(bits int) ([]byte, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}

// fakeRSASPKI marshals an RSA public key whose modulus has exactly the given
// bit length. It is not a usable key, which is all the size check needs, and it
// avoids generating a weak key just to describe one.
func fakeRSASPKI(bits int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		panic(err)
	}
	return der
}

// timeoutErr is what a dial that never got an answer looks like.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func parseAddr(s string) (netip.Addr, error) { return netip.ParseAddr(s) }
