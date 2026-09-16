package webtls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMode(t *testing.T) {
	good := map[string]Mode{
		"":            ModeSelfSigned, // unset means on, not off
		"on":          ModeSelfSigned,
		"true":        ModeSelfSigned,
		"self-signed": ModeSelfSigned,
		"ACME":        ModeACME,
		"letsencrypt": ModeACME,
		"file":        ModeFile,
		"off":         ModeOff,
		"  off  ":     ModeOff,
		"plain":       ModeOff,
	}
	for raw, want := range good {
		got, err := ParseMode(raw)
		if err != nil {
			t.Errorf("ParseMode(%q) = %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", raw, got, want)
		}
	}

	// A typo must be refused. Falling back to plain HTTP because somebody
	// wrote "tls" would silently undo the whole point.
	for _, bad := range []string{"tls", "ssl", "enabled", "maybe", "https"} {
		if _, err := ParseMode(bad); err == nil {
			t.Errorf("ParseMode(%q) was accepted", bad)
		}
	}
}

// Unset must mean HTTPS. That is the entire change this phase makes.
func TestDefaultIsHTTPS(t *testing.T) {
	mode, err := ParseMode("")
	if err != nil {
		t.Fatal(err)
	}
	if mode == ModeOff {
		t.Fatal("an unset DEFENDSEC_TLS disabled TLS")
	}
	p, err := New(Config{Mode: mode, Dir: t.TempDir(), Hosts: []string{"console.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled() {
		t.Fatal("the default provider is not serving TLS")
	}
}

func TestSelfSignedCertificateIsUsable(t *testing.T) {
	dir := t.TempDir()
	p, err := New(Config{Mode: ModeSelfSigned, Dir: dir, Hosts: []string{"console.example", "192.168.1.50"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := p.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}

	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// The configured names must be covered...
	for _, host := range []string{"console.example", "192.168.1.50"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate does not cover %q: %v", host, err)
		}
	}
	// ...and loopback always, so an operator on the box can reach the console
	// when DNS is wrong, which is exactly when they need to.
	for _, host := range []string{"localhost", "127.0.0.1"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate does not cover %q: %v", host, err)
		}
	}

	if leaf.NotAfter.Before(time.Now().Add(365 * 24 * time.Hour)) {
		t.Error("the generated certificate expires within a year")
	}
	if !leaf.NotBefore.Before(time.Now()) {
		t.Error("the certificate is not yet valid; clock skew would break the first start")
	}
}

// The private key must not be world-readable.
func TestSelfSignedKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(Config{Mode: ModeSelfSigned, Dir: dir, Hosts: []string{"x.example"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "console.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("key mode = %o, want no group or other access", perm)
	}
}

// A second start must reuse the certificate, or every restart would show the
// operator a new fingerprint and train them to ignore the warning.
func TestSelfSignedCertificateIsReused(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"console.example"}

	first, err := loadOrCreateSelfSigned(dir, hosts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateSelfSigned(dir, hosts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("a restart generated a new certificate")
	}
}

// Adding a hostname must regenerate, not silently serve a certificate that
// does not cover it.
func TestAddingAHostRegenerates(t *testing.T) {
	dir := t.TempDir()
	first, err := loadOrCreateSelfSigned(dir, []string{"a.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateSelfSigned(dir, []string{"a.example", "b.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatal("adding a hostname did not regenerate the certificate")
	}
	if err := second.Leaf.VerifyHostname("b.example"); err != nil {
		t.Errorf("the regenerated certificate does not cover the new name: %v", err)
	}
}

// An expiring certificate must be replaced before it expires, not after.
func TestCertificateRenewsBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"console.example"}

	now := time.Now()
	first, err := loadOrCreateSelfSigned(dir, hosts, now)
	if err != nil {
		t.Fatal(err)
	}

	// Jump to within the renewal window of expiry.
	later := first.Leaf.NotAfter.Add(-renewBefore).Add(time.Hour)
	second, err := loadOrCreateSelfSigned(dir, hosts, later)
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatal("a certificate close to expiry was not renewed")
	}
	if !second.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Error("the renewed certificate does not last longer than the old one")
	}
}

func TestFileModeValidatesUpFront(t *testing.T) {
	// A certificate problem discovered when somebody tries to log in is
	// discovered at the worst possible time.
	if _, err := New(Config{Mode: ModeFile}); err == nil {
		t.Error("file mode accepted no certificate")
	}
	if _, err := New(Config{Mode: ModeFile, CertFile: "/nope.crt", KeyFile: "/nope.key"}); err == nil {
		t.Error("file mode accepted a missing certificate")
	}

	// A real pair loads.
	dir := t.TempDir()
	if _, err := createSelfSigned(filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key"),
		[]string{"x.example"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Mode: ModeFile,
		CertFile: filepath.Join(dir, "c.crt"), KeyFile: filepath.Join(dir, "c.key")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err := p.TLSConfig(); err != nil || len(cfg.Certificates) != 1 {
		t.Errorf("file mode did not load the certificate: %v", err)
	}
}

func TestACMEValidation(t *testing.T) {
	dir := t.TempDir()

	// Agreeing to someone else's terms of service on their behalf is not ours
	// to do.
	if _, err := New(Config{Mode: ModeACME, Dir: dir, Hosts: []string{"console.example.com"}}); err == nil {
		t.Error("ACME proceeded without the terms being accepted")
	}

	// Names a public CA cannot issue for are rejected at startup rather than
	// producing an opaque ACME error later.
	for _, hosts := range [][]string{
		nil,
		{"192.168.1.50"},
		{"console.local"},
		{"defendsec"},
		{"localhost"},
	} {
		if _, err := New(Config{Mode: ModeACME, Dir: dir, Hosts: hosts, ACMEAcceptTOS: true}); err == nil {
			t.Errorf("ACME accepted unissuable hosts %v", hosts)
		}
	}

	p, err := New(Config{Mode: ModeACME, Dir: dir,
		Hosts: []string{"console.example.com", "192.168.1.50"}, ACMEAcceptTOS: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Manager() == nil {
		t.Fatal("no ACME manager")
	}
	// The host policy must be an allowlist: without one, anyone pointing DNS
	// at this box could have a certificate minted and exhaust the rate limit.
	if err := p.Manager().HostPolicy(t.Context(), "attacker.example.com"); err == nil {
		t.Error("the ACME host policy accepted a name the operator never configured")
	}
	if err := p.Manager().HostPolicy(t.Context(), "console.example.com"); err != nil {
		t.Errorf("the ACME host policy rejected a configured name: %v", err)
	}
}

func TestOffModeIsExplicit(t *testing.T) {
	p, err := New(Config{Mode: ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled() {
		t.Fatal("off mode is serving TLS")
	}
	cfg, err := p.TLSConfig()
	if err != nil || cfg != nil {
		t.Errorf("off mode produced a TLS config: %v, %v", cfg, err)
	}
}

// With a self-signed certificate, comparing the fingerprint is the only
// verification available, so it has to be obtainable.
func TestFingerprint(t *testing.T) {
	p, err := New(Config{Mode: ModeSelfSigned, Dir: t.TempDir(), Hosts: []string{"x.example"}})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := p.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	// Formatted the way a browser shows it, so the comparison is a glance
	// rather than a transcription exercise.
	if len(fp) != 95 || !strings.Contains(fp, ":") {
		t.Errorf("fingerprint = %q, want colon-separated hex", fp)
	}

	off, _ := New(Config{Mode: ModeOff})
	if fp, err := off.Fingerprint(); err != nil || fp != "" {
		t.Errorf("off mode produced a fingerprint: %q, %v", fp, err)
	}
}

func TestPublicHostsFiltering(t *testing.T) {
	got := publicHosts([]string{
		"console.example.com", "192.168.1.50", "::1", "console.local",
		"localhost", "defendsec", "", "  other.example.org  ", "box.internal", "x.lan",
	})
	want := []string{"console.example.com", "other.example.org"}
	if len(got) != len(want) {
		t.Fatalf("publicHosts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("publicHosts = %v, want %v", got, want)
		}
	}
}
