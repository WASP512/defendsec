// Package webtls terminates HTTPS in front of the console (roadmap 5.3).
//
// Port 47261 shipped plain HTTP, which is a credibility problem for a security
// product and something the white paper has to caveat in four separate places.
// The admin token is a bearer credential: on plain HTTP it is readable by
// anything on the path, and a product that signs every host action while
// handing its own admin token around in clear text is not making a coherent
// argument.
//
// # Why a front-end rather than TLS in Next.js
//
// Next.js does not serve HTTPS in production; the documented answer is a
// reverse proxy. Rather than tell every operator to install one — which is
// what "put nginx in front" amounts to, and which most single-container
// deployments will not do — DefendSec ships the terminator itself. The console
// then binds to loopback only, so the plain-HTTP port is not reachable off the
// box at all.
//
// # Certificates
//
// Three modes, in the order most deployments should try them:
//
//   - self-signed, generated on first start. Works immediately on a LAN with no
//     DNS and no internet. The browser warns, which is honest: the certificate
//     really is unverified. It is still strictly better than plain HTTP, which
//     an attacker does not even have to be noticed to read.
//   - ACME (Let's Encrypt), for a deployment with a public name.
//   - a certificate the operator supplies, for an internal CA.
package webtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Mode selects how the certificate is obtained.
type Mode string

const (
	// ModeSelfSigned generates a certificate locally. The default.
	ModeSelfSigned Mode = "self-signed"
	// ModeACME obtains one from Let's Encrypt. Needs a public DNS name and
	// inbound port 80.
	ModeACME Mode = "acme"
	// ModeFile uses a certificate the operator supplies.
	ModeFile Mode = "file"
	// ModeOff serves plain HTTP. An explicit opt-out for isolated labs, never
	// a default and never silent.
	ModeOff Mode = "off"
)

// Config describes the desired posture.
type Config struct {
	Mode Mode
	// Dir is where generated material is kept.
	Dir string
	// Hosts are the names the certificate should cover. For ACME this is the
	// allowlist; requesting a certificate for a name the operator did not
	// name would let anyone pointing DNS at the box mint one.
	Hosts []string
	// CertFile and KeyFile are used in ModeFile.
	CertFile string
	KeyFile  string
	// ACMEEmail receives expiry warnings.
	ACMEEmail string
	// ACMEAcceptTOS must be true. Let's Encrypt requires agreement, and
	// agreeing on an operator's behalf without asking is not ours to do.
	ACMEAcceptTOS bool
}

// SelfSignedLifetime is how long a generated certificate lasts.
//
// Two years rather than the ninety days a public CA issues: this certificate
// is not publicly trusted, so a short life buys nothing against
// misissuance — it only produces an outage on a box nobody is watching.
const SelfSignedLifetime = 2 * 365 * 24 * time.Hour

// renewBefore regenerates a self-signed certificate this long before expiry.
const renewBefore = 30 * 24 * time.Hour

// ParseMode reads the configured mode.
//
// An unrecognised value is an error rather than a fallback. Falling back to
// plain HTTP because someone typed "tls" instead of "on" would silently
// undo the whole point of this phase.
func ParseMode(raw string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "on", "true", "1", "yes", "self-signed", "selfsigned":
		return ModeSelfSigned, nil
	case "acme", "letsencrypt", "lets-encrypt":
		return ModeACME, nil
	case "file", "custom":
		return ModeFile, nil
	case "off", "false", "0", "no", "http", "plain":
		return ModeOff, nil
	default:
		return "", fmt.Errorf("unknown TLS mode %q; want on, acme, file or off", raw)
	}
}

// Provider supplies a TLS configuration.
type Provider struct {
	cfg     Config
	manager *autocert.Manager
}

// New validates a configuration and prepares the provider.
func New(cfg Config) (*Provider, error) {
	switch cfg.Mode {
	case ModeOff:
		return &Provider{cfg: cfg}, nil

	case ModeFile:
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("file mode needs both a certificate and a key")
		}
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			// Checked now rather than on the first request: a certificate
			// problem discovered when somebody tries to log in is discovered
			// at the worst time.
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		return &Provider{cfg: cfg}, nil

	case ModeACME:
		if !cfg.ACMEAcceptTOS {
			return nil, fmt.Errorf(
				"ACME requires accepting the Let's Encrypt terms of service; set DEFENDSEC_ACME_ACCEPT_TOS=1")
		}
		hosts := publicHosts(cfg.Hosts)
		if len(hosts) == 0 {
			return nil, fmt.Errorf(
				"ACME needs at least one public DNS name in DEFENDSEC_TLS_HOSTS; an IP address or .local name cannot be issued a public certificate")
		}
		return &Provider{
			cfg: cfg,
			manager: &autocert.Manager{
				Prompt: autocert.AcceptTOS,
				Cache:  autocert.DirCache(filepath.Join(cfg.Dir, "acme")),
				// An allowlist, not a callback that accepts anything.
				// Without it, anyone who points a DNS name at this box could
				// have a certificate minted for it and exhaust the rate limit.
				HostPolicy: autocert.HostWhitelist(hosts...),
				Email:      cfg.ACMEEmail,
			},
		}, nil

	default:
		if cfg.Dir == "" {
			return nil, fmt.Errorf("self-signed mode needs a directory to keep the certificate in")
		}
		if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
			return nil, fmt.Errorf("create tls directory: %w", err)
		}
		if _, err := loadOrCreateSelfSigned(cfg.Dir, cfg.Hosts, time.Now()); err != nil {
			return nil, err
		}
		return &Provider{cfg: cfg}, nil
	}
}

// Enabled reports whether TLS is in force.
func (p *Provider) Enabled() bool { return p != nil && p.cfg.Mode != ModeOff }

// Mode returns the configured mode.
func (p *Provider) Mode() Mode {
	if p == nil {
		return ModeOff
	}
	return p.cfg.Mode
}

// TLSConfig builds the server configuration.
func (p *Provider) TLSConfig() (*tls.Config, error) {
	if !p.Enabled() {
		return nil, nil
	}

	base := &tls.Config{
		// 1.2 rather than 1.3 only: an agency running an older managed
		// browser should not be locked out of its own console, and 1.2 with
		// modern suites is not the weak link here.
		MinVersion: tls.VersionTLS12,
	}

	switch p.cfg.Mode {
	case ModeACME:
		cfg := p.manager.TLSConfig()
		cfg.MinVersion = base.MinVersion
		return cfg, nil

	case ModeFile:
		cert, err := tls.LoadX509KeyPair(p.cfg.CertFile, p.cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		base.Certificates = []tls.Certificate{cert}
		return base, nil

	default:
		// Resolved per handshake so a renewal is picked up without a restart.
		base.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return loadOrCreateSelfSigned(p.cfg.Dir, p.cfg.Hosts, time.Now())
		}
		return base, nil
	}
}

// publicHosts filters out names a public CA cannot issue for, so the failure
// is reported at startup rather than as an opaque ACME error later.
func publicHosts(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || h == "localhost" {
			continue
		}
		if net.ParseIP(h) != nil {
			continue
		}
		if strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") ||
			strings.HasSuffix(h, ".lan") || !strings.Contains(h, ".") {
			continue
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// loadOrCreateSelfSigned returns the generated certificate, making a new one
// when none exists or the existing one is close to expiry.
func loadOrCreateSelfSigned(dir string, hosts []string, now time.Time) (*tls.Certificate, error) {
	certPath := filepath.Join(dir, "console.crt")
	keyPath := filepath.Join(dir, "console.key")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && now.Add(renewBefore).Before(leaf.NotAfter) && coversAll(leaf, hosts) {
			cert.Leaf = leaf
			return &cert, nil
		}
		// Otherwise fall through and regenerate: expiring soon, or the
		// operator added a hostname the existing certificate does not cover.
	}
	return createSelfSigned(certPath, keyPath, hosts, now)
}

// coversAll reports whether the certificate already covers every configured
// name, so adding one to the configuration regenerates rather than silently
// serving a certificate that does not match.
func coversAll(leaf *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if err := leaf.VerifyHostname(h); err != nil {
			return false
		}
	}
	return true
}

func createSelfSigned(certPath, keyPath string, hosts []string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: primaryHost(hosts), Organization: []string{"DefendSec"}},
		NotBefore:    now.Add(-time.Hour), // tolerate a little clock skew
		NotAfter:     now.Add(SelfSignedLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Self-signed and self-issued, so it has to be its own CA for a
		// browser or an operator to be able to pin it deliberately.
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	// Loopback always, so an operator on the box can reach the console even
	// when DNS is wrong — which is exactly when they need to.
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	tmpl.DNSNames = append(tmpl.DNSNames, "localhost")

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, fmt.Errorf("write certificate: %w", err)
	}
	// The private key is readable only by the service account.
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cert.Leaf, _ = x509.ParseCertificate(der)
	return cert, nil
}

func primaryHost(hosts []string) string {
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			return h
		}
	}
	return "defendsec-console"
}

// Fingerprint returns the SHA-256 of the served certificate, so an operator
// can compare what their browser shows against what the server holds. With a
// self-signed certificate that comparison is the only verification available,
// so it has to be easy to make.
func (p *Provider) Fingerprint() (string, error) {
	cfg, err := p.TLSConfig()
	if err != nil || cfg == nil {
		return "", err
	}
	var leaf *x509.Certificate
	switch {
	case len(cfg.Certificates) > 0:
		leaf, err = x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	case cfg.GetCertificate != nil:
		cert, cerr := cfg.GetCertificate(&tls.ClientHelloInfo{})
		if cerr != nil {
			return "", cerr
		}
		leaf = cert.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
		}
	default:
		// ACME certificates are obtained on demand, so there is nothing to
		// fingerprint until a handshake has happened.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return formatFingerprint(leaf.Raw), nil
}

// Manager exposes the autocert manager for wiring the challenge handler.
func (p *Provider) Manager() *autocert.Manager {
	if p == nil {
		return nil
	}
	return p.manager
}

// WaitForListener is a small helper used by the front-end to report readiness.
func WaitForListener(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("nothing is listening on %s after %s", addr, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func formatFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
