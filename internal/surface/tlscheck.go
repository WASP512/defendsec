package surface

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func (r *run) fipsOn() bool {
	if r.s.FIPS != nil {
		return r.s.FIPS()
	}
	return fips140.Enabled()
}

// handshake performs one TLS handshake with SNI and no verification. The chain
// is verified by hand afterwards so the exact reason can be reported and so a
// certificate that fails verification can still be described.
func (r *run) handshake(c net.Conn, host string, minV, maxV uint16) (tls.ConnectionState, error) {
	cfg := &tls.Config{
		ServerName: host,
		MinVersion: minV,
		MaxVersion: maxV,
		// Verification is done by verifyChain below, deliberately: a failed
		// chain is a finding with evidence, not an aborted connection.
		InsecureSkipVerify: true, // #nosec G402
	}
	tc := tls.Client(c, cfg)
	ctx, cancel := context.WithTimeout(r.ctx, TLSTimeout)
	defer cancel()
	err := tc.HandshakeContext(ctx)
	st := tc.ConnectionState()
	_ = tc.Close()
	return st, err
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func keyDescription(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}

func certObservation(chain []*x509.Certificate) []map[string]any {
	out := make([]map[string]any, 0, len(chain))
	for _, c := range chain {
		out = append(out, map[string]any{
			"subject": c.Subject.String(), "issuer": c.Issuer.String(),
			"dnsNames":  c.DNSNames,
			"notBefore": c.NotBefore.UTC().Format(time.RFC3339), "notAfter": c.NotAfter.UTC().Format(time.RFC3339),
			"sha256": fingerprint(c), "key": keyDescription(c), "signature": c.SignatureAlgorithm.String(),
			"serial": c.SerialNumber.Text(16),
		})
	}
	return out
}

// tlsChecks handshakes with a declared hostname on 443 and judges the
// certificate, then separately probes whether TLS 1.0 and 1.1 are accepted.
func (r *run) tlsChecks() (CheckResult, CheckResult) {
	host := r.a.Value
	conn, ip, err := r.dialHost(host, "443")
	if err != nil {
		var why string
		switch classifyDial(err) {
		case netNoHost:
			why = "nothing to connect to: " + err.Error()
		case netRefused:
			why = "no HTTPS listener on " + host + ":443 (connection refused), so there is no certificate to check"
		case netTimeout:
			why = "timed out connecting to " + host + ":443"
		default:
			why = "could not connect to " + host + ":443: " + err.Error()
		}
		return notAssessed(CheckTLSCert, why, nil), notAssessed(CheckTLSLegacy, why, nil)
	}
	minV := uint16(tls.VersionTLS10)
	if r.fipsOn() {
		minV = 0 // FIPS mode refuses TLS 1.0; take the default
	}
	state, herr := r.handshake(conn, host, minV, 0)
	var cert CheckResult
	if herr != nil {
		cert = notAssessed(CheckTLSCert, "TLS handshake with "+host+":443 failed: "+herr.Error(), map[string]any{"ip": ip.String()})
	} else {
		cert = r.judgeCertificate(host, ip, state)
	}
	return cert, r.legacyCheck(host, ip)
}

func (r *run) judgeCertificate(host string, ip net.IP, st tls.ConnectionState) CheckResult {
	chain := st.PeerCertificates
	if len(chain) == 0 {
		return notAssessed(CheckTLSCert, "the server presented no certificate", map[string]any{"ip": ip.String()})
	}
	leaf := chain[0]
	now := r.s.now()
	obs := map[string]any{
		"host": host, "ip": ip.String(), "port": 443,
		"version": tlsVersionName(st.Version), "cipherSuite": tls.CipherSuiteName(st.CipherSuite),
		"chainSent": certObservation(chain), "checkedAt": now.Format(time.RFC3339),
		"daysRemaining": int(leaf.NotAfter.Sub(now).Hours() / 24),
	}
	var fs []Finding
	ev := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"host": host, "subject": leaf.Subject.String(), "issuer": leaf.Issuer.String(),
			"notAfter": leaf.NotAfter.UTC().Format(time.RFC3339), "sha256": fingerprint(leaf), "dnsNames": leaf.DNSNames,
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	left := leaf.NotAfter.Sub(now)
	switch {
	case left < 0:
		fs = append(fs, newFinding(CheckTLSCert, "tls.expired", host, SevCritical,
			"TLS certificate has expired",
			fmt.Sprintf("The certificate %s presents expired on %s, %d days ago. Browsers show a full-page warning and many clients refuse to connect.", host, leaf.NotAfter.UTC().Format("2006-01-02"), int(-left.Hours()/24)),
			"Renew and install the certificate now. If it should renew automatically, find out why it did not (ACME client, hosting panel or CDN).", ev(nil)))
	case left < 7*24*time.Hour:
		fs = append(fs, newFinding(CheckTLSCert, "tls.expires_soon", host, SevHigh,
			"TLS certificate expires within 7 days",
			fmt.Sprintf("The certificate %s presents expires on %s (%d days).", host, leaf.NotAfter.UTC().Format("2006-01-02"), int(left.Hours()/24)),
			"Renew the certificate now. Automatic renewal normally happens a month ahead, so a certificate this close to expiry means renewal is failing.", ev(nil)))
	case left < 30*24*time.Hour:
		fs = append(fs, newFinding(CheckTLSCert, "tls.expiring", host, SevLow,
			"TLS certificate expires within 30 days",
			fmt.Sprintf("The certificate %s presents expires on %s (%d days).", host, leaf.NotAfter.UTC().Format("2006-01-02"), int(left.Hours()/24)),
			"Renew it. If renewal is automatic, confirm it ran: most ACME clients renew at 30 days left.", ev(nil)))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		fs = append(fs, newFinding(CheckTLSCert, "tls.hostname_mismatch", host, SevHigh,
			"TLS certificate does not match the hostname",
			"The certificate presented for "+host+" is not valid for that name: "+err.Error()+". Browsers show a warning and API clients refuse the connection.",
			"Install a certificate that lists "+host+" (or a matching wildcard) as a subject alternative name.", ev(map[string]any{"error": err.Error()})))
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: r.s.RootCAs, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		var inv x509.CertificateInvalidError
		var sysErr x509.SystemRootsError
		switch {
		case errors.As(err, &sysErr):
			obs["chainNotVerified"] = "this host has no system root certificates: " + err.Error()
			return CheckResult{Check: CheckTLSCert, Assessed: false, Reason: "chain not verified: this host has no system root certificates", Observed: obs, Findings: fs}
		case errors.As(err, &inv) && inv.Reason == x509.Expired && left < 0:
			// Already reported as expired; a second finding would only repeat it.
		default:
			fs = append(fs, newFinding(CheckTLSCert, "tls.chain_invalid", host, SevMedium,
				"TLS certificate chain does not verify",
				"The certificate for "+host+" did not verify against the trusted roots: "+err.Error()+". The usual causes are a missing intermediate certificate (some clients cannot repair it), a self-signed certificate, or a private CA.",
				"Serve the full chain (leaf plus intermediates, not the root) from the server, or install a certificate from a publicly trusted CA.",
				ev(map[string]any{"error": err.Error(), "certificatesSent": len(chain)})))
		}
	}
	return assessed(CheckTLSCert, obs, fs...)
}

// legacyCheck tests whether TLS 1.0 and 1.1 are accepted, each in a handshake
// of its own with the version range pinned. Go's client defaults to TLS 1.2 or
// later, so the range has to be set explicitly.
func (r *run) legacyCheck(host string, ip net.IP) CheckResult {
	if r.fipsOn() {
		return notAssessed(CheckTLSLegacy, "Go's FIPS 140 mode is on in this process, which refuses TLS 1.0 and 1.1 handshakes, so the probe cannot run", nil)
	}
	obs := map[string]any{"host": host, "ip": ip.String()}
	var fs []Finding
	inconclusive := 0
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		name := tlsVersionName(v)
		c, err := r.dialIP(ip, "443")
		if err != nil {
			obs[name] = "could not connect: " + err.Error()
			inconclusive++
			continue
		}
		st, err := r.handshake(c, host, v, v)
		switch {
		case err == nil:
			obs[name] = "accepted"
			fs = append(fs, newFinding(CheckTLSLegacy, "tls.legacy_protocol", name, SevMedium,
				name+" is accepted",
				host+" completed a handshake using "+tlsVersionName(st.Version)+" (cipher "+tls.CipherSuiteName(st.CipherSuite)+"). TLS 1.0 and 1.1 are deprecated (RFC 8996) and have known weaknesses. Modern clients do not need them.",
				"Set the minimum TLS version to 1.2 on the web server, load balancer or CDN setting that terminates TLS for "+host+".",
				map[string]any{"host": host, "version": name, "negotiated": tlsVersionName(st.Version), "cipherSuite": tls.CipherSuiteName(st.CipherSuite)}))
		case legacyRejected(err):
			obs[name] = "rejected: " + err.Error()
		default:
			obs[name] = "inconclusive: " + err.Error()
			inconclusive++
		}
	}
	res := assessed(CheckTLSLegacy, obs, fs...)
	if inconclusive > 0 {
		res.Assessed = false
		res.Reason = fmt.Sprintf("%d of 2 legacy-protocol probes were inconclusive (network errors, not a refusal by the server)", inconclusive)
	}
	return res
}

// legacyRejected is true when the server answered the legacy ClientHello by
// refusing it. A server may do so with an alert, with a version it was not
// offered, or by closing the connection; a timeout is not a refusal.
func legacyRejected(err error) bool {
	m := strings.ToLower(err.Error())
	for _, s := range []string{
		"protocol version not supported", "handshake failure", "insufficient security",
		"server selected unsupported protocol version", "unsupported versions",
		"eof", "connection reset by peer", "broken pipe",
	} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
