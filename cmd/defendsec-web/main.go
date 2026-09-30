// Command defendsec-web terminates HTTPS in front of the console
// (roadmap 5.3).
//
// The console is Next.js, which does not serve HTTPS in production — the
// documented answer is a reverse proxy. Rather than require every operator to
// install and configure one, DefendSec ships the terminator. The console then
// binds to loopback, so the plain-HTTP port is not reachable off the box.
//
// Plain HTTP remains available for isolated labs, but only as an explicit
// opt-out: DEFENDSEC_TLS=off, which is logged loudly at every start.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"defendsec/internal/webtls"
)

// buildCommit is the source commit this binary was built from, stamped by
// scripts/build-release.sh (roadmap 5.7).
//
// Stamped explicitly rather than left to Go's automatic VCS stamping, which
// is switched off in release builds: automatic stamping makes the binary
// depend on a .git directory being present, so a verifier rebuilding from a
// source tarball gets a different hash than the release. An explicit value is
// a build input, and reproducing the release means passing the same one.
var buildCommit = "unknown"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("defendsec-web", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	// No flags on this binary — it is configured entirely by environment, so
	// the build commit is reported in the startup log instead. An operator
	// checking which build is serving their TLS has to be able to find it
	// somewhere.
	log.Info("defendsec-web starting", "commit", buildCommit)

	mode, err := webtls.ParseMode(os.Getenv("DEFENDSEC_TLS"))
	if err != nil {
		// An unrecognised value is refused rather than falling back. Falling
		// back to plain HTTP because somebody typed "tls" instead of "on"
		// would silently undo the point of this.
		return err
	}

	// The front-end takes 47261 — the port operators, bookmarks and agent
	// installers already use — and serves HTTPS on it. The console moves to a
	// loopback-only port behind it, so nothing plain is reachable off the box.
	upstream := envOr("DEFENDSEC_CONSOLE_UPSTREAM", "http://127.0.0.1:47265")
	listen := envOr("DEFENDSEC_WEB_ADDR", ":47261")

	// The plain-HTTP redirector is off unless a port is given. It cannot
	// share 47261 with HTTPS, and guessing a second port would collide with
	// the agent listeners. Port 80 is the usual choice, and ACME needs it.
	httpAddr := strings.TrimSpace(os.Getenv("DEFENDSEC_WEB_HTTP_ADDR"))
	if mode == webtls.ModeACME && httpAddr == "" {
		// http-01 is answered on port 80 by definition, so a missing value
		// here is a misconfiguration that would fail at renewal rather than
		// at startup.
		return fmt.Errorf(
			"ACME needs DEFENDSEC_WEB_HTTP_ADDR set to :80 so Let's Encrypt can reach the http-01 challenge")
	}

	target, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("DEFENDSEC_CONSOLE_UPSTREAM: %w", err)
	}

	provider, err := webtls.New(webtls.Config{
		Mode:          mode,
		Dir:           envOr("DEFENDSEC_TLS_DIR", "/var/lib/defendsec/tls"),
		Hosts:         splitHosts(os.Getenv("DEFENDSEC_TLS_HOSTS")),
		CertFile:      os.Getenv("DEFENDSEC_TLS_CERT"),
		KeyFile:       os.Getenv("DEFENDSEC_TLS_KEY"),
		ACMEEmail:     os.Getenv("DEFENDSEC_ACME_EMAIL"),
		ACMEAcceptTOS: truthy(os.Getenv("DEFENDSEC_ACME_ACCEPT_TOS")),
	})
	if err != nil {
		return err
	}

	proxy := newProxy(target, provider.Enabled())
	srv := &http.Server{
		Addr:              listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if !provider.Enabled() {
		// Never silent. An operator who did not mean to disable TLS should
		// see it in the first line of the log, not discover it in a browser.
		log.Warn("TLS IS DISABLED — the console and its admin token travel in clear text",
			"addr", listen,
			"fix", "unset DEFENDSEC_TLS, or set it to on, to serve HTTPS")
		return serve(log, srv, nil, "http")
	}

	tlsCfg, err := provider.TLSConfig()
	if err != nil {
		return err
	}
	srv.TLSConfig = tlsCfg

	if fp, err := provider.Fingerprint(); err == nil && fp != "" {
		// With a self-signed certificate this comparison is the only
		// verification available, so it has to be in front of the operator
		// rather than buried in a file.
		log.Info("console certificate", "mode", provider.Mode(), "sha256", fp)
	}

	// When configured, a plain-HTTP port answers the ACME challenge and
	// otherwise redirects to HTTPS, so an operator who types http:// lands on
	// the console rather than on a connection refused.
	if httpAddr != "" {
		go runRedirector(log, provider, httpAddr, listen)
	}

	return serve(log, srv, tlsCfg, "https")
}

func serve(log *slog.Logger, srv *http.Server, tlsCfg any, scheme string) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", srv.Addr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("console front-end listening", "addr", srv.Addr, "scheme", scheme)
		if tlsCfg != nil {
			errCh <- srv.ServeTLS(ln, "", "")
			return
		}
		errCh <- srv.Serve(ln)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// runRedirector serves the ACME challenge and redirects plain HTTP.
func runRedirector(log *slog.Logger, provider *webtls.Provider, addr, httpsAddr string) {
	redirect := func(w http.ResponseWriter, r *http.Request) {
		redirectToHTTPS(w, r, httpsAddr)
	}

	var handler http.Handler = http.HandlerFunc(redirect)
	if m := provider.Manager(); m != nil {
		handler = m.HTTPHandler(http.HandlerFunc(redirect))
	}

	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// Not fatal: the redirector is a convenience, and HTTPS is already
		// serving. Losing it must not take the console down.
		log.Warn("http redirector stopped", "addr", addr, "err", err)
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request, httpsAddr string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Carry the HTTPS port across, unless it is the default one a browser
	// would assume anyway.
	if port := strings.TrimPrefix(httpsAddr, ":"); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	}
	target := "https://" + host + r.URL.RequestURI()
	// 302 rather than 301: a permanent redirect is cached by browsers
	// indefinitely, and an operator who later has to turn TLS off for a lab
	// would find the console unreachable with no obvious cause.
	http.Redirect(w, r, target, http.StatusFound)
}

func newProxy(target *url.URL, secure bool) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host

			// SetXForwarded first, then override. It derives the proto from
			// the inbound connection's own TLS state and overwrites whatever
			// was there, so setting the headers before it silently loses
			// them — and the console would then drop the Secure cookie flag
			// exactly when TLS is on.
			r.SetXForwarded()

			// The console decides cookie flags and builds absolute URLs from
			// these, so they have to describe what the browser did rather
			// than the loopback hop that follows.
			r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
			if secure {
				r.Out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Out.Header.Set("X-Forwarded-Proto", "http")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// The console being down is an operational fact, not a 500 from
			// the console itself, and saying so saves a round of confusion.
			http.Error(w,
				"The DefendSec console is not responding. Check: systemctl status defendsec-console",
				http.StatusBadGateway)
			_ = err
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secure {
			// Only sent over HTTPS: on plain HTTP it is meaningless, and
			// sending it from a lab deployment would pin browsers to a scheme
			// that deployment does not serve.
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		proxy.ServeHTTP(w, r)
	})
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitHosts(raw string) []string {
	var out []string
	for _, h := range strings.Split(raw, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
