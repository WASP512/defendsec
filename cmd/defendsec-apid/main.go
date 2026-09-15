package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"defendsec/db/migrations"
	"defendsec/internal/cmdlog"
	"defendsec/internal/control"
	"defendsec/internal/db"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/pki"
	"defendsec/internal/presence"
	"defendsec/internal/secret"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// requireLoopbackAdminAddr fails fast unless the admin API binds to loopback.
// That listener trusts the bearer token alone with no other network control,
// so exposing it beyond localhost turns a leaked/guessed admin token into
// full remote control. Set DEFENDSEC_ALLOW_NONLOOPBACK_ADMIN=1 to override
// when the operator has their own network isolation in front of it.
func requireLoopbackAdminAddr(addr string) error {
	if strings.TrimSpace(os.Getenv("DEFENDSEC_ALLOW_NONLOOPBACK_ADMIN")) == "1" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin-addr %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf(
		"admin-addr %q is not loopback; set DEFENDSEC_ALLOW_NONLOOPBACK_ADMIN=1 to override if you have your own network isolation in front of it",
		addr,
	)
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("defendsec-apid", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dataDir := flag.String("data-dir", "data", "directory for PKI and presence files")
	httpAddr := flag.String("http-addr", "0.0.0.0:47262", "HTTPS enroll/health listen address")
	grpcAddr := flag.String("grpc-addr", "0.0.0.0:47263", "mTLS gRPC listen address")
	adminAddr := flag.String("admin-addr", "127.0.0.1:47264", "loopback HTTP for signed commands (admin token)")
	enrollSecret := flag.String("enroll-secret", "", "override enroll secret (default: DEFENDSEC_ENROLL_SECRET or data/defendsec.json)")
	adminTokenFlag := flag.String("admin-token", "", "override admin token (default: DEFENDSEC_ADMIN_TOKEN or data/admin-token.txt)")
	advertise := flag.String("tls-hostname", strings.TrimSpace(os.Getenv("DEFENDSEC_TLS_HOSTNAME")), "extra hostname/IP SAN for the server certificate (or DEFENDSEC_TLS_HOSTNAME)")
	dbURL := flag.String("db-url", "", "Postgres URL (or DATABASE_URL / DEFENDSEC_DATABASE_URL)")
	flag.Parse()

	if err := requireLoopbackAdminAddr(*adminAddr); err != nil {
		return err
	}

	pkiDir := filepath.Join(*dataDir, "pki")
	hosts := []string{}
	for _, part := range strings.Split(*advertise, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			hosts = append(hosts, part)
		}
	}
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	bundle, err := pki.LoadOrCreate(pkiDir, hosts)
	if err != nil {
		return fmt.Errorf("pki: %w", err)
	}

	secretValue, err := secret.Resolve(*enrollSecret, filepath.Join(*dataDir, "defendsec.json"))
	if err != nil {
		return err
	}

	signer, err := sign.LoadOrCreate(pkiDir)
	if err != nil {
		return fmt.Errorf("control signing key: %w", err)
	}
	adminToken, err := secret.ResolveAdmin(*adminTokenFlag, filepath.Join(*dataDir, "admin-token.txt"))
	if err != nil {
		return fmt.Errorf("admin token (start the console once so data/admin-token.txt exists): %w", err)
	}

	store := presence.New(filepath.Join(*dataDir, "defendsec-agents.json"))
	commands := cmdlog.New(filepath.Join(*dataDir, "commands.json"))
	svc := control.New(bundle, secretValue, adminToken, *dataDir, store, commands, signer, log)
	if viewer := strings.TrimSpace(os.Getenv("DEFENDSEC_VIEWER_TOKEN")); viewer != "" {
		svc.SetViewerToken(viewer)
		log.Info("viewer token enabled (GET-only admin API)")
	}

	if url := db.ResolveURL(*dbURL); url != "" {
		pool, err := db.Open(context.Background(), url)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		if err := migrations.Apply(context.Background(), pool); err != nil {
			return fmt.Errorf("postgres migrations: %w", err)
		}
		pg := storepg.New(pool)
		svc.SetPostgres(pg)
		log.Info("postgres enabled")
		alertDays := 90
		if v := strings.TrimSpace(os.Getenv("DEFENDSEC_ALERT_RETENTION_DAYS")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				alertDays = n
			}
		}
		liveDays := 30
		if v := strings.TrimSpace(os.Getenv("DEFENDSEC_LIVE_QUERY_RETENTION_DAYS")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				liveDays = n
			}
		}
		pruneCtx, pruneCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if result, err := pg.PruneOld(pruneCtx, alertDays, liveDays); err != nil {
			log.Warn("retention prune", "err", err)
		} else if result.AlertsDeleted > 0 || result.LiveQueryDeleted > 0 {
			log.Info("retention prune", "alerts", result.AlertsDeleted, "liveQueries", result.LiveQueryDeleted)
		}
		// Expired sessions are pruned alongside the other retention work
		// rather than left to accumulate (roadmap 1.0).
		sessCtx, sessCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if n, err := pg.PruneExpiredSessions(sessCtx, time.Now().UTC()); err != nil {
			log.Warn("session prune", "err", err)
		} else if n > 0 {
			log.Info("session prune", "sessions", n)
		}
		sessCancel()
		pruneCancel()

		// Materialise the compiled-in control catalog so compliance queries
		// can join it in SQL (roadmap 1.7). The Go registry remains the
		// source of truth; this is rebuilt from it on every start.
		ctlCtx, ctlCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if n, err := pg.SyncControlCatalog(ctlCtx); err != nil {
			log.Warn("control catalog sync", "err", err)
		} else {
			log.Info("control catalog sync", "controls", n)
		}
		ctlCancel()
		defer pool.Close()
	}

	httpTLS, err := bundle.ServerTLS()
	if err != nil {
		return err
	}
	grpcTLS, err := bundle.GRPCTLS()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", svc.HandleHealth)
	mux.HandleFunc("/v1/ca", svc.HandleCA)
	mux.HandleFunc("/v1/enroll", svc.HandleEnroll)
	mux.HandleFunc("/v1/control-pub", svc.HandleControlPub)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", svc.HandleHealth)
	adminMux.HandleFunc("/v1/enroll-secret", svc.HandleEnrollSecret)
	adminMux.HandleFunc("/v1/commands", svc.HandleAdminCommands)
	adminMux.HandleFunc("/v1/baseline", svc.HandleBaseline)
	adminMux.HandleFunc("/v1/control-pub", svc.HandleControlPub)
	adminMux.HandleFunc("/v1/audit", svc.HandleAudit)
	adminMux.HandleFunc("/v1/revoke", svc.HandleRevoke)
	adminMux.HandleFunc("/v1/meta", svc.HandleMeta)
	adminMux.HandleFunc("/v1/advisories", svc.HandleAdvisories)
	adminMux.HandleFunc("/v1/agent-releases", svc.HandleAgentReleases)
	adminMux.HandleFunc("/v1/saved-queries", svc.HandleSavedQueries)
	adminMux.HandleFunc("/v1/alerts", svc.HandleAlerts)
	adminMux.HandleFunc("/v1/alerts/status", svc.HandleAlerts)

	// Identity (roadmap 1.0). Login and session are unauthenticated by
	// necessity; everything else resolves the caller's own session token.
	adminMux.HandleFunc("/v1/login", svc.HandleLogin)
	adminMux.HandleFunc("/v1/logout", svc.HandleLogout)
	adminMux.HandleFunc("/v1/session", svc.HandleSession)
	adminMux.HandleFunc("/v1/users", svc.HandleUsers)
	adminMux.HandleFunc("/v1/users/update", svc.HandleUserUpdate)
	adminMux.HandleFunc("/v1/totp", svc.HandleTOTP)
	adminMux.HandleFunc("/v1/crypto-posture", svc.HandleCryptoPosture)

	// Compliance (roadmap 1.7).
	adminMux.HandleFunc("/v1/controls", svc.HandleControls)
	adminSrv := &http.Server{
		Addr:              *adminAddr,
		Handler:           adminMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(grpcTLS)),
		grpc.UnaryInterceptor(control.UnaryLogging(log)),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	defendsecv1.RegisterAgentControlServer(grpcSrv, svc)

	httpLn, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	grpcLn, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}

	errCh := make(chan error, 3)
	go func() {
		log.Info("https enroll listening", "addr", *httpAddr, "secret_fp", control.HashSecret(secretValue))
		errCh <- httpSrv.Serve(tls.NewListener(httpLn, httpTLS))
	}()
	go func() {
		log.Info("mtls grpc listening", "addr", *grpcAddr)
		errCh <- grpcSrv.Serve(grpcLn)
	}()
	go func() {
		log.Info("admin commands listening", "addr", *adminAddr)
		errCh <- adminSrv.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-sig:
		log.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		_ = adminSrv.Shutdown(ctx)
		grpcSrv.GracefulStop()
		return nil
	}
}
