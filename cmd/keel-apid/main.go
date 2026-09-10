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
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"keel/internal/cmdlog"
	"keel/internal/control"
	keelv1 "keel/internal/gen/keel/v1"
	"keel/internal/pki"
	"keel/internal/presence"
	"keel/internal/secret"
	"keel/internal/sign"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("keel-apid", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dataDir := flag.String("data-dir", "data", "directory for PKI and presence files")
	httpAddr := flag.String("http-addr", "0.0.0.0:47262", "HTTPS enroll/health listen address")
	grpcAddr := flag.String("grpc-addr", "0.0.0.0:47263", "mTLS gRPC listen address")
	adminAddr := flag.String("admin-addr", "127.0.0.1:47264", "loopback HTTP for signed commands (admin token)")
	enrollSecret := flag.String("enroll-secret", "", "override enroll secret (default: KEEL_ENROLL_SECRET or data/keel.json)")
	adminTokenFlag := flag.String("admin-token", "", "override admin token (default: KEEL_ADMIN_TOKEN or data/admin-token.txt)")
	advertise := flag.String("tls-hostname", "", "extra hostname/IP SAN for the server certificate")
	flag.Parse()

	pkiDir := filepath.Join(*dataDir, "pki")
	hosts := []string{*advertise}
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	bundle, err := pki.LoadOrCreate(pkiDir, hosts)
	if err != nil {
		return fmt.Errorf("pki: %w", err)
	}

	secretValue, err := secret.Resolve(*enrollSecret, filepath.Join(*dataDir, "keel.json"))
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

	store := presence.New(filepath.Join(*dataDir, "mtls-agents.json"))
	commands := cmdlog.New(filepath.Join(*dataDir, "commands.json"))
	svc := control.New(bundle, secretValue, adminToken, store, commands, signer, log)

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
	adminMux.HandleFunc("/v1/commands", svc.HandleAdminCommands)
	adminMux.HandleFunc("/v1/baseline", svc.HandleBaseline)
	adminMux.HandleFunc("/v1/control-pub", svc.HandleControlPub)
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
	keelv1.RegisterAgentControlServer(grpcSrv, svc)

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
