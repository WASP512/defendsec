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
	"defendsec/internal/anchor"
	"defendsec/internal/cmdlog"
	"defendsec/internal/control"
	"defendsec/internal/db"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/pki"
	"defendsec/internal/playbook"
	"defendsec/internal/policy"
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
	// Privileged-action history is kept by age rather than by count
	// (roadmap 5.5). The default is the CJIS minimum of one year.
	if v := strings.TrimSpace(os.Getenv("DEFENDSEC_COMMAND_RETENTION_DAYS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			commands.SetRetentionDays(n)
		} else {
			log.Warn("ignoring DEFENDSEC_COMMAND_RETENTION_DAYS", "value", v,
				"reason", "must be a whole number of days; negative keeps everything")
		}
	}
	commands.SetOverflowHandler(func(dropped int) {
		// Reaching the size cap means the age window is not doing its job.
		// Silently discarding signed actions is what this replaced.
		log.Error("command log size cap reached — privileged-action history was discarded",
			"dropped", dropped,
			"fix", "configure Postgres, which retains command history without a cap, or lower DEFENDSEC_COMMAND_RETENTION_DAYS")
	})

	svc := control.New(bundle, secretValue, adminToken, *dataDir, store, commands, signer, log)
	if viewer := strings.TrimSpace(os.Getenv("DEFENDSEC_VIEWER_TOKEN")); viewer != "" {
		svc.SetViewerToken(viewer)
		log.Info("viewer token enabled (GET-only admin API)")
	}

	// Held outside the block so the background checkpoint loop below can use
	// it; nil when no database is configured.
	var pg *storepg.Store

	if url := db.ResolveURL(*dbURL); url != "" {
		pool, err := db.Open(context.Background(), url)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		if err := migrations.Apply(context.Background(), pool); err != nil {
			return fmt.Errorf("postgres migrations: %w", err)
		}
		pg = storepg.New(pool)
		svc.SetPostgres(pg)
		log.Info("postgres enabled")
		// One year, the CJIS Policy Area 4 minimum, rather than the 90 days
		// this used to default to (roadmap 5.5). DefendSec's compliance view
		// claims to evidence audit retention; a default below the minimum of
		// the framework it names would make that claim false out of the box,
		// and the deployments that most need the history are the least likely
		// to have configured it.
		alertDays := 365
		if v := strings.TrimSpace(os.Getenv("DEFENDSEC_ALERT_RETENTION_DAYS")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				alertDays = n
			}
		}
		// Live query results are operational output rather than an audit
		// record, so a shorter window is right — they are large, and the
		// signed command and its acknowledgement are what the ledger keeps.
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
	adminMux.HandleFunc("/v1/retention", svc.HandleRetention)

	// Compliance (roadmap 1.7).
	adminMux.HandleFunc("/v1/controls", svc.HandleControls)
	adminMux.HandleFunc("/v1/controls/check-coverage", svc.HandleCheckCoverage)

	// The audit layer (roadmap 1.9).
	adminMux.HandleFunc("/v1/audit/periods", svc.HandleAuditPeriods)
	adminMux.HandleFunc("/v1/audit/periods/close", svc.HandleAuditPeriodClose)
	adminMux.HandleFunc("/v1/audit/exceptions", svc.HandleControlExceptions)
	adminMux.HandleFunc("/v1/audit/assessment", svc.HandleAuditAssessment)
	adminMux.HandleFunc("/v1/audit/evidence", svc.HandleEvidenceExport)

	// Policy sits between the API and the signer (roadmap 2.1). A deployment
	// with no policy file denies every command, which is the correct posture
	// for an unconfigured response tool — but it would be a surprise, so it
	// is stated loudly at startup rather than discovered at an incident.
	if path := strings.TrimSpace(os.Getenv("DEFENDSEC_POLICY_FILE")); path != "" {
		doc, err := policy.Load(path)
		if err != nil {
			// Refused rather than started without it. Coming up with no
			// policy because the file had a typo would silently disable every
			// host action, and the operator would find out during an incident.
			return fmt.Errorf("policy: %w", err)
		}
		svc.SetPolicy(policy.NewEngine(doc))
		log.Info("policy loaded", "name", doc.Name, "rules", len(doc.Rules),
			"limits", len(doc.Limits), "hash", doc.Hash[:16], "source", doc.Source)
	} else {
		log.Warn("no policy file configured; every host command will be denied",
			"fix", "set DEFENDSEC_POLICY_FILE to a policy document, for example packaging/policy/default.yaml")
	}

	// Playbooks (roadmap 2.5-2.6). Every step is still policy-checked and
	// signed individually, so loading a playbook grants nothing on its own.
	if dir := strings.TrimSpace(os.Getenv("DEFENDSEC_PLAYBOOK_DIR")); dir != "" {
		set, err := playbook.LoadDir(dir)
		if err != nil {
			// One bad file fails the load. A partial set means the operator
			// believes a playbook exists when it does not, and finds out
			// during the incident it was written for.
			return fmt.Errorf("playbooks: %w", err)
		}
		svc.SetPlaybooks(set)
		var automatic int
		for _, pb := range set.All() {
			if pb.Automatic {
				automatic++
			}
		}
		log.Info("playbooks loaded", "count", set.Len(), "automatic", automatic, "dir", dir)
		if automatic > 0 {
			log.Warn("automatic response is enabled for some playbooks",
				"automatic", automatic,
				"note", "these run without human confirmation when policy permits every step")
		}
	}

	// Transparency anchoring (roadmap 1.6).
	adminMux.HandleFunc("/v1/audit/anchors", svc.HandleAnchors)
	// The peer receive endpoint is on the admin listener because that is the
	// interface an operator chooses to expose; it authenticates with its own
	// shared token rather than the admin one, so a peer never holds admin
	// access to the instance it anchors for.
	adminMux.HandleFunc("/v1/anchors/receive", svc.HandleAnchorReceive)

	// Policy-governed response (roadmap 2.1-2.4).
	adminMux.HandleFunc("/v1/policy", svc.HandlePolicy)
	adminMux.HandleFunc("/v1/policy/decisions", svc.HandlePolicyDecisions)
	adminMux.HandleFunc("/v1/policy/approvals", svc.HandleApprovals)
	adminMux.HandleFunc("/v1/policy/break-glass", svc.HandleBreakGlass)
	adminMux.HandleFunc("/v1/policy/host-classes", svc.HandleHostClasses)
	adminMux.HandleFunc("/v1/playbooks", svc.HandlePlaybooks)

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

	// Playbooks (roadmap 2.5-2.6). Every step is still policy-checked and
	// signed individually, so loading a playbook grants nothing on its own.
	if dir := strings.TrimSpace(os.Getenv("DEFENDSEC_PLAYBOOK_DIR")); dir != "" {
		set, err := playbook.LoadDir(dir)
		if err != nil {
			// One bad file fails the load. A partial set means the operator
			// believes a playbook exists when it does not, and finds out
			// during the incident it was written for.
			return fmt.Errorf("playbooks: %w", err)
		}
		svc.SetPlaybooks(set)
		var automatic int
		for _, pb := range set.All() {
			if pb.Automatic {
				automatic++
			}
		}
		log.Info("playbooks loaded", "count", set.Len(), "automatic", automatic, "dir", dir)
		if automatic > 0 {
			log.Warn("automatic response is enabled for some playbooks",
				"automatic", automatic,
				"note", "these run without human confirmation when policy permits every step")
		}
	}

	// Transparency anchoring (roadmap 1.6). Unset means no anchoring, which is
	// a real posture rather than a broken one — the ledger is still
	// tamper-evident against anyone who cannot also sign checkpoints.
	if raw := strings.TrimSpace(os.Getenv("DEFENDSEC_ANCHOR_TARGETS")); raw != "" {
		targets, err := anchor.ParseTargets(raw)
		if err != nil {
			// Refused rather than skipped: an operator who mistyped a target
			// would otherwise believe they have anchoring they do not have,
			// and stop looking.
			return fmt.Errorf("DEFENDSEC_ANCHOR_TARGETS: %w", err)
		}
		server := strings.TrimSpace(os.Getenv("DEFENDSEC_PUBLIC_CONSOLE_URL"))
		if server == "" {
			server, _ = os.Hostname()
		}
		svc.SetAnchoring(anchor.NewPublisher(targets, server),
			strings.TrimSpace(os.Getenv("DEFENDSEC_PEER_ANCHOR_TOKEN")))
		for _, t := range targets {
			log.Info("anchor target configured", "kind", t.Kind, "target", t.Ref)
		}
	} else if token := strings.TrimSpace(os.Getenv("DEFENDSEC_PEER_ANCHOR_TOKEN")); token != "" {
		// Holding anchors for a peer without publishing any of your own is a
		// legitimate arrangement, so it is configured independently.
		svc.SetAnchoring(nil, token)
		log.Info("accepting peer anchors")
	}

	rootCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	// Checkpoint and anchor on a timer.
	//
	// Checkpoints were signed on demand and never scheduled, so in practice a
	// deployment had none — and an anchor needs a checkpoint to anchor. The
	// two run together: sign the tip, then publish it externally.
	if pg != nil && signer != nil {
		interval := 6 * time.Hour
		if v := strings.TrimSpace(os.Getenv("DEFENDSEC_CHECKPOINT_INTERVAL")); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
				interval = d
			} else {
				log.Warn("ignoring DEFENDSEC_CHECKPOINT_INTERVAL", "value", v,
					"reason", "must be a duration of at least one minute")
			}
		}
		go runCheckpointLoop(rootCtx, pg, svc, signer, interval, log)
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
		stopBackground()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		_ = adminSrv.Shutdown(ctx)
		grpcSrv.GracefulStop()
		return nil
	}
}

// runCheckpointLoop signs the tip of the audit chain on an interval and
// publishes it to any configured anchor targets.
//
// Anchoring failures are logged and otherwise ignored: a timestamp authority
// being unreachable must not stop the next checkpoint from being signed, and
// the failure is stored as an anchor record so it is visible in the console
// rather than only in a log nobody reads.
func runCheckpointLoop(
	ctx context.Context,
	pg *storepg.Store,
	svc *control.Server,
	signer *sign.Key,
	interval time.Duration,
	log *slog.Logger,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		cp, ok, err := pg.AppendCheckpoint(runCtx, signer.Private, signer.KeyID())
		if err != nil {
			log.Warn("append audit checkpoint", "err", err)
			cancel()
			continue
		}
		if !ok {
			// Nothing chained yet; nothing to attest.
			cancel()
			continue
		}
		log.Info("audit checkpoint signed", "throughSeq", cp.ThroughSeq)

		if records, anchored, err := svc.AnchorLatest(runCtx); err != nil {
			log.Warn("anchor checkpoint", "err", err)
		} else if anchored {
			for _, r := range records {
				if r.OK() {
					log.Info("checkpoint anchored", "kind", r.Kind, "target", r.Target,
						"throughSeq", r.ThroughSeq, "reference", r.Reference)
				} else {
					log.Warn("checkpoint anchor failed", "kind", r.Kind, "target", r.Target,
						"throughSeq", r.ThroughSeq, "err", r.Error)
				}
			}
		}
		cancel()
	}
}
