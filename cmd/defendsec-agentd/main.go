package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"defendsec/internal/agentcmd"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/agentfim"
	"defendsec/internal/hostinv"
	"defendsec/internal/sign"
)

const agentVersion = "0.6.0-phase6"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("defendsec-agentd", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	serverHTTP := flag.String("server-http", "https://127.0.0.1:47262", "control plane HTTPS base URL")
	serverGRPC := flag.String("server-grpc", "127.0.0.1:47263", "control plane gRPC host:port")
	enrollSecret := flag.String("enroll-secret", os.Getenv("DEFENDSEC_ENROLL_SECRET"), "enroll secret")
	enrollFile := flag.String("enroll-secret-file", "", "file containing the enroll secret")
	stateDir := flag.String("state-dir", "data/agent-mtls", "where to store CA, client cert, and key")
	tlsServerName := flag.String("tls-server-name", "localhost", "SNI / hostname to verify on the server certificate")
	heartbeatEvery := flag.Duration("heartbeat", 20*time.Second, "unary heartbeat interval")
	flag.Parse()

	secret := *enrollSecret
	if *enrollFile != "" {
		raw, err := os.ReadFile(*enrollFile)
		if err != nil {
			return fmt.Errorf("enroll secret file: %w", err)
		}
		secret = strings.TrimSpace(string(raw))
	}

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}

	if err := ensureEnrolled(log, *serverHTTP, *tlsServerName, *stateDir, secret); err != nil {
		return err
	}
	if err := ensureControlPub(log, *serverHTTP, *tlsServerName, *stateDir); err != nil {
		return err
	}
	pub, err := loadControlPub(*stateDir)
	if err != nil {
		return err
	}
	deviceID := strings.TrimSpace(readString(filepath.Join(*stateDir, "device-id")))

	tlsCfg, err := clientTLS(*stateDir, *tlsServerName)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(
		*serverGRPC,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}
	defer conn.Close()
	client := defendsecv1.NewAgentControlClient(conn)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go runStream(ctx, log, client, pub, deviceID, *stateDir)
	go runInventory(ctx, log, client, *stateDir)
	go runFimWatch(ctx, log, client, *stateDir)
	runHeartbeats(ctx, log, client, *heartbeatEvery, *stateDir)
	return nil
}

func ensureEnrolled(log *slog.Logger, httpBase, serverName, stateDir, secret string) error {
	certPath := filepath.Join(stateDir, "client.pem")
	keyPath := filepath.Join(stateDir, "client.key")
	caPath := filepath.Join(stateDir, "ca.pem")
	if fileExists(certPath) && fileExists(keyPath) && fileExists(caPath) {
		return nil
	}
	if secret == "" {
		return fmt.Errorf("missing enroll secret (and no existing client cert in %s)", stateDir)
	}
	log.Info("bootstrapping CA (TOFU) then enrolling")
	caPEM, err := fetchCA(httpBase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: host, Organization: []string{"DefendSec agent"}},
	}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("invalid CA from control plane")
	}
	body, err := json.Marshal(map[string]string{
		"enrollSecret": secret,
		"hostname":     host,
		"csrPem":       string(csrPEM),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, httpBase+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
				ServerName: serverName,
			},
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enroll failed: %s %s", resp.Status, raw)
	}
	var out struct {
		DeviceID      string `json:"deviceId"`
		CertPEM       string `json:"certPem"`
		CAPEM         string `json:"caPem"`
		ControlPubPEM string `json:"controlPubPem"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, []byte(out.CertPEM), 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if out.CAPEM != "" {
		_ = os.WriteFile(caPath, []byte(out.CAPEM), 0o644)
	}
	if out.ControlPubPEM != "" {
		_ = os.WriteFile(filepath.Join(stateDir, "control.pub"), []byte(out.ControlPubPEM), 0o644)
	}
	_ = os.WriteFile(filepath.Join(stateDir, "device-id"), []byte(out.DeviceID+"\n"), 0o644)
	log.Info("enrolled", "device", out.DeviceID)
	return nil
}

func fetchCA(httpBase string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, httpBase+"/v1/ca", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true, // TOFU: pin the downloaded CA immediately after
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch ca: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch ca: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<16))
}

func clientTLS(stateDir, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, "client.pem"), filepath.Join(stateDir, "client.key"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid ca.pem")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
	}, nil
}

func runHeartbeats(ctx context.Context, log *slog.Logger, client defendsecv1.AgentControlClient, every time.Duration, stateDir string) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	send := func() {
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		resp, err := client.Heartbeat(hctx, heartbeat(stateDir))
		if err != nil {
			log.Warn("heartbeat", "err", err)
			return
		}
		log.Info("heartbeat ok", "server_time", resp.GetServerTimeUnix())
	}
	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func runStream(ctx context.Context, log *slog.Logger, client defendsecv1.AgentControlClient, pub ed25519.PublicKey, deviceID, stateDir string) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := attachStream(ctx, log, client, pub, deviceID, stateDir); err != nil && ctx.Err() == nil {
			log.Warn("control stream", "err", err, "retry", backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		return
	}
}

func attachStream(ctx context.Context, log *slog.Logger, client defendsecv1.AgentControlClient, pub ed25519.PublicKey, deviceID, stateDir string) error {
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if err := stream.Send(&defendsecv1.AgentToServer{
		Body: &defendsecv1.AgentToServer_Hello{Hello: &defendsecv1.Hello{Hostname: host, AgentVersion: agentVersion}},
	}); err != nil {
		return err
	}
	log.Info("control stream up")
	replay := newReplay()
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch body := msg.GetBody().(type) {
		case *defendsecv1.ServerToAgent_Ping:
			ack := &defendsecv1.CommandAck{CommandId: msg.GetRequestId(), Accepted: true, Message: "pong"}
			if err := stream.Send(&defendsecv1.AgentToServer{
				RequestId: msg.GetRequestId(),
				Body:      &defendsecv1.AgentToServer_Ack{Ack: ack},
			}); err != nil {
				return err
			}
			log.Info("pong", "server_time", body.Ping.GetServerTimeUnix())
		case *defendsecv1.ServerToAgent_Command:
			ack := executeCommand(log, pub, deviceID, stateDir, replay, body.Command)
			if err := stream.Send(&defendsecv1.AgentToServer{
				RequestId: msg.GetRequestId(),
				Body:      &defendsecv1.AgentToServer_Ack{Ack: ack},
			}); err != nil {
				return err
			}
			if ack.Accepted {
				log.Info("command accepted", "type", body.Command.GetType(), "id", body.Command.GetCommandId(), "msg", ack.Message)
			} else {
				log.Warn("command rejected", "type", body.Command.GetType(), "id", body.Command.GetCommandId(), "msg", ack.Message)
			}
		}
	}
}

func heartbeat(stateDir string) *defendsecv1.HeartbeatRequest {
	host, _ := os.Hostname()
	platform := runtime.GOOS
	osName := runtime.GOOS
	switch runtime.GOOS {
	case "darwin":
		osName = "macOS"
	case "linux":
		osName = "Linux"
	case "windows":
		osName = "Windows"
	}
	return &defendsecv1.HeartbeatRequest{
		Hostname:      host,
		OsName:        osName,
		OsVersion:     runtime.Version(),
		Arch:          runtime.GOARCH,
		Platform:      platform,
		UptimeSeconds: 0,
		Isolated:      agentcmd.LoadState(stateDir).Isolated,
	}
}


func runFimWatch(ctx context.Context, log *slog.Logger, client defendsecv1.AgentControlClient, stateDir string) {
	trigger := make(chan struct{}, 1)
	stop, err := agentfim.WatchPaths(log, hostinv.FimPaths(), func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	})
	if err != nil {
		log.Warn("fim watcher disabled", "err", err)
		return
	}
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			snap := hostinv.Collect()
			_, err := client.ReportInventory(hctx, inventoryReport(snap, stateDir))
			cancel()
			if err != nil {
				log.Warn("fim-triggered inventory", "err", err)
			} else {
				log.Info("fim-triggered inventory ok", "fim", len(snap.Fim))
			}
		}
	}
}

func runInventory(ctx context.Context, log *slog.Logger, client defendsecv1.AgentControlClient, stateDir string) {
	send := func() {
		snap := hostinv.Collect()
		hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_, err := client.ReportInventory(hctx, inventoryReport(snap, stateDir))
		if err != nil {
			log.Warn("inventory", "err", err)
			return
		}
		log.Info("inventory ok", "software", len(snap.Software), "fim", len(snap.Fim), "patches", len(snap.PendingUpdates))
	}
	send()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func inventoryReport(snap hostinv.Snapshot, stateDir string) *defendsecv1.InventoryReport {
	enc, fw := int32(0), int32(0)
	if snap.DiskEncryption != nil {
		if *snap.DiskEncryption {
			enc = 2
		} else {
			enc = 1
		}
	}
	if snap.Firewall != nil {
		if *snap.Firewall {
			fw = 2
		} else {
			fw = 1
		}
	}
	rep := &defendsecv1.InventoryReport{
		Host:           heartbeat(stateDir),
		Serial:         snap.Serial,
		HardwareModel:  snap.HardwareModel,
		Cpu:            snap.CPU,
		MemoryMb:       snap.MemoryMb,
		DiskEncryption: enc,
		Firewall:       fw,
		IpAddresses:    snap.IPAddresses,
		Username:       snap.Username,
		PatchInventory: snap.PatchInventory,
	}
	rep.Host.Hostname = snap.Hostname
	rep.Host.OsName = snap.OSName
	rep.Host.OsVersion = snap.OSVersion
	rep.Host.Arch = snap.Arch
	rep.Host.Platform = snap.Platform
	rep.Host.UptimeSeconds = snap.UptimeSeconds
	for _, item := range snap.Software {
		rep.Software = append(rep.Software, &defendsecv1.SoftwareItem{Name: item.Name, Version: item.Version})
	}
	for _, item := range snap.PendingUpdates {
		rep.PendingUpdates = append(rep.PendingUpdates, &defendsecv1.PendingUpdate{Name: item.Name, Current: item.Current, Available: item.Available})
	}
	for _, item := range snap.Fim {
		rep.Fim = append(rep.Fim, &defendsecv1.FimFile{Path: item.Path, Sha256: item.SHA256, Size: item.Size, Mtime: item.Mtime})
	}
	return rep
}

func ensureControlPub(log *slog.Logger, httpBase, serverName, stateDir string) error {
	path := filepath.Join(stateDir, "control.pub")
	if fileExists(path) {
		return nil
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("invalid ca.pem")
	}
	req, err := http.NewRequest(http.MethodGet, httpBase+"/v1/control-pub", nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
				ServerName: serverName,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("control-pub: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control-pub: %s %s", resp.Status, raw)
	}
	if _, err := sign.ParsePublicPEM(raw); err != nil {
		return err
	}
	log.Info("pinned control-plane Ed25519 public key")
	return os.WriteFile(path, raw, 0o644)
}

func loadControlPub(stateDir string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "control.pub"))
	if err != nil {
		return nil, err
	}
	return sign.ParsePublicPEM(raw)
}

func readString(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
