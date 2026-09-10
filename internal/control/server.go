package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"defendsec/internal/cmdlog"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/pki"
	"defendsec/internal/presence"
	"defendsec/internal/sca"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

type Server struct {
	defendsecv1.UnimplementedAgentControlServer
	bundle     *pki.Bundle
	secret     string
	adminToken  string
	viewerToken string
	dataDir     string
	store      *presence.File
	commands   *cmdlog.File
	pg         *storepg.Store
	hub        *Hub
	signer     *sign.Key
	log        *slog.Logger
}

func New(bundle *pki.Bundle, secret, adminToken, dataDir string, store *presence.File, commands *cmdlog.File, signer *sign.Key, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	if dataDir == "" {
		dataDir = "data"
	}
	return &Server{
		bundle:     bundle,
		secret:     secret,
		adminToken: adminToken,
		dataDir:    dataDir,
		store:      store,
		commands:   commands,
		hub:        NewHub(),
		signer:     signer,
		log:        log,
	}
}

func (s *Server) SetPostgres(pg *storepg.Store) {
	s.pg = pg
}

func (s *Server) SetViewerToken(token string) {
	s.viewerToken = strings.TrimSpace(token)
}

func (s *Server) syncDevice(dev presence.Device) {
	if s.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.pg.UpsertDevice(ctx, dev); err != nil {
		s.log.Warn("postgres upsert device", "err", err, "device", dev.ID)
	}
}

func (s *Server) syncCommand(rec cmdlog.Record) {
	if s.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.pg.AppendCommand(ctx, rec); err != nil {
		s.log.Warn("postgres append command", "err", err)
	}
}

func (s *Server) audit(actor, action, deviceID string, detail any) {
	if s.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.pg.Audit(ctx, actor, action, deviceID, detail)
}

type enrollRequest struct {
	EnrollSecret string `json:"enrollSecret"`
	Hostname     string `json:"hostname"`
	CSR          string `json:"csrPem"`
}

type enrollResponse struct {
	DeviceID      string `json:"deviceId"`
	CertPEM       string `json:"certPem"`
	CAPEM         string `json:"caPem"`
	ControlPubPEM string `json:"controlPubPem"`
}

func (s *Server) HandleCA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.bundle.CACertPEM())
}

func (s *Server) HandleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *Server) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req enrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !secretMatch(req.EnrollSecret, s.secret) {
		http.Error(w, "invalid enroll secret", http.StatusUnauthorized)
		return
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		hostname = "unknown-host"
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "csrPem must be a PEM certificate request", http.StatusBadRequest)
		return
	}
	deviceID, err := newDeviceID()
	if err != nil {
		http.Error(w, "device id", http.StatusInternalServerError)
		return
	}
	certPEM, err := s.bundle.SignCSR(block.Bytes, deviceID, hostname, 90*24*time.Hour)
	if err != nil {
		s.log.Error("sign csr", "err", err)
		http.Error(w, "could not sign csr", http.StatusInternalServerError)
		return
	}
	dev := presence.Device{
		ID:        deviceID,
		Hostname:  hostname,
		LastSeen:  time.Now().UTC().Format(time.RFC3339),
		Connected: false,
		Transport: "mtls-grpc",
	}
	_ = s.store.Upsert(dev)
	s.syncDevice(dev)
	s.audit("enroll", "device_enrolled", deviceID, map[string]any{"hostname": hostname})
	resp := enrollResponse{
		DeviceID:      deviceID,
		CertPEM:       string(certPEM),
		CAPEM:         string(s.bundle.CACertPEM()),
		ControlPubPEM: string(s.signer.PublicPEM()),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error("encode enroll", "err", err)
	}
}

func (s *Server) Heartbeat(ctx context.Context, req *defendsecv1.HeartbeatRequest) (*defendsecv1.HeartbeatResponse, error) {
	id, fp, err := peerIdentity(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.ensureNotRevoked(ctx, fp); err != nil {
		return nil, err
	}
	dev := presence.Device{
		ID:              id,
		Hostname:        req.GetHostname(),
		Platform:        req.GetPlatform(),
		OSName:          req.GetOsName(),
		OSVersion:       req.GetOsVersion(),
		Arch:            req.GetArch(),
		UptimeSeconds:   req.GetUptimeSeconds(),
		LastSeen:        time.Now().UTC().Format(time.RFC3339),
		Connected:       true,
		CertFingerprint: fp,
		Transport:       "mtls-grpc",
		Isolated:        req.GetIsolated(),
	}
	if err := s.store.Upsert(dev); err != nil {
		s.log.Error("presence upsert", "err", err)
		return nil, status.Error(codes.Internal, "presence")
	}
	if got, ok := s.store.Get(id); ok {
		s.syncDevice(got)
	} else {
		s.syncDevice(dev)
	}
	return &defendsecv1.HeartbeatResponse{Ok: true, ServerTimeUnix: time.Now().Unix()}, nil
}

func (s *Server) ReportInventory(ctx context.Context, req *defendsecv1.InventoryReport) (*defendsecv1.HeartbeatResponse, error) {
	id, fp, err := peerIdentity(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.ensureNotRevoked(ctx, fp); err != nil {
		return nil, err
	}
	host := req.GetHost()
	dev := presence.Device{
		ID:              id,
		Hostname:        host.GetHostname(),
		Platform:        host.GetPlatform(),
		OSName:          host.GetOsName(),
		OSVersion:       host.GetOsVersion(),
		Arch:            host.GetArch(),
		UptimeSeconds:   host.GetUptimeSeconds(),
		LastSeen:        time.Now().UTC().Format(time.RFC3339),
		Connected:       true,
		CertFingerprint: fp,
		Transport:       "mtls-grpc",
		Isolated:        host.GetIsolated(),
		Serial:          req.GetSerial(),
		HardwareModel:   req.GetHardwareModel(),
		CPU:             req.GetCpu(),
		MemoryMb:        req.GetMemoryMb(),
		DiskEncryption:  triBool(req.GetDiskEncryption()),
		Firewall:        triBool(req.GetFirewall()),
		IPAddresses:     req.GetIpAddresses(),
		Username:        req.GetUsername(),
		PatchInventory:  req.GetPatchInventory(),
	}
	for _, item := range req.GetSoftware() {
		dev.Software = append(dev.Software, presence.Software{Name: item.GetName(), Version: item.GetVersion()})
	}
	for _, item := range req.GetPendingUpdates() {
		dev.PendingUpdates = append(dev.PendingUpdates, presence.Update{
			Name: item.GetName(), Current: item.GetCurrent(), Available: item.GetAvailable(),
		})
	}
	for _, item := range req.GetFim() {
		dev.Fim = append(dev.Fim, presence.FimFile{
			Path: item.GetPath(), SHA256: item.GetSha256(), Size: item.GetSize(), Mtime: item.GetMtime(),
		})
	}
	for _, item := range req.GetScaResults() {
		dev.ScaResults = append(dev.ScaResults, presence.ScaResult{
			PackID: item.GetPackId(), CheckID: item.GetCheckId(), Title: item.GetTitle(),
			Severity: item.GetSeverity(), Pass: item.GetPass(), Detail: item.GetDetail(),
		})
	}
	events, err := s.store.ApplyInventory(dev)
	if err != nil {
		s.log.Error("inventory", "err", err)
		return nil, status.Error(codes.Internal, "inventory")
	}
	merged := dev
	if got, ok := s.store.Get(id); ok {
		merged = got
	}
	merged.ScaResults = s.evaluateSca(merged, merged.ScaResults)
	if err := s.store.Upsert(merged); err != nil {
		s.log.Warn("sca merge upsert", "err", err)
	}
	s.syncDevice(merged)
	s.processFimAlerts(events)
	s.processDriftAlerts(merged)
	s.processScaAlerts(merged, toScaResults(merged.ScaResults))
	s.processVulnAlerts(merged)
	if s.pg != nil {
		ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, ev := range events {
			if err := s.pg.AppendFimEvent(ctx2, ev); err != nil {
				s.log.Warn("postgres fim event", "err", err)
			}
		}
	}
	return &defendsecv1.HeartbeatResponse{Ok: true, ServerTimeUnix: time.Now().Unix()}, nil
}

func toScaResults(in []presence.ScaResult) []sca.Result {
	out := make([]sca.Result, len(in))
	for i, r := range in {
		out[i] = sca.Result{
			PackID: r.PackID, CheckID: r.CheckID, Title: r.Title,
			Severity: r.Severity, Pass: r.Pass, Detail: r.Detail,
		}
	}
	return out
}

func triBool(v int32) *bool {
	switch v {
	case 2:
		t := true
		return &t
	case 1:
		t := false
		return &t
	default:
		return nil
	}
}

func (s *Server) Connect(stream defendsecv1.AgentControl_ConnectServer) error {
	id, fp, err := peerIdentity(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.ensureNotRevoked(stream.Context(), fp); err != nil {
		return err
	}
	s.log.Info("agent connected", "device", id, "fp", fp[:min(12, len(fp))])
	_ = s.store.SetConnected(id, true)
	if s.pg != nil {
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.pg.SetConnected(ctx2, id, true)
		cancel()
	}
	defer func() {
		_ = s.store.SetConnected(id, false)
		if s.pg != nil {
			ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.pg.SetConnected(ctx2, id, false)
			cancel()
		}
		s.log.Info("agent disconnected", "device", id)
	}()

	ch := s.hub.Register(id)
	defer s.hub.Unregister(id, ch)
	s.flushQueued(id)

	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			switch body := msg.GetBody().(type) {
			case *defendsecv1.AgentToServer_Hello:
				s.log.Info("hello", "device", id, "host", body.Hello.GetHostname(), "ver", body.Hello.GetAgentVersion())
			case *defendsecv1.AgentToServer_Heartbeat:
				_, err := s.Heartbeat(stream.Context(), body.Heartbeat)
				if err != nil {
					errCh <- err
					return
				}
			case *defendsecv1.AgentToServer_Ack:
				s.log.Info("ack", "device", id, "command", body.Ack.GetCommandId(), "ok", body.Ack.GetAccepted(), "msg", body.Ack.GetMessage())
				s.noteAck(id, body.Ack.GetAccepted(), body.Ack.GetCommandId(), body.Ack.GetMessage())
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-errCh:
			if err == io.EOF {
				return nil
			}
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		case msg := <-ch:
			if err := stream.Send(msg); err != nil {
				return err
			}
		case <-ticker.C:
			reqID, err := newDeviceID()
			if err != nil {
				return err
			}
			if err := stream.Send(&defendsecv1.ServerToAgent{
				RequestId: reqID,
				Body:      &defendsecv1.ServerToAgent_Ping{Ping: &defendsecv1.Ping{ServerTimeUnix: time.Now().Unix()}},
			}); err != nil {
				return err
			}
		}
	}
}


func (s *Server) ensureNotRevoked(ctx context.Context, fingerprint string) error {
	if s.pg == nil || fingerprint == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	revoked, err := s.pg.IsRevoked(cctx, fingerprint)
	if err != nil {
		s.log.Warn("revoke check", "err", err)
		return nil
	}
	if revoked {
		return status.Error(codes.PermissionDenied, "certificate revoked")
	}
	return nil
}

func peerIdentity(ctx context.Context) (deviceID, fingerprint string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", fmt.Errorf("no peer")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", "", fmt.Errorf("not tls")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", "", fmt.Errorf("no client certificate")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	if cert.Subject.CommonName == "" {
		return "", "", fmt.Errorf("client cert missing CN")
	}
	return cert.Subject.CommonName, pki.Fingerprint(cert), nil
}

func newDeviceID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func UnaryLogging(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		if err != nil {
			log.Warn("grpc", "method", info.FullMethod, "err", err, "dur", time.Since(start))
		}
		return resp, err
	}
}

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

func secretMatch(got, want string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
