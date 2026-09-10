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

	keelv1 "keel/internal/gen/keel/v1"
	"keel/internal/pki"
	"keel/internal/presence"
)

type Server struct {
	keelv1.UnimplementedAgentControlServer
	bundle *pki.Bundle
	secret string
	store  *presence.File
	log    *slog.Logger
}

func New(bundle *pki.Bundle, secret string, store *presence.File, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{bundle: bundle, secret: secret, store: store, log: log}
}

type enrollRequest struct {
	EnrollSecret string `json:"enrollSecret"`
	Hostname     string `json:"hostname"`
	CSR          string `json:"csrPem"`
}

type enrollResponse struct {
	DeviceID string `json:"deviceId"`
	CertPEM  string `json:"certPem"`
	CAPEM    string `json:"caPem"`
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
	_ = s.store.Upsert(presence.Device{
		ID:        deviceID,
		Hostname:  hostname,
		LastSeen:  time.Now().UTC().Format(time.RFC3339),
		Connected: false,
		Transport: "mtls-grpc",
	})
	resp := enrollResponse{
		DeviceID: deviceID,
		CertPEM:  string(certPEM),
		CAPEM:    string(s.bundle.CACertPEM()),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error("encode enroll", "err", err)
	}
}

func (s *Server) Heartbeat(ctx context.Context, req *keelv1.HeartbeatRequest) (*keelv1.HeartbeatResponse, error) {
	id, fp, err := peerIdentity(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
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
	}
	if err := s.store.Upsert(dev); err != nil {
		s.log.Error("presence upsert", "err", err)
		return nil, status.Error(codes.Internal, "presence")
	}
	return &keelv1.HeartbeatResponse{Ok: true, ServerTimeUnix: time.Now().Unix()}, nil
}

func (s *Server) Connect(stream keelv1.AgentControl_ConnectServer) error {
	id, fp, err := peerIdentity(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	s.log.Info("agent connected", "device", id, "fp", fp[:min(12, len(fp))])
	_ = s.store.SetConnected(id, true)
	defer func() {
		_ = s.store.SetConnected(id, false)
		s.log.Info("agent disconnected", "device", id)
	}()

	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			switch body := msg.GetBody().(type) {
			case *keelv1.AgentToServer_Hello:
				s.log.Info("hello", "device", id, "host", body.Hello.GetHostname(), "ver", body.Hello.GetAgentVersion())
			case *keelv1.AgentToServer_Heartbeat:
				_, err := s.Heartbeat(stream.Context(), body.Heartbeat)
				if err != nil {
					errCh <- err
					return
				}
			case *keelv1.AgentToServer_Ack:
				s.log.Info("ack", "device", id, "command", body.Ack.GetCommandId(), "ok", body.Ack.GetAccepted())
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
		case <-ticker.C:
			reqID, err := newDeviceID()
			if err != nil {
				return err
			}
			if err := stream.Send(&keelv1.ServerToAgent{
				RequestId: reqID,
				Body:      &keelv1.ServerToAgent_Ping{Ping: &keelv1.Ping{ServerTimeUnix: time.Now().Unix()}},
			}); err != nil {
				return err
			}
		}
	}
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
