package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/presence"
)

// File-integrity changes are recorded as change evidence, and the alert for
// one is the baseline drift: a state that clears when the file returns to the
// accepted baseline. Slice 6 removed the second alert that used to be raised
// per change event and never cleared, which was an event alert, not a finding.
func TestFimChangeIsEvidenceAndOneDriftAlert(t *testing.T) {
	s := testServer()
	path := filepath.Join(t.TempDir(), "agents.json")
	s.store = presence.New(path)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
			Subject:      pkix.Name{CommonName: "dev-fim"},
			SerialNumber: big.NewInt(1),
			Raw:          []byte("raw"),
		}}},
	}})
	report := func(hash string) {
		t.Helper()
		_, err := s.ReportInventory(ctx, &defendsecv1.InventoryReport{
			Host: &defendsecv1.HeartbeatRequest{Hostname: "host-fim", Platform: "linux"},
			Fim:  []*defendsecv1.FimFile{{Path: "/etc/ssh/sshd_config", Sha256: hash}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	report("aaaa") // first report becomes the baseline
	if n := len(s.store.ListAlerts("", "fim", "", 100)); n != 0 {
		t.Fatalf("%d fim alerts before anything changed", n)
	}
	report("bbbb") // the file changes

	alerts := s.store.ListAlerts("", "fim", "", 100)
	if len(alerts) != 1 {
		t.Fatalf("%d fim alerts after one change, want exactly the drift alert: %+v", len(alerts), alerts)
	}
	if alerts[0].SourceType != "fim_drift" {
		t.Errorf("alert source %q, want fim_drift", alerts[0].SourceType)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FimEvents []struct {
			Path, Action string
		} `json:"fimEvents"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.FimEvents) != 1 || doc.FimEvents[0].Path != "/etc/ssh/sshd_config" || doc.FimEvents[0].Action != "modified" {
		t.Errorf("change evidence = %+v, want one modified event", doc.FimEvents)
	}
}
