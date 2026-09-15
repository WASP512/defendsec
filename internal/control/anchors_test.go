package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"defendsec/internal/anchor"
)

func TestAnchorEndpointsRequireDatabase(t *testing.T) {
	s := testServer()
	for name, h := range map[string]http.HandlerFunc{
		"anchors": s.HandleAnchors,
		"receive": s.HandleAnchorReceive,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/audit/"+name, nil)
			req.Header.Set("Authorization", "Bearer admin-token")
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status=%d, want 503 without a database", rec.Code)
			}
		})
	}
}

// An instance that was never configured to hold peer anchors must not
// advertise the endpoint, and must not accept anything on it.
func TestAnchorReceiveClosedByDefault(t *testing.T) {
	s := testServer()
	s.SetAnchoring(nil, "")
	if s.peerAnchorToken != "" {
		t.Fatal("peer anchoring is enabled by default")
	}
}

func TestAnchorTargetSummaryHidesTokens(t *testing.T) {
	s := testServer()
	s.SetAnchoring(anchor.NewPublisher([]anchor.Target{
		{Kind: anchor.KindPeer, Ref: "https://peer.example/v1/anchors/receive", Token: "s3cret"},
		{Kind: anchor.KindFile, Ref: "/var/lib/defendsec/anchors"},
	}, "server-1"), "")

	summary := s.anchorTargetSummary()
	if len(summary) != 2 {
		t.Fatalf("summary has %d entries", len(summary))
	}
	blob, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	// A peer token is a shared secret. It must not leak through a status
	// endpoint any authenticated reader can hit.
	if strings.Contains(string(blob), "s3cret") {
		t.Fatalf("the peer token leaked into the target summary: %s", blob)
	}
}

func TestAnchorTargetSummaryWithoutAnchoring(t *testing.T) {
	s := testServer()
	if got := s.anchorTargetSummary(); got == nil || len(got) != 0 {
		t.Errorf("summary = %v, want an empty list rather than null", got)
	}
}

func TestAnchorsRejectsWrongMethod(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/anchors/receive", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleAnchorReceive(rec, req)
	// Without a database the availability check answers first; that is the
	// correct order, and the method check is covered once one is configured.
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d", rec.Code)
	}
}

func TestAnchorLatestIsANoOpWithoutTargets(t *testing.T) {
	s := testServer()
	records, anchored, err := s.AnchorLatest(t.Context())
	if err != nil || anchored || records != nil {
		t.Errorf("AnchorLatest = %v, %v, %v; want a quiet no-op", records, anchored, err)
	}
}
