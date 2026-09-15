package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"defendsec/internal/controls"
)

func getControls(t *testing.T, s *Server, query, token string) (*httptest.ResponseRecorder, controlCatalogResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/controls"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.HandleControls(rec, req)
	var body controlCatalogResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
		}
	}
	return rec, body
}

func TestControlsCatalogServesEveryFramework(t *testing.T) {
	s := testServer()
	rec, body := getControls(t, s, "", "admin-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if len(body.Controls) != len(controls.Catalog()) {
		t.Errorf("served %d controls, catalog has %d", len(body.Controls), len(controls.Catalog()))
	}
	if len(body.Frameworks) != len(controls.Frameworks()) {
		t.Errorf("served %d framework summaries, want %d", len(body.Frameworks), len(controls.Frameworks()))
	}
	for _, f := range body.Frameworks {
		if f.Total != f.Evidenced+f.Partial+f.NotEvidenced {
			t.Errorf("%s: counts do not add up: %+v", f.ID, f)
		}
		if f.Total == 0 {
			t.Errorf("%s: no controls", f.ID)
		}
	}
}

func TestControlsCatalogFiltersByFramework(t *testing.T) {
	s := testServer()
	rec, body := getControls(t, s, "?framework=CJIS-V6", "admin-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if body.Framework != string(controls.CJISv6) {
		t.Errorf("framework = %q", body.Framework)
	}
	if len(body.Controls) == 0 {
		t.Fatal("no controls returned")
	}
	for _, c := range body.Controls {
		if c.ID.Framework() != controls.CJISv6 {
			t.Errorf("%s leaked into the CJIS view", c.ID)
		}
	}

	// An unknown framework is an error, not an empty list: silently returning
	// nothing would read as "this framework has no findings".
	rec, _ = getControls(t, s, "?framework=made-up", "admin-token")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 for an unknown framework", rec.Code)
	}
}

// The honesty claim, asserted at the API boundary rather than only in the
// package: what DefendSec cannot evidence is served, with the reason.
func TestControlsCatalogServesWhatItCannotEvidence(t *testing.T) {
	s := testServer()
	_, body := getControls(t, s, "?framework=cjis-v6", "admin-token")

	var none int
	for _, c := range body.Controls {
		if c.Coverage == controls.CoverageNone {
			none++
			if strings.TrimSpace(c.Note) == "" {
				t.Errorf("%s is not evidenced and gives no reason", c.ID)
			}
		}
	}
	if none == 0 {
		t.Fatal("the CJIS view claims to evidence every policy area, which is false")
	}
}

// A viewer preparing for an audit is exactly who needs this, so read access
// must not require admin — but an unauthenticated caller still gets nothing.
func TestControlsCatalogAuthorisation(t *testing.T) {
	s := testServer()
	for token, want := range map[string]int{
		"admin-token":  http.StatusOK,
		"viewer-token": http.StatusOK,
		"bogus":        http.StatusUnauthorized,
		"":             http.StatusUnauthorized,
	} {
		rec, _ := getControls(t, s, "", token)
		if rec.Code != want {
			t.Errorf("token %q: status=%d, want %d", token, rec.Code, want)
		}
	}
}

func TestControlsCatalogRejectsWrongMethod(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/controls", http.NoBody)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleControls(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}
