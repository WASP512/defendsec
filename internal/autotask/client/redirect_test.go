package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"defendsec/internal/autotask/atest"
	"defendsec/internal/autotask/client"
)

// otherHost records every request it gets and every credential header on it.
type otherHost struct {
	mu   sync.Mutex
	hits int
	cred bool
}

func newOtherHost(t *testing.T) (*httptest.Server, *otherHost) {
	t.Helper()
	o := &otherHost{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hits++
		if r.Header.Get("Secret") != "" || r.Header.Get("UserName") != "" || r.Header.Get("ApiIntegrationCode") != "" {
			o.cred = true
		}
		o.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"item":{"id":3001}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, o
}

func TestARedirectIsNeverFollowedAndNoCredentialLeavesTheZone(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		other, o := newOtherHost(t)
		zone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+r.URL.Path, code)
		}))
		defer zone.Close()
		c, err := client.New(client.Config{BaseURL: zone.URL + "/atservicesrest", UserName: atest.User, Secret: atest.Secret, IntegrationCode: atest.IntegrationCode, AllowAnyHost: true})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if _, err := c.Threshold(ctx); err == nil {
			t.Errorf("%d: a redirected read was taken as success", code)
		}
		if _, err := c.Company(ctx, 3001); err == nil {
			t.Errorf("%d: a redirected company read was taken as success", code)
		}
		// A POST (the body, too, would be replayed by a 307/308).
		if _, err := c.CreateTicket(ctx, validTicket()); err == nil {
			t.Errorf("%d: a redirected create was taken as success", code)
		}
		o.mu.Lock()
		hits, cred := o.hits, o.cred
		o.mu.Unlock()
		if hits != 0 || cred {
			t.Errorf("%d: the second host saw %d requests (credentials: %v)", code, hits, cred)
		}
	}
}

func TestADiscoveryRedirectIsNotFollowed(t *testing.T) {
	other, o := newOtherHost(t)
	zone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/zoneInformation", http.StatusTemporaryRedirect)
	}))
	defer zone.Close()
	if _, err := client.Discover(context.Background(), nil, zone.URL+"/atservicesrest/v1.0/zoneInformation", atest.User, true); err == nil {
		t.Fatal("a redirected discovery was taken as an answer")
	}
	if o.hits != 0 {
		t.Fatalf("the second host saw %d requests", o.hits)
	}
}

func TestACallerSuppliedHTTPClientStillNeverFollowsARedirect(t *testing.T) {
	other, o := newOtherHost(t)
	zone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer zone.Close()
	own := &http.Client{} // follows redirects unless told not to
	c, err := client.New(client.Config{BaseURL: zone.URL + "/atservicesrest", UserName: atest.User, Secret: atest.Secret, IntegrationCode: atest.IntegrationCode, AllowAnyHost: true, HTTP: own})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Threshold(context.Background()); err == nil || o.hits != 0 {
		t.Fatalf("err %v, second host hits %d", err, o.hits)
	}
	if own.CheckRedirect != nil {
		t.Error("the caller's client was modified")
	}
}

func TestNewRefusesAHostThatIsNotAutotask(t *testing.T) {
	base := client.Config{UserName: "u", Secret: "s", IntegrationCode: "c"}
	for _, bad := range []string{
		"https://evil.example.com/atservicesrest",
		"http://webservices3.autotask.net/atservicesrest",
		"https://autotask.net.evil.example.com/atservicesrest",
		"https://webservices3.autotask.net:8443/atservicesrest",
		"https://user:pw@webservices3.autotask.net/atservicesrest",
		"http://127.0.0.1:9/atservicesrest",
	} {
		cfg := base
		cfg.BaseURL = bad
		if _, err := client.New(cfg); err == nil {
			t.Errorf("%q was accepted without AllowAnyHost", bad)
		}
	}
	cfg := base
	cfg.BaseURL = "https://webservices3.autotask.net/atservicesrest/"
	if c, err := client.New(cfg); err != nil || c.String() != "autotask client for https://webservices3.autotask.net/atservicesrest/v1.0" {
		t.Errorf("a real zone URL: %v, %v", c, err)
	}
}

func TestANoteIsNotRetriedAfterAServerError(t *testing.T) {
	srv := newServer(t)
	srv.AddFault(serverFault("POST /Tickets/9001/Notes", 502, 1))
	c, _ := newClient(t, srv, nil)
	_, err := c.CreateNote(context.Background(), client.NoteCreate{TicketID: 9001, Title: "t", Description: "d", NoteType: 1, Publish: 2})
	if !client.IsAmbiguous(err) {
		t.Fatalf("a 502 on a note must be ambiguous: %v", err)
	}
	if n := srv.Count("POST /Tickets/9001/Notes"); n != 1 {
		t.Fatalf("a note was sent %d times after a 502", n)
	}
}
