package client_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/autotask/atest"
	"defendsec/internal/autotask/client"
)

type sleeper struct {
	mu    sync.Mutex
	slept []time.Duration
}

func (s *sleeper) Sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slept = append(s.slept, d)
	return nil
}

func newClient(t *testing.T, srv *atest.Server, mod func(*client.Config)) (*client.Client, *sleeper) {
	t.Helper()
	sl := &sleeper{}
	cfg := client.Config{BaseURL: srv.BaseURL(), UserName: atest.User, Secret: atest.Secret, IntegrationCode: atest.IntegrationCode, Sleep: sl.Sleep, AllowAnyHost: true}
	if mod != nil {
		mod(&cfg)
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, sl
}

func newServer(t *testing.T) *atest.Server {
	t.Helper()
	srv := atest.New()
	t.Cleanup(srv.Close)
	return srv
}

func validTicket() client.TicketCreate {
	q, src, it, sub := int64(101), int64(7), int64(20), int64(200)
	return client.TicketCreate{CompanyID: 3001, Title: "Update openssl on 2 hosts [DS-abc1234567]", Description: "body", Status: 1, Priority: 2,
		QueueID: &q, Source: &src, IssueType: &it, SubIssueType: &sub, DueDateTime: "2026-10-31T00:00:00.00"}
}

func TestCompanyAndPicklists(t *testing.T) {
	srv := newServer(t)
	c, _ := newClient(t, srv, nil)
	ctx := context.Background()

	co, err := c.Company(ctx, 3001)
	if err != nil || co.CompanyName != "Example Client LLC" || !co.IsActive {
		t.Fatalf("company = %+v, %v", co, err)
	}
	if _, err := c.Company(ctx, 4040); err == nil {
		t.Fatal("an unknown company was returned")
	}
	found, err := c.SearchCompanies(ctx, "example cl")
	if err != nil || len(found) != 1 || found[0].ID != 3001 {
		t.Fatalf("search = %+v, %v", found, err)
	}
	if _, err := c.SearchCompanies(ctx, "e"); err == nil {
		t.Fatal("a one-letter search was sent")
	}

	f, err := c.TicketFields(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !f.HasActive("queueID", "101") || f.Label("queueID", "101") != "Security Test Queue" {
		t.Errorf("queue picklist not read: %+v", f["queueID"])
	}
	if f.HasActive("priority", "4") {
		t.Error("an inactive priority counts as available")
	}
	if f.HasActive("status", "9") || len(f.Active("status")) != 3 {
		t.Errorf("active statuses = %+v", f.Active("status"))
	}
	if f["subIssueType"].PicklistParentValueField != "issueType" {
		t.Errorf("sub-issue type parent field = %q", f["subIssueType"].PicklistParentValueField)
	}
	if f["title"].Length != 255 || f["description"].Length != 8000 {
		t.Errorf("lengths = %d, %d", f["title"].Length, f["description"].Length)
	}
	nf, err := c.NoteFields(ctx)
	if err != nil || !nf.HasActive("noteType", "1") || !nf.HasActive("publish", "2") {
		t.Fatalf("note fields: %v", err)
	}
	th, err := c.Threshold(ctx)
	if err != nil || th.ExternalRequestThreshold != 10000 || th.CurrentTimeframeRequestCount != 0 {
		t.Fatalf("threshold = %+v, %v", th, err)
	}
}

func TestCreateFindStatusNote(t *testing.T) {
	srv := newServer(t)
	c, _ := newClient(t, srv, nil)
	ctx := context.Background()

	id, err := c.CreateTicket(ctx, validTicket())
	if err != nil || id <= 0 {
		t.Fatalf("create: %d, %v", id, err)
	}
	tickets := srv.Tickets()
	if len(tickets) != 1 || tickets[0].Title != validTicket().Title || tickets[0].DueDateTime != "2026-10-31T00:00:00.00" || *tickets[0].QueueID != 101 {
		t.Fatalf("stored ticket = %+v", tickets)
	}

	found, err := c.FindTickets(ctx, 3001, "[DS-abc1234567]")
	if err != nil || len(found) != 1 || found[0].ID != id || found[0].Completed() {
		t.Fatalf("find = %+v, %v", found, err)
	}
	if none, err := c.FindTickets(ctx, 3002, "[DS-abc1234567]"); err != nil || len(none) != 0 {
		t.Fatalf("another company's search = %+v, %v", none, err)
	}
	if _, err := c.FindTickets(ctx, 3001, " "); err == nil {
		t.Fatal("an empty tag was searched")
	}

	nid, err := c.CreateNote(ctx, client.NoteCreate{TicketID: id, Title: "DefendSec", Description: "fixed on host-a", NoteType: 1, Publish: 2})
	if err != nil || nid <= 0 {
		t.Fatalf("note: %d, %v", nid, err)
	}
	if n := srv.Notes(id); len(n) != 1 || n[0].Description != "fixed on host-a" || n[0].Publish != 2 {
		t.Fatalf("notes = %+v", n)
	}

	if err := c.SetTicketStatus(ctx, id, 5); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetTickets(ctx, []int64{id, 424242})
	if err != nil || len(got) != 1 || !got[id].Completed() || got[id].Status != 5 {
		t.Fatalf("after completing: %+v, %v", got, err)
	}
}

func TestRefusalsAreRejectedWithTheServicesOwnWords(t *testing.T) {
	srv := newServer(t)
	c, _ := newClient(t, srv, nil)
	ctx := context.Background()

	cases := map[string]func(*client.TicketCreate){
		"inactive priority":       func(t *client.TicketCreate) { t.Priority = 4 },
		"unknown queue":           func(t *client.TicketCreate) { q := int64(999); t.QueueID = &q },
		"sub-issue of other type": func(t *client.TicketCreate) { s := int64(210); t.SubIssueType = &s },
		"title too long":          func(t *client.TicketCreate) { t.Title = strings.Repeat("x", 256) },
		"unknown company":         func(t *client.TicketCreate) { t.CompanyID = 77 },
	}
	for name, mod := range cases {
		tk := validTicket()
		mod(&tk)
		before := srv.Count("POST /Tickets")
		_, err := c.CreateTicket(ctx, tk)
		var e *client.Error
		if !errors.As(err, &e) || e.Kind != client.KindRejected || len(e.Messages) == 0 || e.Ambiguous {
			t.Errorf("%s: err = %v", name, err)
		}
		if srv.Count("POST /Tickets")-before != 1 {
			t.Errorf("%s: a refused create was retried", name)
		}
	}
	if len(srv.Tickets()) != 0 {
		t.Error("a refused create left a ticket")
	}
}

func TestOneRequestAtATime(t *testing.T) {
	srv := newServer(t)
	srv.Delay = 15 * time.Millisecond
	c, _ := newClient(t, srv, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Company(context.Background(), 3001); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := srv.MaxInFlight(); n != 1 {
		t.Fatalf("%d requests were in flight at once; Autotask limits the threads per endpoint and asks for serial requests", n)
	}
}

func TestThrottleHonoursRetryAfter(t *testing.T) {
	srv := newServer(t)
	srv.AddFault(fault429(2, "7"))
	c, sl := newClient(t, srv, nil)
	co, err := c.Company(context.Background(), 3001)
	if err != nil || co.ID != 3001 {
		t.Fatalf("after two throttles: %+v, %v", co, err)
	}
	if len(sl.slept) != 2 || sl.slept[0] != 7*time.Second {
		t.Fatalf("slept %v, want two waits of the 7 s asked for", sl.slept)
	}

	// A create that was throttled was not executed, so it is retried, once.
	srv2 := newServer(t)
	srv2.AddFault(fault429(1, "1"))
	c2, _ := newClient(t, srv2, nil)
	if _, err := c2.CreateTicket(context.Background(), validTicket()); err != nil {
		t.Fatal(err)
	}
	if len(srv2.Tickets()) != 1 {
		t.Fatalf("%d tickets after a throttled create", len(srv2.Tickets()))
	}
}

func TestThrottleThatDoesNotClearStops(t *testing.T) {
	srv := newServer(t)
	srv.AddFault(fault429(0, "1"))
	c, sl := newClient(t, srv, nil)
	_, err := c.Company(context.Background(), 3001)
	var e *client.Error
	if !errors.As(err, &e) || e.Kind != client.KindThrottled || !client.IsFatal(err) {
		t.Fatalf("err = %v", err)
	}
	if got := srv.Count("GET /Companies/"); got != 3 {
		t.Errorf("%d attempts, want 3", got)
	}
	if len(sl.slept) != 2 {
		t.Errorf("slept %v", sl.slept)
	}

	// A wait longer than the bound is not slept at all.
	srv2 := newServer(t)
	srv2.AddFault(fault429(0, "3600"))
	c2, sl2 := newClient(t, srv2, nil)
	if _, err := c2.Company(context.Background(), 3001); !client.IsFatal(err) {
		t.Fatalf("err = %v", err)
	}
	if len(sl2.slept) != 0 || srv2.Count("GET /Companies/") != 1 {
		t.Errorf("an hour-long Retry-After was waited for or retried: slept %v, %d attempts", sl2.slept, srv2.Count("GET /Companies/"))
	}
}

func TestServerErrorsRetryReadsNotCreates(t *testing.T) {
	srv := newServer(t)
	srv.AddFault(serverFault("GET /Companies/", 503, 2))
	c, sl := newClient(t, srv, nil)
	if _, err := c.Company(context.Background(), 3001); err != nil {
		t.Fatalf("a read after two 503s: %v", err)
	}
	if len(sl.slept) != 2 {
		t.Errorf("backoff = %v", sl.slept)
	}

	srv2 := newServer(t)
	srv2.AddFault(serverFault("POST /Tickets", 502, 1))
	c2, _ := newClient(t, srv2, nil)
	_, err := c2.CreateTicket(context.Background(), validTicket())
	if !client.IsAmbiguous(err) {
		t.Fatalf("a 502 on a create must be ambiguous: %v", err)
	}
	if srv2.Count("POST /Tickets") != 1 {
		t.Fatalf("a create was repeated after a 502 (%d requests)", srv2.Count("POST /Tickets"))
	}
	if client.IsFatal(err) {
		t.Error("one ambiguous create must not stop the whole run")
	}
}

func TestLostAnswerLeavesATicketTheTagFinds(t *testing.T) {
	srv := newServer(t)
	srv.AddFault(atest.Fault{Match: "POST /Tickets", Status: 500, Body: "", AfterServing: true, Times: 1})
	c, _ := newClient(t, srv, nil)
	ctx := context.Background()
	_, err := c.CreateTicket(ctx, validTicket())
	if !client.IsAmbiguous(err) {
		t.Fatalf("err = %v", err)
	}
	if len(srv.Tickets()) != 1 {
		t.Fatal("the fake should have created the ticket before losing the answer")
	}
	found, err := c.FindTickets(ctx, 3001, "[DS-abc1234567]")
	if err != nil || len(found) != 1 {
		t.Fatalf("the ticket the lost answer hid was not found: %+v, %v", found, err)
	}
}

func TestAuthFailureIsFatalAndNeverEchoesTheSecret(t *testing.T) {
	srv := newServer(t)
	sl := &sleeper{}
	c, err := client.New(client.Config{BaseURL: srv.BaseURL(), UserName: atest.User, Secret: "the-wrong-secret-value", IntegrationCode: atest.IntegrationCode, Sleep: sl.Sleep, AllowAnyHost: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Company(context.Background(), 3001)
	if !client.IsAuth(err) || !client.IsFatal(err) {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{"the-wrong-secret-value", atest.IntegrationCode, "Secret"} {
		if strings.Contains(err.Error(), leak) || strings.Contains(c.String(), leak) {
			t.Errorf("the error or the client's string holds %q: %v / %s", leak, err, c)
		}
	}
	if srv.Count("GET /Companies/") != 1 {
		t.Error("a refused credential was retried")
	}
}

func TestBudgetStopsBeforeSending(t *testing.T) {
	srv := newServer(t)
	c, _ := newClient(t, srv, func(cfg *client.Config) { cfg.MaxRequests = 3 })
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Company(ctx, 3001); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.Company(ctx, 3001)
	var e *client.Error
	if !errors.As(err, &e) || e.Kind != client.KindBudget || !client.IsFatal(err) {
		t.Fatalf("err = %v", err)
	}
	if srv.Count("GET /Companies/") != 3 || c.Requests() != 3 {
		t.Fatalf("sent %d, counted %d", srv.Count("GET /Companies/"), c.Requests())
	}
}

func TestEveryRequestIsOnTheDocumentedList(t *testing.T) {
	srv := newServer(t)
	c, _ := newClient(t, srv, nil)
	ctx := context.Background()
	id, _ := c.CreateTicket(ctx, validTicket())
	_, _ = c.Company(ctx, 3001)
	_, _ = c.SearchCompanies(ctx, "example")
	_, _ = c.TicketFields(ctx)
	_, _ = c.NoteFields(ctx)
	_, _ = c.Threshold(ctx)
	_, _ = c.GetTickets(ctx, []int64{id})
	_, _ = c.FindTickets(ctx, 3001, "[DS-x]")
	_, _ = c.CreateNote(ctx, client.NoteCreate{TicketID: id, Description: "n", NoteType: 1, Publish: 1})
	_ = c.SetTicketStatus(ctx, id, 5)

	allowed := map[string]bool{
		"GET /ThresholdInformation": true, "GET /Companies/3001": true, "POST /Companies/query": true,
		"GET /Tickets/entityInformation/fields": true, "GET /TicketNotes/entityInformation/fields": true,
		"POST /Tickets/query": true, "POST /Tickets": true, "PATCH /Tickets": true,
	}
	for _, r := range srv.Requests() {
		key := r.Method + " " + r.Path
		if strings.HasPrefix(r.Path, "/Tickets/") && strings.HasSuffix(r.Path, "/Notes") && r.Method == "POST" {
			continue
		}
		if !allowed[key] {
			t.Errorf("a request outside the documented list: %s", key)
		}
	}
}

func TestGetTicketsChunksIds(t *testing.T) {
	srv := newServer(t)
	c, _ := newClient(t, srv, nil)
	ids := make([]int64, 250)
	for i := range ids {
		ids[i] = int64(100 + i)
	}
	if _, err := c.GetTickets(context.Background(), ids); err != nil {
		t.Fatal(err)
	}
	if n := srv.Count("POST /Tickets/query"); n != 3 {
		t.Fatalf("%d queries for 250 ids, want 3 (100 each)", n)
	}
	if n := srv.Count("POST /Tickets/query"); n == 0 {
		t.Fatal("no query")
	}
	if got, err := c.GetTickets(context.Background(), nil); err != nil || len(got) != 0 || srv.Count("POST /Tickets/query") != 3 {
		t.Fatal("no ids must send nothing")
	}
}

func TestBadAnswersAreNotTreatedAsSuccess(t *testing.T) {
	srv := newServer(t)
	srv.AddFault(atest.Fault{Match: "POST /Tickets", Status: 200, Body: `{"itemId": 0}`, Times: 1, AfterServing: false})
	c, _ := newClient(t, srv, nil)
	_, err := c.CreateTicket(context.Background(), validTicket())
	var e *client.Error
	if !errors.As(err, &e) || e.Kind != client.KindBadResponse || !e.Ambiguous {
		t.Fatalf("a create answered with no id: %v", err)
	}
	srv.AddFault(atest.Fault{Match: "GET /Companies/", Status: 200, Body: `<html>proxy</html>`, Times: 1})
	if _, err := c.Company(context.Background(), 3001); err == nil {
		t.Fatal("an HTML answer was accepted")
	}
}

func TestZoneURLIsCheckedBeforeCredentialsGoThere(t *testing.T) {
	good := map[string]string{
		"https://webservices3.autotask.net/atservicesrest":    "https://webservices3.autotask.net/atservicesrest",
		"https://webservices3.autotask.net/atservicesrest/":   "https://webservices3.autotask.net/atservicesrest",
		"https://webservices19.autotask.net/ATServicesRest":   "https://webservices19.autotask.net/atservicesrest",
		"https://prde.autotask.net/atservicesrest/":           "https://prde.autotask.net/atservicesrest",
		"  https://webservices5.autotask.net/atservicesrest ": "https://webservices5.autotask.net/atservicesrest",
	}
	for in, want := range good {
		if got, err := client.CheckZoneURL(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"http://webservices3.autotask.net/atservicesrest",
		"https://evil.example.com/atservicesrest",
		"https://autotask.net.evil.example.com/atservicesrest",
		"https://webservices3.autotask.net.evil.example.com/atservicesrest",
		"https://notautotask.net/atservicesrest",
		"https://user:pw@webservices3.autotask.net/atservicesrest",
		"https://webservices3.autotask.net:8443/atservicesrest",
		"https://webservices3.autotask.net/other",
		"https://webservices3.autotask.net/atservicesrest/v1.0",
		"",
		"webservices3.autotask.net",
	} {
		if got, err := client.CheckZoneURL(bad); err == nil {
			t.Errorf("%q was accepted as %q", bad, got)
		}
	}
}

func TestZoneDiscovery(t *testing.T) {
	srv := newServer(t)
	z, err := client.Discover(context.Background(), nil, srv.URL+"/atservicesrest/v1.0/zoneInformation", atest.User, true)
	if err != nil || z.ZoneName != "America East" || !strings.HasPrefix(z.URL, srv.URL) {
		t.Fatalf("zone = %+v, %v", z, err)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].Path != "/zoneInformation" {
		t.Fatalf("requests = %+v", reqs)
	}

	// An answer that names a host outside autotask.net must not be followed.
	if _, err := client.Discover(context.Background(), nil, srv.URL+"/atservicesrest/v1.0/zoneInformation", atest.User, false); err == nil {
		t.Fatal("a zone URL on a local server was accepted without the test switch")
	}
	srv.Zone["url"] = "https://webservices3.autotask.net/atservicesrest/"
	z, err = client.Discover(context.Background(), nil, srv.URL+"/atservicesrest/v1.0/zoneInformation", atest.User, false)
	if err != nil || z.URL != "https://webservices3.autotask.net/atservicesrest" {
		t.Fatalf("zone = %+v, %v", z, err)
	}
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	for name, cfg := range map[string]client.Config{
		"no user":   {BaseURL: "https://x.autotask.net/atservicesrest", Secret: "s", IntegrationCode: "c"},
		"no secret": {BaseURL: "https://x.autotask.net/atservicesrest", UserName: "u", IntegrationCode: "c"},
		"no code":   {BaseURL: "https://x.autotask.net/atservicesrest", UserName: "u", Secret: "s"},
		"bad url":   {BaseURL: "::", UserName: "u", Secret: "s", IntegrationCode: "c"},
	} {
		if _, err := client.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func fault429(times int, retryAfter string) atest.Fault {
	return atest.Fault{Match: "", Status: 429, Body: `{"errors":["Thread limit exceeded."]}`, Header: map[string]string{"Retry-After": retryAfter}, Times: times}
}

func serverFault(match string, status, times int) atest.Fault {
	return atest.Fault{Match: match, Status: status, Body: "", Times: times}
}
