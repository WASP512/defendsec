// Package atest is a fake Autotask REST service for tests (slice 14). It speaks
// the documented shapes ({"item"}, {"items","pageDetails"}, {"itemId"},
// {"errors"}), checks the three credential headers, enforces what the real API
// enforces and the code relies on (required fields, active picklist values, field
// lengths), and records every request so a test can assert what was and was not
// called. Its data are the scrubbed shapes of the documentation's examples.
package atest

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed fixtures/*.json
var fixtures embed.FS

// Credentials the fake accepts.
const (
	User            = "api-user@example.com"
	Secret          = "test-secret-not-real"
	IntegrationCode = "TESTINTEGRATIONCODE0000"
)

// Req is one request the fake received.
type Req struct {
	Method string
	Path   string // without the /atservicesrest/v1.0 prefix
	Body   string
}

// Fault makes matching requests fail instead of being served.
type Fault struct {
	// Match picks the requests ("POST /Tickets" is a prefix, "POST /Tickets$" exact).
	Match string
	// Status and Body are the answer; Header is added.
	Status int
	Body   string
	Header map[string]string
	// Times is how many matching requests fail (0 = every one). After that the
	// request is served normally.
	Times int
	// AfterServing, when true, carries the request out and then answers with the fault
	// (a create whose answer was lost).
	AfterServing bool
	hits         int
}

// Company is a company in the fake.
type Company struct {
	ID          int64  `json:"id"`
	CompanyName string `json:"companyName"`
	IsActive    bool   `json:"isActive"`
	CompanyType int64  `json:"companyType"`
}

// Ticket is a ticket in the fake.
type Ticket struct {
	ID            int64   `json:"id"`
	TicketNumber  string  `json:"ticketNumber"`
	CompanyID     int64   `json:"companyID"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	Status        int64   `json:"status"`
	Priority      int64   `json:"priority"`
	QueueID       *int64  `json:"queueID"`
	Source        *int64  `json:"source,omitempty"`
	IssueType     *int64  `json:"issueType,omitempty"`
	SubIssueType  *int64  `json:"subIssueType,omitempty"`
	DueDateTime   string  `json:"dueDateTime,omitempty"`
	CompletedDate *string `json:"completedDate"`
}

// Note is a ticket note in the fake.
type Note struct {
	ID          int64  `json:"id"`
	TicketID    int64  `json:"ticketID"`
	Title       string `json:"title"`
	Description string `json:"description"`
	NoteType    int64  `json:"noteType"`
	Publish     int64  `json:"publish"`
}

// Server is the fake service.
type Server struct {
	*httptest.Server

	mu        sync.Mutex
	Companies map[int64]Company
	tickets   map[int64]*Ticket
	notes     []Note
	nextID    int64
	reqs      []Req
	faults    []*Fault
	// Used is currentTimeframeRequestCount in ThresholdInformation.
	Used int
	// Threshold is externalRequestThreshold (10000 unless a test lowers it).
	Threshold int
	// TicketFieldsJSON and NoteFieldsJSON are the field lists served; a test may
	// replace them to remove or deactivate a picklist value.
	TicketFieldsJSON []byte
	NoteFieldsJSON   []byte
	// Zone is what zoneInformation answers with (URL defaults to this server's).
	Zone map[string]any
	// Delay holds every request this long, so a test can see overlap.
	Delay time.Duration

	inflight, maxInflight int
}

// MaxInFlight is the most requests the fake has served at the same moment.
func (s *Server) MaxInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxInflight
}

// New starts a fake service with one company (id 3001, "Example Client LLC").
func New() *Server {
	s := &Server{
		Companies: map[int64]Company{
			3001: {ID: 3001, CompanyName: "Example Client LLC", IsActive: true, CompanyType: 1},
			3002: {ID: 3002, CompanyName: "Example Other Co", IsActive: true, CompanyType: 1},
		},
		tickets:   map[int64]*Ticket{},
		nextID:    9000,
		Threshold: 10000,
	}
	s.TicketFieldsJSON = mustFixture("ticket_fields.json")
	s.NoteFieldsJSON = mustFixture("note_fields.json")
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	s.Zone = map[string]any{"zoneName": "America East", "url": s.Server.URL + "/atservicesrest/", "webUrl": "https://ww3.example.com/", "ci": 20264}
	return s
}

func mustFixture(name string) []byte {
	b, err := fixtures.ReadFile("fixtures/" + name)
	if err != nil {
		panic(err)
	}
	return b
}

// BaseURL is the REST root to give the client.
func (s *Server) BaseURL() string { return s.Server.URL + "/atservicesrest" }

// AddFault queues a failure.
func (s *Server) AddFault(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &f)
}

// ClearFaults removes every fault.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = nil
}

// Requests returns a copy of every request received.
func (s *Server) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// Count returns how many requests matched "METHOD /Path" (a path prefix; a
// trailing $ makes it exact: "POST /Tickets$").
func (s *Server) Count(match string) int {
	n := 0
	for _, r := range s.Requests() {
		if matches(match, r) {
			n++
		}
	}
	return n
}

// ResetRequests forgets the recorded requests.
func (s *Server) ResetRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = nil
}

// Tickets returns the tickets, by id.
func (s *Server) Tickets() []Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Ticket, 0, len(s.tickets))
	for _, t := range s.tickets {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Notes returns a ticket's notes in order.
func (s *Server) Notes(ticketID int64) []Note {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Note
	for _, n := range s.notes {
		if n.TicketID == ticketID {
			out = append(out, n)
		}
	}
	return out
}

// Complete marks a ticket completed, as a technician would.
func (s *Server) Complete(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tickets[id]; t != nil {
		now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		t.CompletedDate = &now
		t.Status = 5
	}
}

// Remove deletes a ticket, as a technician with the right would.
func (s *Server) Remove(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tickets, id)
}

// Seed adds a ticket directly (a ticket DefendSec created in an earlier life, or by hand).
func (s *Server) Seed(t Ticket) Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	t.ID = s.nextID
	if t.TicketNumber == "" {
		t.TicketNumber = fmt.Sprintf("T20261024.%04d", t.ID-9000)
	}
	s.tickets[t.ID] = &t
	return t
}

func matches(match string, r Req) bool {
	method, path, _ := strings.Cut(match, " ")
	if strings.HasSuffix(path, "$") {
		return (method == "" || method == r.Method) && r.Path == strings.TrimSuffix(path, "$")
	}
	return (method == "" || method == r.Method) && strings.HasPrefix(r.Path, path)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errorsJSON(w http.ResponseWriter, status int, msgs ...string) {
	writeJSON(w, status, map[string]any{"errors": msgs})
}

const prefix = "/atservicesrest/v1.0"

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	path := strings.TrimPrefix(r.URL.Path, prefix)

	s.mu.Lock()
	rec := Req{Method: r.Method, Path: path, Body: string(body)}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		rec.Path = r.URL.Path
	}
	s.reqs = append(s.reqs, rec)
	s.inflight++
	if s.inflight > s.maxInflight {
		s.maxInflight = s.inflight
	}
	delay := s.Delay
	var fault *Fault
	for _, f := range s.faults {
		if matches(f.Match, rec) && (f.Times == 0 || f.hits < f.Times) {
			f.hits++
			fault = f
			break
		}
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	if delay > 0 {
		time.Sleep(delay)
	}

	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	if path == "/zoneInformation" {
		writeJSON(w, 200, s.Zone)
		return
	}
	if r.Header.Get("UserName") != User || r.Header.Get("Secret") != Secret || r.Header.Get("ApiIntegrationCode") != IntegrationCode {
		errorsJSON(w, 401, "The supplied credentials are invalid.")
		return
	}
	if fault != nil && !fault.AfterServing {
		for k, v := range fault.Header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fault.Status)
		_, _ = io.WriteString(w, fault.Body)
		return
	}
	rw := w
	if fault != nil {
		rw = discard{}
	}
	s.route(rw, r.Method, path, body)
	if fault != nil {
		for k, v := range fault.Header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(fault.Status)
		_, _ = io.WriteString(w, fault.Body)
	}
}

// discard swallows the real answer of a request whose answer is "lost".
type discard struct{}

func (discard) Header() http.Header         { return http.Header{} }
func (discard) Write(b []byte) (int, error) { return len(b), nil }
func (discard) WriteHeader(int)             {}

func (s *Server) route(w http.ResponseWriter, method, path string, body []byte) {
	switch {
	case method == "GET" && path == "/ThresholdInformation":
		s.mu.Lock()
		used, th := s.Used, s.Threshold
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"externalRequestThreshold": th, "requestThresholdTimeframe": 60, "currentTimeframeRequestCount": used})
	case method == "GET" && strings.HasPrefix(path, "/Companies/") && !strings.Contains(path[len("/Companies/"):], "/"):
		id, _ := strconv.ParseInt(path[len("/Companies/"):], 10, 64)
		c, ok := s.Companies[id]
		if !ok {
			writeJSON(w, 200, map[string]any{"item": nil})
			return
		}
		writeJSON(w, 200, map[string]any{"item": c})
	case method == "POST" && path == "/Companies/query":
		s.queryCompanies(w, body)
	case method == "GET" && path == "/Tickets/entityInformation/fields":
		w.Header().Set("Content-Type", "application/json")
		s.mu.Lock()
		b := s.TicketFieldsJSON
		s.mu.Unlock()
		_, _ = w.Write(b)
	case method == "GET" && path == "/TicketNotes/entityInformation/fields":
		w.Header().Set("Content-Type", "application/json")
		s.mu.Lock()
		b := s.NoteFieldsJSON
		s.mu.Unlock()
		_, _ = w.Write(b)
	case method == "POST" && path == "/Tickets/query":
		s.queryTickets(w, body)
	case method == "POST" && path == "/Tickets":
		s.createTicket(w, body)
	case method == "PATCH" && path == "/Tickets":
		s.patchTicket(w, body)
	case method == "POST" && strings.HasPrefix(path, "/Tickets/") && strings.HasSuffix(path, "/Notes"):
		s.createNote(w, path, body)
	default:
		errorsJSON(w, 404, "no such resource in the fake: "+method+" "+path)
	}
}

type filterExpr struct {
	Op    string          `json:"op"`
	Field string          `json:"field"`
	Value json.RawMessage `json:"value"`
}

type query struct {
	Filter []filterExpr `json:"filter"`
	Max    int          `json:"MaxRecords"`
}

func (s *Server) queryCompanies(w http.ResponseWriter, body []byte) {
	var q query
	if json.Unmarshal(body, &q) != nil {
		errorsJSON(w, 500, "Invalid query syntax.")
		return
	}
	items := []Company{}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]int64, 0, len(s.Companies))
	for id := range s.Companies {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		c := s.Companies[id]
		ok := true
		for _, f := range q.Filter {
			switch {
			case f.Field == "companyName" && f.Op == "contains":
				var v string
				_ = json.Unmarshal(f.Value, &v)
				ok = ok && strings.Contains(strings.ToLower(c.CompanyName), strings.ToLower(v))
			case f.Field == "isActive" && f.Op == "eq":
				var v bool
				_ = json.Unmarshal(f.Value, &v)
				ok = ok && c.IsActive == v
			}
		}
		if ok {
			items = append(items, c)
		}
	}
	writeJSON(w, 200, map[string]any{"items": items, "pageDetails": map[string]any{"count": len(items), "requestCount": 25, "prevPageUrl": nil, "nextPageUrl": nil}})
}

func (s *Server) queryTickets(w http.ResponseWriter, body []byte) {
	var q query
	if json.Unmarshal(body, &q) != nil || len(q.Filter) == 0 {
		errorsJSON(w, 500, "Invalid query syntax.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []Ticket{}
	ids := make([]int64, 0, len(s.tickets))
	for id := range s.tickets {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		t := s.tickets[id]
		ok := true
		for _, f := range q.Filter {
			switch {
			case f.Field == "id" && f.Op == "in":
				var vals []int64
				_ = json.Unmarshal(f.Value, &vals)
				if len(vals) > 500 {
					errorsJSON(w, 500, "Invalid query syntax. Queries are limited to 500 or fewer 'OR' conditions.")
					return
				}
				found := false
				for _, v := range vals {
					found = found || v == t.ID
				}
				ok = ok && found
			case f.Field == "companyID" && f.Op == "eq":
				var v int64
				_ = json.Unmarshal(f.Value, &v)
				ok = ok && t.CompanyID == v
			case f.Field == "title" && f.Op == "contains":
				var v string
				_ = json.Unmarshal(f.Value, &v)
				ok = ok && strings.Contains(strings.ToLower(t.Title), strings.ToLower(v))
			default:
				errorsJSON(w, 500, "the fake does not support this filter: "+f.Op+" "+f.Field)
				return
			}
		}
		if ok {
			items = append(items, *t)
		}
	}
	max := q.Max
	if max <= 0 || max > 500 {
		max = 500
	}
	if len(items) > max {
		items = items[:max]
	}
	writeJSON(w, 200, map[string]any{"items": items, "pageDetails": map[string]any{"count": len(items), "requestCount": max, "prevPageUrl": nil, "nextPageUrl": nil}})
}

type fieldDoc struct {
	Fields []struct {
		Name           string `json:"name"`
		Length         int    `json:"length"`
		IsRequired     bool   `json:"isRequired"`
		PicklistValues []struct {
			Value       string `json:"value"`
			ParentValue string `json:"parentValue"`
			IsActive    bool   `json:"isActive"`
		} `json:"picklistValues"`
	} `json:"fields"`
}

func (d fieldDoc) active(name, value string) (found, active bool, parent string) {
	for _, f := range d.Fields {
		if f.Name != name {
			continue
		}
		for _, v := range f.PicklistValues {
			if v.Value == value {
				return true, v.IsActive, v.ParentValue
			}
		}
	}
	return false, false, ""
}

func (d fieldDoc) length(name string) int {
	for _, f := range d.Fields {
		if f.Name == name {
			return f.Length
		}
	}
	return 0
}

func (s *Server) createTicket(w http.ResponseWriter, body []byte) {
	var in map[string]any
	if json.Unmarshal(body, &in) != nil {
		errorsJSON(w, 500, "Invalid JSON.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var doc fieldDoc
	_ = json.Unmarshal(s.TicketFieldsJSON, &doc)

	num := func(k string) (int64, bool) {
		v, ok := in[k]
		if !ok || v == nil {
			return 0, false
		}
		f, ok := v.(float64)
		return int64(f), ok
	}
	var msgs []string
	for _, req := range []string{"companyID", "status", "priority"} {
		if _, ok := num(req); !ok {
			msgs = append(msgs, "The field "+req+" is required.")
		}
	}
	title, _ := in["title"].(string)
	desc, _ := in["description"].(string)
	if strings.TrimSpace(title) == "" {
		msgs = append(msgs, "The field title is required.")
	}
	if l := doc.length("title"); l > 0 && len([]rune(title)) > l {
		msgs = append(msgs, fmt.Sprintf("title must be %d characters or fewer.", l))
	}
	if l := doc.length("description"); l > 0 && len([]rune(desc)) > l {
		msgs = append(msgs, fmt.Sprintf("description must be %d characters or fewer.", l))
	}
	if cid, ok := num("companyID"); ok {
		if _, known := s.Companies[cid]; !known {
			msgs = append(msgs, "companyID does not reference an existing company.")
		}
	}
	for _, pl := range []string{"status", "priority", "queueID", "source", "issueType", "subIssueType"} {
		v, ok := num(pl)
		if !ok {
			continue
		}
		found, active, parent := doc.active(pl, strconv.FormatInt(v, 10))
		if !found || !active {
			msgs = append(msgs, fmt.Sprintf("%s value %d is not an active picklist value.", pl, v))
		}
		if pl == "subIssueType" && found {
			if it, has := num("issueType"); !has {
				msgs = append(msgs, "When a subIssueType value is provided, the associated issueType value must also be provided.")
			} else if strconv.FormatInt(it, 10) != parent {
				msgs = append(msgs, "subIssueType does not belong to issueType.")
			}
		}
	}
	if len(msgs) > 0 {
		errorsJSON(w, 500, msgs...)
		return
	}
	s.nextID++
	t := &Ticket{ID: s.nextID, TicketNumber: fmt.Sprintf("T20261024.%04d", s.nextID-9000), Title: title, Description: desc}
	t.CompanyID, _ = num("companyID")
	t.Status, _ = num("status")
	t.Priority, _ = num("priority")
	if v, ok := num("queueID"); ok {
		t.QueueID = &v
	}
	if v, ok := num("source"); ok {
		t.Source = &v
	}
	if v, ok := num("issueType"); ok {
		t.IssueType = &v
	}
	if v, ok := num("subIssueType"); ok {
		t.SubIssueType = &v
	}
	t.DueDateTime, _ = in["dueDateTime"].(string)
	s.tickets[t.ID] = t
	writeJSON(w, 200, map[string]any{"itemId": t.ID})
}

func (s *Server) patchTicket(w http.ResponseWriter, body []byte) {
	var in map[string]any
	if json.Unmarshal(body, &in) != nil {
		errorsJSON(w, 500, "Invalid JSON.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idf, _ := in["id"].(float64)
	t := s.tickets[int64(idf)]
	if t == nil {
		errorsJSON(w, 404, "No ticket with that id.")
		return
	}
	for k := range in {
		if k != "id" && k != "status" {
			errorsJSON(w, 500, "the fake only accepts a status change: "+k)
			return
		}
	}
	if st, ok := in["status"].(float64); ok {
		var doc fieldDoc
		_ = json.Unmarshal(s.TicketFieldsJSON, &doc)
		if _, active, _ := doc.active("status", strconv.FormatInt(int64(st), 10)); !active {
			errorsJSON(w, 500, "status is not an active picklist value.")
			return
		}
		t.Status = int64(st)
		if t.Status == 5 {
			now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
			t.CompletedDate = &now
		}
	}
	writeJSON(w, 200, map[string]any{"itemId": t.ID})
}

func (s *Server) createNote(w http.ResponseWriter, path string, body []byte) {
	mid := strings.TrimSuffix(strings.TrimPrefix(path, "/Tickets/"), "/Notes")
	tid, err := strconv.ParseInt(mid, 10, 64)
	var in struct {
		TicketID    int64  `json:"ticketID"`
		Title       string `json:"title"`
		Description string `json:"description"`
		NoteType    *int64 `json:"noteType"`
		Publish     *int64 `json:"publish"`
	}
	if err != nil || json.Unmarshal(body, &in) != nil {
		errorsJSON(w, 500, "Invalid request.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets[tid] == nil {
		errorsJSON(w, 500, "The parent ticket does not exist.")
		return
	}
	var doc fieldDoc
	_ = json.Unmarshal(s.NoteFieldsJSON, &doc)
	var msgs []string
	if in.NoteType == nil || in.Publish == nil || strings.TrimSpace(in.Description) == "" {
		msgs = append(msgs, "noteType, publish and description are required.")
	} else {
		if _, active, _ := doc.active("noteType", strconv.FormatInt(*in.NoteType, 10)); !active {
			msgs = append(msgs, "noteType is not an active picklist value.")
		}
		if _, active, _ := doc.active("publish", strconv.FormatInt(*in.Publish, 10)); !active {
			msgs = append(msgs, "publish is not an active picklist value.")
		}
	}
	if l := doc.length("description"); l > 0 && len([]rune(in.Description)) > l {
		msgs = append(msgs, "description is too long.")
	}
	if len(msgs) > 0 {
		errorsJSON(w, 500, msgs...)
		return
	}
	s.nextID++
	n := Note{ID: s.nextID, TicketID: tid, Title: in.Title, Description: in.Description, NoteType: *in.NoteType, Publish: *in.Publish}
	s.notes = append(s.notes, n)
	writeJSON(w, 200, map[string]any{"itemId": n.ID})
}
