package client

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ---- entities --------------------------------------------------------------------

// Company is the part of an Autotask company DefendSec reads.
type Company struct {
	ID          int64  `json:"id"`
	CompanyName string `json:"companyName"`
	IsActive    bool   `json:"isActive"`
	CompanyType int64  `json:"companyType"`
}

// Ticket is the part of an Autotask ticket DefendSec reads back.
type Ticket struct {
	ID            int64   `json:"id"`
	TicketNumber  string  `json:"ticketNumber"`
	CompanyID     int64   `json:"companyID"`
	Title         string  `json:"title"`
	Status        int64   `json:"status"`
	Priority      int64   `json:"priority"`
	QueueID       *int64  `json:"queueID"`
	CompletedDate *string `json:"completedDate"`
}

// Completed reports whether Autotask records the ticket as completed.
func (t Ticket) Completed() bool {
	return t.CompletedDate != nil && strings.TrimSpace(*t.CompletedDate) != ""
}

// TicketCreate is a new ticket. A nil pointer leaves the field out, so the
// category's own default applies.
type TicketCreate struct {
	CompanyID    int64  `json:"companyID"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Status       int64  `json:"status"`
	Priority     int64  `json:"priority"`
	QueueID      *int64 `json:"queueID,omitempty"`
	Source       *int64 `json:"source,omitempty"`
	IssueType    *int64 `json:"issueType,omitempty"`
	SubIssueType *int64 `json:"subIssueType,omitempty"`
	// DueDateTime is UTC, "2006-01-02T15:04:05.00" (the documented format).
	DueDateTime string `json:"dueDateTime,omitempty"`
}

// TicketStatusPatch changes a ticket's status (completing it).
type TicketStatusPatch struct {
	ID     int64 `json:"id"`
	Status int64 `json:"status"`
}

// NoteCreate is a note on a ticket.
type NoteCreate struct {
	TicketID    int64  `json:"ticketID"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	NoteType    int64  `json:"noteType"`
	Publish     int64  `json:"publish"`
}

// PickValue is one entry of a picklist.
type PickValue struct {
	Value        string `json:"value"`
	Label        string `json:"label"`
	IsDefault    bool   `json:"isDefaultValue"`
	SortOrder    int    `json:"sortOrder"`
	ParentValue  string `json:"parentValue"`
	IsActive     bool   `json:"isActive"`
	IsSystemItem bool   `json:"isSystem"`
}

// Field describes one field of an entity (entityInformation/fields).
type Field struct {
	Name                     string      `json:"name"`
	DataType                 string      `json:"dataType"`
	Length                   int         `json:"length"`
	IsRequired               bool        `json:"isRequired"`
	IsReadOnly               bool        `json:"isReadOnly"`
	IsQueryable              bool        `json:"isQueryable"`
	IsReference              bool        `json:"isReference"`
	ReferenceEntityType      string      `json:"referenceEntityType"`
	IsPickList               bool        `json:"isPickList"`
	PicklistValues           []PickValue `json:"picklistValues"`
	PicklistParentValueField string      `json:"picklistParentValueField"`
}

// Fields is an entity's field list by name.
type Fields map[string]Field

// Active returns a field's active picklist values.
func (f Fields) Active(name string) []PickValue {
	var out []PickValue
	for _, v := range f[name].PicklistValues {
		if v.IsActive {
			out = append(out, v)
		}
	}
	return out
}

// HasActive reports whether value is an active entry of the named picklist.
func (f Fields) HasActive(name, value string) bool {
	for _, v := range f.Active(name) {
		if v.Value == value {
			return true
		}
	}
	return false
}

// Label returns the label of a picklist value ("" if unknown).
func (f Fields) Label(name, value string) string {
	for _, v := range f[name].PicklistValues {
		if v.Value == value {
			return v.Label
		}
	}
	return ""
}

// Threshold is ThresholdInformation: what the database has used this hour.
type Threshold struct {
	ExternalRequestThreshold     int `json:"externalRequestThreshold"`
	RequestThresholdTimeframe    int `json:"requestThresholdTimeframe"`
	CurrentTimeframeRequestCount int `json:"currentTimeframeRequestCount"`
}

// ---- calls -----------------------------------------------------------------------

func queryBody(filter []map[string]any, fields []string, max int) map[string]any {
	b := map[string]any{"filter": filter}
	if len(fields) > 0 {
		b["IncludeFields"] = fields
	}
	if max > 0 {
		b["MaxRecords"] = max
	}
	return b
}

// Threshold reads the database's request count for the current hour.
func (c *Client) Threshold(ctx context.Context) (Threshold, error) {
	var t Threshold
	err := c.request(ctx, "read threshold", "GET", "/ThresholdInformation", nil, &t, true)
	if err == nil && t.ExternalRequestThreshold <= 0 {
		return Threshold{}, &Error{Kind: KindBadResponse, Op: "read threshold", Messages: []string{"no threshold in the answer"}}
	}
	return t, err
}

// Company reads one company by id.
func (c *Client) Company(ctx context.Context, id int64) (Company, error) {
	var out struct {
		Item *Company `json:"item"`
	}
	if err := c.request(ctx, "read company", "GET", "/Companies/"+strconv.FormatInt(id, 10), nil, &out, true); err != nil {
		return Company{}, err
	}
	if out.Item == nil || out.Item.ID != id {
		return Company{}, &Error{Kind: KindRejected, Op: "read company", Messages: []string{"no such company, or the API user cannot see it"}}
	}
	return *out.Item, nil
}

// SearchCompanies finds active companies whose name contains text (at most 25),
// so the settings page can offer a lookup. The id, not the name, is what is saved.
func (c *Client) SearchCompanies(ctx context.Context, text string) ([]Company, error) {
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return nil, &Error{Kind: KindRejected, Op: "search companies", Messages: []string{"type at least two characters"}}
	}
	var out struct {
		Items []Company `json:"items"`
	}
	body := queryBody([]map[string]any{
		{"op": "contains", "field": "companyName", "value": text},
		{"op": "eq", "field": "isActive", "value": true},
	}, []string{"id", "companyName", "isActive", "companyType"}, 25)
	if err := c.request(ctx, "search companies", "POST", "/Companies/query", body, &out, true); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) fields(ctx context.Context, entity string) (Fields, error) {
	var out struct {
		Fields []Field `json:"fields"`
	}
	if err := c.request(ctx, "read "+entity+" fields", "GET", "/"+entity+"/entityInformation/fields", nil, &out, true); err != nil {
		return nil, err
	}
	if len(out.Fields) == 0 {
		return nil, &Error{Kind: KindBadResponse, Op: "read " + entity + " fields", Messages: []string{"no fields in the answer"}}
	}
	f := make(Fields, len(out.Fields))
	for _, x := range out.Fields {
		f[x.Name] = x
	}
	return f, nil
}

// TicketFields reads the ticket field list with its live picklists: queue,
// status, priority, source, issue and sub-issue types.
func (c *Client) TicketFields(ctx context.Context) (Fields, error) { return c.fields(ctx, "Tickets") }

// NoteFields reads the ticket note field list (note type and publish picklists).
func (c *Client) NoteFields(ctx context.Context) (Fields, error) { return c.fields(ctx, "TicketNotes") }

var ticketFieldList = []string{"id", "ticketNumber", "companyID", "title", "status", "priority", "queueID", "completedDate"}

// GetTickets reads tickets by id in one request per 100 ids. A ticket that does
// not exist (or the API user cannot see) is simply absent from the result.
func (c *Client) GetTickets(ctx context.Context, ids []int64) (map[int64]Ticket, error) {
	out := map[int64]Ticket{}
	for start := 0; start < len(ids); start += 100 {
		end := start + 100
		if end > len(ids) {
			end = len(ids)
		}
		vals := make([]int64, 0, end-start)
		vals = append(vals, ids[start:end]...)
		var resp struct {
			Items []Ticket `json:"items"`
		}
		body := queryBody([]map[string]any{{"op": "in", "field": "id", "value": vals}}, ticketFieldList, 500)
		if err := c.request(ctx, "read tickets", "POST", "/Tickets/query", body, &resp, true); err != nil {
			return nil, err
		}
		for _, t := range resp.Items {
			out[t.ID] = t
		}
	}
	return out, nil
}

// FindTickets finds the company's tickets whose title contains tag. The tag is
// DefendSec's key in the title, so this is how a ticket is found again when the
// local record of it is lost.
func (c *Client) FindTickets(ctx context.Context, companyID int64, tag string) ([]Ticket, error) {
	if strings.TrimSpace(tag) == "" {
		return nil, &Error{Kind: KindRejected, Op: "find tickets", Messages: []string{"no tag"}}
	}
	var resp struct {
		Items []Ticket `json:"items"`
	}
	body := queryBody([]map[string]any{
		{"op": "eq", "field": "companyID", "value": companyID},
		{"op": "contains", "field": "title", "value": tag},
	}, ticketFieldList, 50)
	if err := c.request(ctx, "find tickets", "POST", "/Tickets/query", body, &resp, true); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// itemID reads {"itemId": n}, which a create and an update answer with.
type itemID struct {
	ItemID int64 `json:"itemId"`
}

// CreateTicket creates a ticket and returns its id. After an ambiguous failure
// (Error.Ambiguous) the ticket may exist: FindTickets before trying again.
func (c *Client) CreateTicket(ctx context.Context, t TicketCreate) (int64, error) {
	var out itemID
	if err := c.request(ctx, "create ticket", "POST", "/Tickets", t, &out, false); err != nil {
		return 0, err
	}
	if out.ItemID <= 0 {
		return 0, &Error{Kind: KindBadResponse, Op: "create ticket", Ambiguous: true, Messages: []string{"no ticket id in the answer"}}
	}
	return out.ItemID, nil
}

// SetTicketStatus changes a ticket's status. It is the only update DefendSec
// makes to a ticket, and only to complete one when the operator has allowed it.
func (c *Client) SetTicketStatus(ctx context.Context, id, status int64) error {
	return c.request(ctx, "update ticket", "PATCH", "/Tickets", TicketStatusPatch{ID: id, Status: status}, &itemID{}, true)
}

// CreateNote adds a note to a ticket (the child collection of the ticket).
func (c *Client) CreateNote(ctx context.Context, n NoteCreate) (int64, error) {
	var out itemID
	path := "/Tickets/" + url.PathEscape(strconv.FormatInt(n.TicketID, 10)) + "/Notes"
	if err := c.request(ctx, "create ticket note", "POST", path, n, &out, false); err != nil {
		return 0, err
	}
	if out.ItemID <= 0 {
		return 0, &Error{Kind: KindBadResponse, Op: "create ticket note", Ambiguous: true, Messages: []string{"no note id in the answer"}}
	}
	return out.ItemID, nil
}

// String is for logs: the zone, never a credential.
func (c *Client) String() string { return fmt.Sprintf("autotask client for %s", c.base) }
