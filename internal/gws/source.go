package gws

import (
	"context"
	"encoding/json"

	"defendsec/internal/gws/google"
)

// GoogleSource reads a domain through the Admin SDK Directory API and the Gmail
// settings API. Every call is a GET.
//
// Endpoints and the scope each needs (verified against Google's reference pages,
// see docs/GOOGLE-WORKSPACE.md for the date and the URLs):
//
//	GET /admin/directory/v1/users              admin.directory.user.readonly (as the administrator)
//	GET /gmail/v1/users/me/settings/autoForwarding   gmail.readonly or gmail.settings.basic (as each user)
//	GET /gmail/v1/users/me/settings/filters          gmail.readonly or gmail.settings.basic (as each user)
type GoogleSource struct{ C *google.Client }

// NewGoogleSource wraps a client.
func NewGoogleSource(c *google.Client) *GoogleSource { return &GoogleSource{C: c} }

// Requests is the number of API requests made so far.
func (g *GoogleSource) Requests() int { return g.C.Requests() }

// Users lists the domain's users.
func (g *GoogleSource) Users(ctx context.Context) ([]User, error) {
	var out []User
	err := g.C.EachUser(ctx, func(raw json.RawMessage) error {
		var u struct {
			ID, PrimaryEmail, OrgUnitPath string
			Name                          struct{ FullName string }
			Aliases                       []string
			IsAdmin                       bool
			IsDelegatedAdmin              bool
			IsEnrolledIn2Sv               bool
			IsEnforcedIn2Sv               bool
			Suspended, Archived           bool
			IsMailboxSetup                *bool
			IsGuestUser                   bool
		}
		if err := json.Unmarshal(raw, &u); err != nil || u.ID == "" || u.PrimaryEmail == "" {
			return &google.Error{Kind: google.KindBadResponse, Path: "/admin/directory/v1/users", Msg: "a user is not the documented JSON"}
		}
		mailbox := true
		if u.IsMailboxSetup != nil {
			mailbox = *u.IsMailboxSetup
		}
		out = append(out, User{
			ID: u.ID, Email: u.PrimaryEmail, Name: u.Name.FullName, Aliases: u.Aliases,
			IsAdmin: u.IsAdmin, IsDelegatedAdmin: u.IsDelegatedAdmin,
			Enrolled2SV: u.IsEnrolledIn2Sv, Enforced2SV: u.IsEnforcedIn2Sv,
			Suspended: u.Suspended, Archived: u.Archived, Guest: u.IsGuestUser, MailboxSetup: mailbox, OrgUnit: u.OrgUnitPath,
		})
		return nil
	})
	return out, err
}

// AutoForwarding reads a user's auto-forwarding setting, acting as that user.
func (g *GoogleSource) AutoForwarding(ctx context.Context, userEmail string) (AutoForwarding, error) {
	var a struct {
		Enabled      bool   `json:"enabled"`
		EmailAddress string `json:"emailAddress"`
		Disposition  string `json:"disposition"`
	}
	if err := g.C.GmailSettings(ctx, userEmail, "autoForwarding", &a); err != nil {
		return AutoForwarding{}, err
	}
	return AutoForwarding{Enabled: a.Enabled, EmailAddress: a.EmailAddress, Disposition: a.Disposition}, nil
}

// Filters reads a user's Gmail filters, acting as that user.
func (g *GoogleSource) Filters(ctx context.Context, userEmail string) ([]Filter, error) {
	var r struct {
		Filter []struct {
			ID       string `json:"id"`
			Criteria struct {
				From, To, Subject, Query, NegatedQuery string
				HasAttachment, ExcludeChats            bool
				Size                                   int64
			} `json:"criteria"`
			Action struct {
				AddLabelIDs    []string `json:"addLabelIds"`
				RemoveLabelIDs []string `json:"removeLabelIds"`
				Forward        string   `json:"forward"`
			} `json:"action"`
		} `json:"filter"`
	}
	if err := g.C.GmailSettings(ctx, userEmail, "filters", &r); err != nil {
		return nil, err
	}
	out := make([]Filter, 0, len(r.Filter))
	for _, f := range r.Filter {
		out = append(out, Filter{
			ID: f.ID, From: f.Criteria.From, To: f.Criteria.To, Subject: f.Criteria.Subject, Query: f.Criteria.Query,
			NegatedQuery: f.Criteria.NegatedQuery, HasAttachment: f.Criteria.HasAttachment, ExcludeChats: f.Criteria.ExcludeChats,
			Size: f.Criteria.Size, AddLabelIDs: f.Action.AddLabelIDs, RemoveLabelIDs: f.Action.RemoveLabelIDs, Forward: f.Action.Forward,
		})
	}
	return out, nil
}
