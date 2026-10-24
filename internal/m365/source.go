package m365

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"defendsec/internal/m365/graph"
)

// GraphSource reads a tenant through Microsoft Graph. Every call is a GET.
//
// Endpoints and the application permission each needs (verified against
// Microsoft Learn, see docs/M365.md for the date and the URLs):
//
//	GET /users                                                 User.Read.All
//	GET /reports/authenticationMethods/userRegistrationDetails AuditLog.Read.All (+ Entra ID P1/P2)
//	GET /roleManagement/directory/roleDefinitions              RoleManagement.Read.Directory
//	GET /roleManagement/directory/roleAssignments?$expand=principal   RoleManagement.Read.Directory
//	GET /policies/identitySecurityDefaultsEnforcementPolicy    Policy.Read.All
//	GET /identity/conditionalAccess/policies                   Policy.Read.All (+ Entra ID P1)
//	GET /users/{id}/mailFolders/inbox/messageRules             MailboxSettings.Read
//	GET /users/{id}/mailFolders/{folderId}?$select=displayName Mail.ReadBasic.All (optional, off by default)
type GraphSource struct{ C *graph.Client }

// NewGraphSource wraps a client.
func NewGraphSource(c *graph.Client) *GraphSource { return &GraphSource{C: c} }

// Requests is the number of Graph requests made so far.
func (g *GraphSource) Requests() int { return g.C.Requests() }

func q(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func (g *GraphSource) SecurityDefaults(ctx context.Context) (SecurityDefaults, error) {
	var d struct {
		IsEnabled *bool `json:"isEnabled"`
	}
	if err := g.C.Get(ctx, "/policies/identitySecurityDefaultsEnforcementPolicy", nil, &d); err != nil {
		return SecurityDefaults{}, err
	}
	if d.IsEnabled == nil {
		return SecurityDefaults{}, &graph.Error{Kind: graph.KindBadResponse, Path: "/policies/identitySecurityDefaultsEnforcementPolicy", Msg: "no isEnabled in the answer"}
	}
	return SecurityDefaults{Enabled: *d.IsEnabled}, nil
}

func (g *GraphSource) ConditionalAccessPolicies(ctx context.Context) ([]CAPolicy, error) {
	var out []CAPolicy
	err := g.C.Each(ctx, "/identity/conditionalAccess/policies", nil, func(raw json.RawMessage) error {
		var p struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			State       string `json:"state"`
			Conditions  struct {
				ClientAppTypes []string `json:"clientAppTypes"`
				Users          struct {
					IncludeUsers, ExcludeUsers, IncludeGroups, ExcludeGroups, IncludeRoles, ExcludeRoles []string
				} `json:"users"`
				Applications struct {
					IncludeApplications, ExcludeApplications []string
				} `json:"applications"`
			} `json:"conditions"`
			GrantControls *struct {
				Operator        string   `json:"operator"`
				BuiltInControls []string `json:"builtInControls"`
			} `json:"grantControls"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return &graph.Error{Kind: graph.KindBadResponse, Path: "/identity/conditionalAccess/policies", Msg: "a policy is not the documented JSON"}
		}
		cp := CAPolicy{
			ID: p.ID, DisplayName: p.DisplayName, State: p.State, ClientAppTypes: p.Conditions.ClientAppTypes,
			IncludeUsers: p.Conditions.Users.IncludeUsers, ExcludeUsers: p.Conditions.Users.ExcludeUsers,
			IncludeGroups: p.Conditions.Users.IncludeGroups, ExcludeGroups: p.Conditions.Users.ExcludeGroups,
			IncludeRoles: p.Conditions.Users.IncludeRoles, ExcludeRoles: p.Conditions.Users.ExcludeRoles,
			IncludeApps: p.Conditions.Applications.IncludeApplications, ExcludeApps: p.Conditions.Applications.ExcludeApplications,
		}
		if p.GrantControls != nil {
			cp.BuiltInControls, cp.GrantOperator = p.GrantControls.BuiltInControls, p.GrantControls.Operator
		}
		out = append(out, cp)
		return nil
	})
	return out, err
}

func (g *GraphSource) Users(ctx context.Context) ([]User, error) {
	var out []User
	err := g.C.Each(ctx, "/users", q("$select", "id,userPrincipalName,displayName,mail,accountEnabled,userType", "$top", "999"), func(raw json.RawMessage) error {
		var u struct {
			ID, UserPrincipalName, DisplayName, Mail, UserType string
			AccountEnabled                                     *bool
		}
		if err := json.Unmarshal(raw, &u); err != nil {
			return &graph.Error{Kind: graph.KindBadResponse, Path: "/users", Msg: "a user is not the documented JSON"}
		}
		on := true
		if u.AccountEnabled != nil {
			on = *u.AccountEnabled
		}
		out = append(out, User{ID: u.ID, UPN: u.UserPrincipalName, DisplayName: u.DisplayName, Mail: u.Mail, AccountEnabled: on, UserType: u.UserType})
		return nil
	})
	return out, err
}

func (g *GraphSource) MFARegistrations(ctx context.Context) ([]MFARegistration, error) {
	var out []MFARegistration
	err := g.C.Each(ctx, "/reports/authenticationMethods/userRegistrationDetails", q("$top", "999"), func(raw json.RawMessage) error {
		var r struct {
			ID, UserPrincipalName, UserDisplayName, UserType string
			IsAdmin, IsMfaRegistered, IsMfaCapable           bool
			MethodsRegistered                                []string
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return &graph.Error{Kind: graph.KindBadResponse, Path: "/reports/authenticationMethods/userRegistrationDetails", Msg: "a row is not the documented JSON"}
		}
		out = append(out, MFARegistration{ID: r.ID, UPN: r.UserPrincipalName, DisplayName: r.UserDisplayName, UserType: r.UserType,
			IsAdmin: r.IsAdmin, IsMfaRegistered: r.IsMfaRegistered, IsMfaCapable: r.IsMfaCapable, Methods: r.MethodsRegistered})
		return nil
	})
	return out, err
}

func (g *GraphSource) RoleDefinitions(ctx context.Context) ([]RoleDefinition, error) {
	var out []RoleDefinition
	err := g.C.Each(ctx, "/roleManagement/directory/roleDefinitions", q("$select", "id,displayName,templateId"), func(raw json.RawMessage) error {
		var d struct{ ID, DisplayName, TemplateID string }
		if err := json.Unmarshal(raw, &d); err != nil {
			return &graph.Error{Kind: graph.KindBadResponse, Path: "/roleManagement/directory/roleDefinitions", Msg: "a role is not the documented JSON"}
		}
		out = append(out, RoleDefinition{ID: d.ID, DisplayName: d.DisplayName, TemplateID: d.TemplateID})
		return nil
	})
	return out, err
}

func (g *GraphSource) RoleAssignments(ctx context.Context) ([]RoleAssignment, error) {
	var out []RoleAssignment
	err := g.C.Each(ctx, "/roleManagement/directory/roleAssignments", q("$expand", "principal"), func(raw json.RawMessage) error {
		var a struct {
			ID               string `json:"id"`
			PrincipalID      string `json:"principalId"`
			RoleDefinitionID string `json:"roleDefinitionId"`
			Principal        struct {
				Type              string `json:"@odata.type"`
				UserPrincipalName string `json:"userPrincipalName"`
				DisplayName       string `json:"displayName"`
			} `json:"principal"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return &graph.Error{Kind: graph.KindBadResponse, Path: "/roleManagement/directory/roleAssignments", Msg: "an assignment is not the documented JSON"}
		}
		t := strings.TrimPrefix(a.Principal.Type, "#microsoft.graph.")
		out = append(out, RoleAssignment{ID: a.ID, PrincipalID: a.PrincipalID, RoleDefinitionID: a.RoleDefinitionID,
			PrincipalType: t, PrincipalUPN: a.Principal.UserPrincipalName, PrincipalName: a.Principal.DisplayName})
		return nil
	})
	return out, err
}

type recipientJSON struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

func addresses(l []recipientJSON) []string {
	var out []string
	for _, r := range l {
		if a := strings.TrimSpace(r.EmailAddress.Address); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// ruleKnownConditions and ruleKnownActions are the keys InboxRule models; any
// other key with a non-empty value is named in OtherConditions/OtherActions.
var ruleKnownConditions = map[string]bool{
	"senderContains": true, "fromAddresses": true, "subjectContains": true, "bodyContains": true,
	"bodyOrSubjectContains": true, "headerContains": true, "recipientContains": true,
}
var ruleKnownActions = map[string]bool{
	"delete": true, "permanentDelete": true, "markAsRead": true, "moveToFolder": true, "copyToFolder": true,
	"forwardTo": true, "redirectTo": true, "forwardAsAttachmentTo": true,
}

func emptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "false" || s == "[]" || s == "{}" || s == `""`
}

func otherKeys(m map[string]json.RawMessage, known map[string]bool) []string {
	var out []string
	for k, v := range m {
		if !known[k] && !emptyJSON(v) && k != "stopProcessingRules" && k != "markImportance" && k != "assignCategories" {
			out = append(out, k)
		}
	}
	// Stable order.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// InboxRules reads the definitions of a user's inbox rules: name, conditions,
// actions. It reads no message.
func (g *GraphSource) InboxRules(ctx context.Context, userID string) ([]InboxRule, error) {
	var out []InboxRule
	path := "/users/" + url.PathEscape(userID) + "/mailFolders/inbox/messageRules"
	err := g.C.Each(ctx, path, nil, func(raw json.RawMessage) error {
		var r struct {
			ID          string                     `json:"id"`
			DisplayName string                     `json:"displayName"`
			Sequence    int                        `json:"sequence"`
			IsEnabled   bool                       `json:"isEnabled"`
			HasError    bool                       `json:"hasError"`
			IsReadOnly  bool                       `json:"isReadOnly"`
			Conditions  map[string]json.RawMessage `json:"conditions"`
			Actions     map[string]json.RawMessage `json:"actions"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return &graph.Error{Kind: graph.KindBadResponse, Path: "messageRules", Msg: "a rule is not the documented JSON"}
		}
		rule := InboxRule{ID: r.ID, Name: r.DisplayName, Sequence: r.Sequence, Enabled: r.IsEnabled, HasError: r.HasError, ReadOnly: r.IsReadOnly}
		strs := func(m map[string]json.RawMessage, k string) []string {
			var l []string
			_ = json.Unmarshal(m[k], &l)
			return l
		}
		recips := func(m map[string]json.RawMessage, k string) []string {
			var l []recipientJSON
			_ = json.Unmarshal(m[k], &l)
			return addresses(l)
		}
		boolOf := func(m map[string]json.RawMessage, k string) bool {
			var b bool
			_ = json.Unmarshal(m[k], &b)
			return b
		}
		str := func(m map[string]json.RawMessage, k string) string {
			var s string
			_ = json.Unmarshal(m[k], &s)
			return s
		}
		rule.SenderContains = strs(r.Conditions, "senderContains")
		rule.FromAddresses = recips(r.Conditions, "fromAddresses")
		rule.SubjectContains = strs(r.Conditions, "subjectContains")
		rule.BodyContains = strs(r.Conditions, "bodyContains")
		rule.BodyOrSubjectContains = strs(r.Conditions, "bodyOrSubjectContains")
		rule.HeaderContains = strs(r.Conditions, "headerContains")
		rule.RecipientContains = strs(r.Conditions, "recipientContains")
		rule.OtherConditions = otherKeys(r.Conditions, ruleKnownConditions)
		rule.Delete = boolOf(r.Actions, "delete")
		rule.PermanentDelete = boolOf(r.Actions, "permanentDelete")
		rule.MarkAsRead = boolOf(r.Actions, "markAsRead")
		rule.MoveToFolder = str(r.Actions, "moveToFolder")
		rule.CopyToFolder = str(r.Actions, "copyToFolder")
		rule.ForwardTo = recips(r.Actions, "forwardTo")
		rule.RedirectTo = recips(r.Actions, "redirectTo")
		rule.ForwardAsAttachmentTo = recips(r.Actions, "forwardAsAttachmentTo")
		rule.OtherActions = otherKeys(r.Actions, ruleKnownActions)
		out = append(out, rule)
		return nil
	})
	return out, err
}

// FolderName reads the display name of one mail folder. It reads folder
// metadata only, never a message; it needs Mail.ReadBasic.All, which is why it
// is only called when the operator enabled folder names.
func (g *GraphSource) FolderName(ctx context.Context, userID, folderID string) (string, error) {
	var f struct {
		DisplayName string `json:"displayName"`
	}
	path := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(folderID)
	if err := g.C.Get(ctx, path, q("$select", "displayName"), &f); err != nil {
		return "", err
	}
	return f.DisplayName, nil
}
