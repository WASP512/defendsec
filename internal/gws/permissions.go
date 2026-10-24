package gws

import "defendsec/internal/gws/google"

// Permission is one scope the service account's domain-wide delegation must carry.
type Permission struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Why      string `json:"why"`
}

// Permissions are the OAuth scopes the collector asks for, for the console and
// docs/GOOGLE-WORKSPACE.md. Every one is read-only except the alternative Gmail
// scope, which is listed so an operator can see what choosing it means.
var Permissions = []Permission{
	{Name: google.ScopeDirectoryUsers, Required: true, Why: "Lists the domain's users with their 2-Step Verification state and administrator flags (Admin SDK Directory API, users.list). Read-only."},
	{Name: google.ScopeGmailReadonly, Required: true, Why: "Reads each mailbox's auto-forwarding setting and filters (Gmail API users.settings.getAutoForwarding and filters.list), acting as that user. It is the only read-only scope those calls accept. It could also read messages; DefendSec's client has no call that names one. Choose gmail.settings.basic below instead if you prefer a scope that cannot read mail."},
	{Name: google.ScopeGmailSettingsBasic, Required: false, Why: "Alternative to gmail.readonly in the identity settings: it cannot read a message, but it is a write scope for Gmail settings (it could change forwarding and filters). DefendSec still only makes GET requests. Delegate one of the two Gmail scopes, not both."},
}
