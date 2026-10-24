package gws

import "defendsec/internal/gws/google"

// Permission is one scope the service account's domain-wide delegation must carry.
type Permission struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Why      string `json:"why"`
}

// Permissions are the OAuth scopes the collector asks for, for the console and
// docs/GOOGLE-WORKSPACE.md. The Directory scope is read-only. Of the two Gmail
// scopes exactly one is delegated: gmail.settings.basic is the default (it cannot
// read mail, but it is a write scope for settings); gmail.readonly is the
// alternative (it cannot change settings, but it could read mail). Both are listed
// so an operator can see what each choice means.
var Permissions = []Permission{
	{Name: google.ScopeDirectoryUsers, Required: true, Why: "Lists the domain's users with their 2-Step Verification state and administrator flags (Admin SDK Directory API, users.list). Read-only."},
	{Name: google.ScopeGmailSettingsBasic, Required: true, Why: "Default Gmail scope. Reads each mailbox's auto-forwarding setting and filters (Gmail API users.settings.getAutoForwarding and filters.list), acting as that user. It cannot read a message, so a leaked key could not read anyone's mail; it is a write scope for Gmail settings (a thief could add a forwarding address or a filter), and DefendSec only makes GET requests. Delegate this one or gmail.readonly, not both."},
	{Name: google.ScopeGmailReadonly, Required: false, Why: "Alternative Gmail scope, for an operator who cannot accept a write scope. The same two reads accept it, but it can read messages, so a leaked key could read every mailbox; DefendSec's client has no call that names one. Select it in the identity settings, and delegate it instead of gmail.settings.basic."},
}
