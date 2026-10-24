package m365

// Permission is one Microsoft Graph application permission the collector uses.
type Permission struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	// Why says what DefendSec reads with it, and what is not assessed without it.
	Why string `json:"why"`
}

// Permissions is the final, minimal set of Microsoft Graph application
// permissions (docs/M365.md lists the Microsoft Learn page each was verified
// against). Every one is a read permission; none can change a tenant.
var Permissions = []Permission{
	{"AuditLog.Read.All", true, "The authentication methods registration report: who has registered MFA. Needs Microsoft Entra ID P1 or P2. Without it, MFA registration is not assessed."},
	{"Policy.Read.All", true, "Security defaults and Conditional Access policies, to see whether legacy authentication is blocked. Conditional Access needs Entra ID P1. Without it, legacy authentication is not assessed."},
	{"RoleManagement.Read.Directory", true, "Directory role assignments: who holds Global Administrator and other administrator roles. Without it, the administrator count is not assessed and an administrator without MFA is ranked high, not critical."},
	{"User.Read.All", true, "The user list: which accounts are enabled members with a mailbox, and the tenant's own domains (to tell an outside address from an inside one). Without it, inbox rules are not assessed."},
	{"MailboxSettings.Read", true, "The definitions of each mailbox's inbox rules: name, conditions and actions. No message is read. Without it, inbox rules are not assessed."},
	{"Mail.ReadBasic.All", false, "Optional, off by default. Names the folder a rule moves mail to (RSS Feeds, Archive, ...). It is broader than the rest: it lets an application read the sender and subject of messages in every mailbox, which DefendSec never requests. Without it, a move to an unnamed folder is only reported when the rule matches finance terms."},
}
