package controls

import "sort"

// A Signal names something DefendSec observes or does, in terms that do not
// change when a framework is revised.
//
// Records are tagged with a signal, not with control identifiers directly.
// That indirection is the whole point: when CJIS renumbers a policy area or a
// new framework is added, the mapping table changes and a million stored rows
// do not. It also means a single record can satisfy several frameworks at once
// without storing the same fact five times.
type Signal string

const (
	// SignalAuditChain — the audit log is hash-chained, so an edit, deletion
	// or reordering is detectable.
	SignalAuditChain Signal = "audit.chain"
	// SignalAuditCheckpoint — chain state is periodically signed by the
	// control key, making truncation of the tail detectable.
	SignalAuditCheckpoint Signal = "audit.checkpoint"
	// SignalAuditAnchor — checkpoints are published somewhere the server
	// cannot retroactively control (roadmap 1.6).
	SignalAuditAnchor Signal = "audit.anchor"
	// SignalAuditRetention — audit records are retained for a defined period.
	SignalAuditRetention Signal = "audit.retention"
	// SignalAuditReview — the console presents the ledger for review.
	SignalAuditReview Signal = "audit.review"

	// SignalCommandSigned — every host mutation is Ed25519-signed, and the
	// envelope is persisted so the signature can be checked after the fact.
	SignalCommandSigned Signal = "command.signed"
	// SignalCommandAck — the agent's acknowledgement is itself signed and
	// binds the result text, so "it ran" is a claim the agent made and cannot
	// later disown.
	SignalCommandAck Signal = "command.ack"
	// SignalCommandAttributed — the acting account is recorded on the action.
	SignalCommandAttributed Signal = "command.attributed"

	// SignalIdentityAccounts — named per-person accounts rather than a
	// shared token.
	SignalIdentityAccounts Signal = "identity.accounts"
	// SignalIdentityMFA — second-factor authentication.
	SignalIdentityMFA Signal = "identity.mfa"
	// SignalIdentityLockout — repeated failures lock the account.
	SignalIdentityLockout Signal = "identity.lockout"
	// SignalIdentityRoles — admin and viewer are separated, so read access
	// does not carry the ability to act.
	SignalIdentityRoles Signal = "identity.roles"
	// SignalIdentitySession — sessions expire and can be revoked at once.
	SignalIdentitySession Signal = "identity.session"

	// SignalInventoryHardware — enrolled hosts and their attributes.
	SignalInventoryHardware Signal = "inventory.hardware"
	// SignalInventorySoftware — installed packages per host.
	SignalInventorySoftware Signal = "inventory.software"

	// SignalVulnAssessment — installed versions assessed against advisories,
	// with distro backports handled rather than guessed at.
	SignalVulnAssessment Signal = "vuln.assessment"
	// SignalPatchAction — the signed action that remediates a finding.
	SignalPatchAction Signal = "patch.action"
	// SignalSoftwareSupported — installed software from outside the
	// distribution is checked against its upstream support lifecycle, so
	// software that no longer receives security fixes is found.
	SignalSoftwareSupported Signal = "software.supported"
	// SignalRepoHealth — the host's package repositories are checked for an
	// expired or missing signing key and a stale index, so a "no pending
	// updates" report is not taken from a package manager that has silently
	// stopped refreshing.
	SignalRepoHealth Signal = "repo.health"

	// SignalFIM — file integrity monitoring against a baseline.
	SignalFIM Signal = "fim.integrity"
	// SignalSCA — configuration checks against a baseline pack.
	SignalSCA Signal = "sca.baseline"

	// SignalTransportMTLS — agents authenticate with mutual TLS.
	SignalTransportMTLS Signal = "transport.mtls"
	// SignalCertRevocation — a host certificate can be revoked and the
	// connection dropped.
	SignalCertRevocation Signal = "transport.revocation"

	// SignalAlertLifecycle — findings are triaged, acknowledged and resolved
	// by a named account.
	SignalAlertLifecycle Signal = "alert.lifecycle"
	// SignalIsolation — a host can be isolated in response to an incident.
	SignalIsolation Signal = "response.isolation"
	// SignalDetection — behavioural detection: process execution, network
	// and file activity matched against rules, rather than state compared
	// between snapshots (roadmap 3.3).
	SignalDetection Signal = "detection.behaviour"

	// SignalFIPSCrypto — the cryptographic posture is reported and can be
	// constrained to approved algorithms (roadmap 1.8).
	SignalFIPSCrypto Signal = "crypto.fips"
	// SignalEvidenceExport — a signed, offline-verifiable evidence bundle.
	SignalEvidenceExport Signal = "evidence.export"
	// SignalBackup — backups of the evidence store itself.
	SignalBackup Signal = "backup"
	// SignalManagedUpdate — operator-approved server and agent updates with
	// checksum verification.
	SignalManagedUpdate Signal = "update.managed"

	// The external surface scanner (slice 7a). Each is what the outside world
	// can be seen to do with a declared asset, from DNS, TLS handshakes, MTA-STS
	// fetches and TCP connects only.

	// SignalSurfaceEmail — the domain's published email authentication
	// (SPF, DKIM, DMARC, MTA-STS, TLS-RPT) was read and judged.
	SignalSurfaceEmail Signal = "surface.email"
	// SignalSurfaceDNS — DNS hygiene (DNSSEC, CAA, dangling CNAME).
	SignalSurfaceDNS Signal = "surface.dns"
	// SignalSurfaceTLS — the certificate and protocol versions a declared
	// hostname presents.
	SignalSurfaceTLS Signal = "surface.tls"
	// SignalSurfacePorts — which risky TCP ports on a declared IP accept a
	// connection.
	SignalSurfacePorts Signal = "surface.ports"

	// The Microsoft 365 identity posture collector (slice 12). Each is what a
	// tenant's own configuration was read to say, through Microsoft Graph with
	// read-only application permissions.

	// SignalM365MFA — which users of the tenant have registered multi-factor
	// authentication (the authentication methods registration report).
	SignalM365MFA Signal = "m365.mfa"
	// SignalM365Roles — how many accounts hold which administrator role.
	SignalM365Roles Signal = "m365.roles"
	// SignalM365LegacyAuth — whether security defaults or a Conditional Access
	// policy blocks legacy authentication.
	SignalM365LegacyAuth Signal = "m365.legacyauth"
	// SignalM365MailRules — the definitions of users' inbox rules: external
	// forwarding and rules that hide mail.
	SignalM365MailRules Signal = "m365.mailrules"
)

// SignalTitle is the human sentence for a signal, used wherever a control's
// evidence is explained to someone who does not know DefendSec's internals.
var signalTitles = map[Signal]string{
	SignalAuditChain:        "Hash-chained audit log",
	SignalAuditCheckpoint:   "Signed audit checkpoints",
	SignalAuditAnchor:       "Externally anchored checkpoints",
	SignalAuditRetention:    "Audit retention policy",
	SignalAuditReview:       "Audit log review",
	SignalCommandSigned:     "Cryptographically signed host actions",
	SignalCommandAck:        "Signed agent acknowledgements",
	SignalCommandAttributed: "Per-account action attribution",
	SignalIdentityAccounts:  "Named operator accounts",
	SignalIdentityMFA:       "Multi-factor authentication",
	SignalIdentityLockout:   "Account lockout on repeated failure",
	SignalIdentityRoles:     "Separated admin and read-only roles",
	SignalIdentitySession:   "Session expiry and revocation",
	SignalInventoryHardware: "Hardware and host inventory",
	SignalInventorySoftware: "Installed software inventory",
	SignalVulnAssessment:    "Vulnerability assessment",
	SignalPatchAction:       "Remediation actions",
	SignalSoftwareSupported: "Software support lifecycle",
	SignalRepoHealth:        "Package repository health",
	SignalFIM:               "File integrity monitoring",
	SignalSCA:               "Configuration baseline checks",
	SignalTransportMTLS:     "Mutually authenticated agent transport",
	SignalCertRevocation:    "Host certificate revocation",
	SignalAlertLifecycle:    "Finding triage and resolution",
	SignalIsolation:         "Host isolation",
	SignalDetection:         "Behavioural detection",
	SignalFIPSCrypto:        "Approved cryptographic algorithms",
	SignalEvidenceExport:    "Signed evidence export",
	SignalBackup:            "Evidence store backup",
	SignalManagedUpdate:     "Verified, operator-approved updates",
	SignalSurfaceEmail:      "External email authentication check",
	SignalSurfaceDNS:        "External DNS hygiene check",
	SignalSurfaceTLS:        "External TLS check",
	SignalSurfacePorts:      "External exposed-port check",
	SignalM365MFA:           "Microsoft 365 MFA registration check",
	SignalM365Roles:         "Microsoft 365 administrator role check",
	SignalM365LegacyAuth:    "Microsoft 365 legacy authentication check",
	SignalM365MailRules:     "Microsoft 365 inbox rule check",
}

// SignalTitle returns the human name, falling back to the raw signal so an
// unmapped one is visible rather than blank.
func SignalTitle(s Signal) string {
	if t, ok := signalTitles[s]; ok {
		return t
	}
	return string(s)
}

// KnownSignal reports whether s is one the mapping understands.
func KnownSignal(s Signal) bool {
	_, ok := signalTitles[s]
	return ok
}

// Signals lists every signal in a stable order.
func Signals() []Signal {
	out := make([]Signal, 0, len(signalTitles))
	for s := range signalTitles {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
