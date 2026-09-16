package controls

import (
	"fmt"
	"sort"
)

// Coverage states how well DefendSec can evidence a control. It is recorded
// per control rather than summarised, because the summary is where compliance
// products become dishonest: a coverage percentage lets a control DefendSec
// has never looked at disappear into a rounding error.
type Coverage string

const (
	// CoverageEvidenced — DefendSec produces the technical evidence this
	// control asks for, and an assessor can check it.
	CoverageEvidenced Coverage = "evidenced"
	// CoveragePartial — DefendSec evidences part of the control. The Note
	// says which part is missing and who has to supply it.
	CoveragePartial Coverage = "partial"
	// CoverageNone — DefendSec cannot evidence this control at all. It is
	// still listed, because a control silently absent from a compliance view
	// reads as "no finding" to the person least able to tell the difference.
	CoverageNone Coverage = "not-evidenced"
)

// Rank orders coverage from weakest to strongest, so a derived control can
// take the weakest of the things it depends on rather than the flattering one.
func (c Coverage) Rank() int {
	switch c {
	case CoverageEvidenced:
		return 2
	case CoveragePartial:
		return 1
	default:
		return 0
	}
}

// Control is one catalog entry.
type Control struct {
	ID       ID       `json:"id"`
	Title    string   `json:"title"`
	Family   string   `json:"family"`
	Coverage Coverage `json:"coverage"`
	Signals  []Signal `json:"signals,omitempty"`
	Note     string   `json:"note,omitempty"`
	// DerivedFrom names the hub controls this entry was crosswalked from,
	// so an assessor can see the reasoning rather than trusting the mapping.
	DerivedFrom []ID `json:"derivedFrom,omitempty"`
}

// native is the hand-written half of the catalog: NIST SP 800-53 Rev 5 and
// CIS Controls v8. Everything else is crosswalked onto these.
//
// Titles are paraphrased to what the control requires, not copied from the
// publications. The intent is that an operator reading the compliance view
// understands what is being claimed; the authoritative wording is in the
// publication, and this is not a substitute for it.
var native = []Control{
	// --- Audit and Accountability (AU) -----------------------------------
	{
		ID: MustParseID("nist-800-53:AU-2"), Family: "AU",
		Title:    "Event logging — determine which events the system logs",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditChain, SignalCommandSigned, SignalAlertLifecycle},
		Note:     "DefendSec logs its own administrative actions, agent actions and findings. The organisation still has to decide and document which host-level events are in scope; DefendSec does not enumerate that for you.",
	},
	{
		ID: MustParseID("nist-800-53:AU-3"), Family: "AU",
		Title:    "Content of audit records — what, when, where, source, outcome, who",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditChain, SignalCommandAttributed, SignalCommandAck},
		Note:     "Every ledger entry carries the event, the time, the host, the acting account and the outcome. Actions taken through a shared bootstrap token are recorded as unattributed rather than as a person, which is honest but is not the 'who' the control wants — create named accounts.",
	},
	{
		ID: MustParseID("nist-800-53:AU-6"), Family: "AU",
		Title:    "Audit record review, analysis and reporting",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditReview, SignalAlertLifecycle},
		Note:     "The console presents the ledger and the findings for review. Evidence that a human actually reviewed them on a defined frequency is a process record DefendSec does not hold.",
	},
	{
		ID: MustParseID("nist-800-53:AU-8"), Family: "AU",
		Title:    "Time stamps from an authoritative source",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditChain, SignalAuditAnchor},
		Note:     "Ledger times come from the control plane's clock. An RFC 3161 anchor gives a third party's time for a checkpoint; host clock synchronisation itself is the operating system's job and is not evidenced here.",
	},
	{
		ID: MustParseID("nist-800-53:AU-9"), Family: "AU",
		Title:    "Protection of audit information from unauthorised modification",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalAuditChain, SignalAuditCheckpoint},
		Note:     "Each entry carries the hash of the one before it, so an edit, deletion or reordering breaks the chain at that point and every point after it.",
	},
	{
		ID: MustParseID("nist-800-53:AU-9(3)"), Family: "AU",
		Title:    "Cryptographic protection of audit information",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalAuditChain, SignalAuditCheckpoint, SignalFIPSCrypto},
		Note:     "SHA-256 hash chain with checkpoints signed by the control key, verifiable offline with the server stopped.",
	},
	{
		ID: MustParseID("nist-800-53:AU-10"), Family: "AU",
		Title:    "Non-repudiation of actions",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalCommandSigned, SignalCommandAck, SignalCommandAttributed, SignalIdentityAccounts},
		Note:     "Host mutations are Ed25519-signed by the control plane and acknowledged with an ECDSA signature that binds the result text, each attributed to a named account.",
	},
	{
		ID: MustParseID("nist-800-53:AU-11"), Family: "AU",
		Title:    "Audit record retention",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditRetention, SignalBackup},
		Note:     "The audit ledger is never pruned, and command history defaults to one year — the CJIS Policy Area 4 minimum. GET /v1/retention reports the windows actually in force and how much history is really held, because a one-year policy on a system installed last month evidences one month.",
	},

	// --- Access Control (AC) ---------------------------------------------
	{
		ID: MustParseID("nist-800-53:AC-2"), Family: "AC",
		Title:    "Account management",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalIdentityAccounts, SignalIdentitySession, SignalIdentityRoles},
		Note:     "Covers accounts for DefendSec itself: creation, role, disablement and session revocation, all recorded. Accounts on the managed hosts are inventoried but not governed.",
	},
	{
		ID: MustParseID("nist-800-53:AC-3"), Family: "AC",
		Title:    "Access enforcement",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalIdentityRoles, SignalTransportMTLS},
		Note:     "Admin and viewer are separated, and agents are admitted only with a valid client certificate. Enforcement on the hosts themselves is out of scope.",
	},
	{
		ID: MustParseID("nist-800-53:AC-6(9)"), Family: "AC",
		Title:    "Logging use of privileged functions",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalCommandSigned, SignalCommandAttributed, SignalAuditChain},
		Note:     "Every privileged action — isolate, kill, live query, quarantine, script, update — is signed, attributed and chained.",
	},
	{
		ID: MustParseID("nist-800-53:AC-7"), Family: "AC",
		Title:    "Unsuccessful logon attempts",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityLockout},
		Note:     "Repeated failures lock the account for a fixed interval, and the correct password does not bypass an active lockout.",
	},
	{
		ID: MustParseID("nist-800-53:AC-12"), Family: "AC",
		Title:    "Session termination",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentitySession},
		Note:     "Sessions expire, and disabling an account invalidates its live sessions immediately rather than at next expiry.",
	},

	// --- Identification and Authentication (IA) --------------------------
	{
		ID: MustParseID("nist-800-53:IA-2"), Family: "IA",
		Title:    "Unique identification and authentication of organisational users",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityAccounts},
		Note:     "Named accounts, and the ledger records the account rather than the role.",
	},
	{
		ID: MustParseID("nist-800-53:IA-2(1)"), Family: "IA",
		Title:    "Multi-factor authentication for privileged accounts",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityMFA},
		Note:     "TOTP, with a per-account replay check so an observed code cannot be presented twice.",
	},
	{
		ID: MustParseID("nist-800-53:IA-3"), Family: "IA",
		Title:    "Device identification and authentication",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalTransportMTLS, SignalCertRevocation},
		Note:     "Each agent holds a per-host certificate issued at enrollment; revocation drops the live connection.",
	},
	{
		ID: MustParseID("nist-800-53:IA-5"), Family: "IA",
		Title:    "Authenticator management",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalIdentityAccounts, SignalFIPSCrypto},
		Note:     "Passwords are stored only as salted hashes with a minimum length enforced. Rotation intervals and complexity policy beyond length are not enforced by DefendSec.",
	},

	// --- Configuration Management (CM) -----------------------------------
	{
		ID: MustParseID("nist-800-53:CM-2"), Family: "CM",
		Title:    "Baseline configuration",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalSCA, SignalFIM},
		Note:     "Configuration baselines are checked per pack and file baselines are monitored. The authoritative baseline document itself lives outside DefendSec.",
	},
	{
		ID: MustParseID("nist-800-53:CM-3"), Family: "CM",
		Title:    "Configuration change control",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalFIM, SignalCommandSigned, SignalAuditChain},
		Note:     "Changes made through DefendSec are signed and recorded, and unexpected file changes are detected. Change approval workflow is not modelled.",
	},
	{
		ID: MustParseID("nist-800-53:CM-5"), Family: "CM",
		Title:    "Access restrictions for change",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityRoles, SignalCommandSigned, SignalCommandAttributed},
		Note:     "Only an admin account can issue a mutating command, and the signed envelope records which one did.",
	},
	{
		ID: MustParseID("nist-800-53:CM-6"), Family: "CM",
		Title:    "Configuration settings",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalSCA},
		Note:     "Checked against the shipped packs. DefendSec does not ship full benchmark content and does not claim benchmark coverage.",
	},
	{
		ID: MustParseID("nist-800-53:CM-8"), Family: "CM",
		Title:    "System component inventory",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalInventoryHardware, SignalInventorySoftware},
		Note:     "Enrolled hosts and their installed packages, refreshed by the agent.",
	},

	// --- Risk Assessment and System Integrity (RA, SI) -------------------
	{
		ID: MustParseID("nist-800-53:RA-5"), Family: "RA",
		Title:    "Vulnerability monitoring and scanning",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalVulnAssessment, SignalInventorySoftware},
		Note:     "Installed versions are assessed against advisories using the distribution's own version ordering, so a backported fix is not reported as vulnerable.",
	},
	{
		ID: MustParseID("nist-800-53:SI-2"), Family: "SI",
		Title:    "Flaw remediation",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalVulnAssessment, SignalPatchAction, SignalAlertLifecycle},
		Note:     "Findings are tracked to resolution and remediation actions are signed. Remediation timeliness against an organisational standard is not measured.",
	},
	{
		ID: MustParseID("nist-800-53:SI-4"), Family: "SI",
		Title:    "System monitoring",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalFIM, SignalSCA, SignalAlertLifecycle, SignalIsolation},
		Note:     "Host-level integrity and configuration monitoring with a response path. Network monitoring and intrusion detection are not part of DefendSec.",
	},
	{
		ID: MustParseID("nist-800-53:SI-7"), Family: "SI",
		Title:    "Software, firmware and information integrity",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalFIM, SignalAuditChain, SignalManagedUpdate},
		Note:     "File baselines detect modification, updates are checksum-verified before replacement, and the ledger detects its own modification.",
	},

	// --- Incident Response and Contingency (IR, CP) ----------------------
	{
		ID: MustParseID("nist-800-53:IR-4"), Family: "IR",
		Title:    "Incident handling",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAlertLifecycle, SignalIsolation, SignalEvidenceExport},
		Note:     "Detection, containment and an exportable evidence record. The incident response plan, roles and exercises are organisational and are not held here.",
	},
	{
		ID: MustParseID("nist-800-53:IR-5"), Family: "IR",
		Title:    "Incident monitoring and tracking",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalAlertLifecycle, SignalAuditChain},
		Note:     "Each finding carries its full lifecycle — raised, acknowledged, resolved or reopened — attributed and chained.",
	},
	{
		ID: MustParseID("nist-800-53:CP-9"), Family: "CP",
		Title:    "System backup",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalBackup},
		Note:     "A backup script and a systemd timer are provided but are not enabled automatically, and DefendSec cannot see whether backups are copied off the host. Enable the timer and verify it.",
	},

	// --- System and Communications Protection (SC) -----------------------
	{
		ID: MustParseID("nist-800-53:SC-8"), Family: "SC",
		Title:    "Transmission confidentiality and integrity",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalTransportMTLS},
		Note:     "Agent traffic is mutually authenticated TLS. Console TLS is terminated by the operator's reverse proxy and is the operator's to evidence.",
	},
	{
		ID: MustParseID("nist-800-53:SC-13"), Family: "SC",
		Title:    "Cryptographic protection using approved algorithms",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalFIPSCrypto},
		Note:     "Algorithms are approved ones and the live posture is reported, including the deviations. Running under an approved mode is not the same as holding a validation certificate; the module's certificate status is the Go project's, not DefendSec's.",
	},
	{
		ID: MustParseID("nist-800-53:SC-28"), Family: "SC",
		Title:    "Protection of information at rest",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalSCA, SignalInventoryHardware},
		Note:     "The agent reports whether host disk encryption is enabled, and a baseline check fails when it is not — so the state is evidenced per host. DefendSec does not configure encryption, and says nothing about the database's own encryption at rest or about key management.",
	},

	// --- Controls DefendSec deliberately cannot evidence ------------------
	{
		ID: MustParseID("nist-800-53:AT-2"), Family: "AT",
		Title:    "Security awareness training",
		Coverage: CoverageNone,
		Note:     "Training records are not technical telemetry. No security product should claim this one.",
	},
	{
		ID: MustParseID("nist-800-53:MP-6"), Family: "MP",
		Title:    "Media sanitisation",
		Coverage: CoverageNone,
		Note:     "DefendSec does not perform or witness media sanitisation.",
	},
	{
		ID: MustParseID("nist-800-53:PE-3"), Family: "PE",
		Title:    "Physical access control",
		Coverage: CoverageNone,
		Note:     "Physical controls are outside anything an agent can observe.",
	},
	{
		ID: MustParseID("nist-800-53:PS-3"), Family: "PS",
		Title:    "Personnel screening",
		Coverage: CoverageNone,
		Note:     "Personnel records are held by the agency, not by DefendSec.",
	},

	// --- CIS Controls v8 --------------------------------------------------
	{
		ID: MustParseID("cis-v8:1.1"), Family: "1",
		Title:    "Establish and maintain a detailed enterprise asset inventory",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalInventoryHardware},
		Note:     "Enrolled hosts with their attributes and last-seen time. Assets that never enroll are, by definition, not in it — reconcile against a network source.",
	},
	{
		ID: MustParseID("cis-v8:2.1"), Family: "2",
		Title:    "Establish and maintain a software inventory",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalInventorySoftware},
		Note:     "Installed packages per host, collected by the agent.",
	},
	{
		ID: MustParseID("cis-v8:3.11"), Family: "3",
		Title:    "Encrypt sensitive data at rest",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalSCA, SignalInventoryHardware},
		Note:     "Host disk encryption state is collected and checked. Encryption of the data itself, inside applications or the database, is not.",
	},
	{
		ID: MustParseID("cis-v8:4.1"), Family: "4",
		Title:    "Establish and maintain a secure configuration process",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalSCA, SignalFIM},
		Note:     "The checking half is evidenced. The documented process itself is organisational.",
	},
	{
		ID: MustParseID("cis-v8:5.1"), Family: "5",
		Title:    "Establish and maintain an inventory of accounts",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalIdentityAccounts},
		Note:     "Accounts for DefendSec are inventoried. Accounts on the managed hosts are not enumerated.",
	},
	{
		ID: MustParseID("cis-v8:5.4"), Family: "5",
		Title:    "Restrict administrator privileges to dedicated administrator accounts",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityRoles, SignalCommandAttributed},
		Note:     "Viewer accounts can read but cannot act, and the actor on every action is recorded.",
	},
	{
		ID: MustParseID("cis-v8:6.3"), Family: "6",
		Title:    "Require MFA for externally-exposed applications",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityMFA},
		Note:     "TOTP with replay prevention. Whether the console is externally exposed is the operator's deployment decision.",
	},
	{
		ID: MustParseID("cis-v8:6.5"), Family: "6",
		Title:    "Require MFA for administrative access",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalIdentityMFA, SignalIdentityRoles},
		Note:     "Enrollable per account; enforce it on every admin account rather than assuming it.",
	},
	{
		ID: MustParseID("cis-v8:7.1"), Family: "7",
		Title:    "Establish and maintain a vulnerability management process",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalVulnAssessment, SignalAlertLifecycle},
		Note:     "Continuous assessment and tracking to resolution; the documented process and remediation SLAs are organisational.",
	},
	{
		ID: MustParseID("cis-v8:7.3"), Family: "7",
		Title:    "Perform automated operating system patch management",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalVulnAssessment, SignalPatchAction},
		Note:     "Findings drive signed remediation actions. DefendSec does not run an unattended patch schedule; updates are operator-approved on purpose.",
	},
	{
		ID: MustParseID("cis-v8:8.2"), Family: "8",
		Title:    "Collect audit logs",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditChain, SignalAlertLifecycle},
		Note:     "DefendSec's own actions and findings are collected. It is not a log aggregator and does not collect host system logs.",
	},
	{
		ID: MustParseID("cis-v8:8.3"), Family: "8",
		Title:    "Ensure adequate audit log storage",
		Coverage: CoveragePartial,
		Signals:  []Signal{SignalAuditRetention, SignalBackup},
		Note:     "Retention is configurable, defaults to a year, and is reported by GET /v1/retention. Capacity planning is still the operator's.",
	},
	{
		ID: MustParseID("cis-v8:8.5"), Family: "8",
		Title:    "Collect detailed audit logs",
		Coverage: CoverageEvidenced,
		Signals:  []Signal{SignalAuditChain, SignalCommandAttributed, SignalCommandAck},
		Note:     "Each entry carries the source, the event, the timestamp, the actor and the outcome.",
	},
	{
		ID: MustParseID("cis-v8:10.1"), Family: "10",
		Title:    "Deploy and maintain anti-malware software",
		Coverage: CoverageNone,
		Note:     "DefendSec is not an anti-malware product and does not scan for malware signatures.",
	},
	{
		ID: MustParseID("cis-v8:14.1"), Family: "14",
		Title:    "Establish and maintain a security awareness program",
		Coverage: CoverageNone,
		Note:     "Not technical telemetry.",
	},
	{
		ID: MustParseID("cis-v8:17.1"), Family: "17",
		Title:    "Designate personnel to manage incident handling",
		Coverage: CoverageNone,
		Note:     "An organisational assignment, not a system state.",
	},
}

// catalog is the fully-resolved set, native entries plus everything derived
// through the crosswalks, built once at startup.
var catalog = func() map[ID]Control {
	out := make(map[ID]Control, len(native)*3)
	for _, c := range native {
		if _, dup := out[c.ID]; dup {
			panic(fmt.Sprintf("controls: duplicate catalog entry %s", c.ID))
		}
		for _, s := range c.Signals {
			if !KnownSignal(s) {
				panic(fmt.Sprintf("controls: %s maps unknown signal %q", c.ID, s))
			}
		}
		if c.Coverage != CoverageEvidenced && c.Note == "" {
			panic(fmt.Sprintf("controls: %s is %s and must say why", c.ID, c.Coverage))
		}
		if c.Coverage == CoverageNone && len(c.Signals) > 0 {
			panic(fmt.Sprintf("controls: %s claims signals but is marked not-evidenced", c.ID))
		}
		out[c.ID] = c
	}
	for _, d := range derive(out) {
		if _, dup := out[d.ID]; dup {
			panic(fmt.Sprintf("controls: crosswalk entry %s collides with a native one", d.ID))
		}
		out[d.ID] = d
	}
	return out
}()

// Lookup returns the catalog entry for an identifier.
func Lookup(id ID) (Control, bool) {
	c, ok := catalog[id]
	return c, ok
}

// Catalog returns every control, ordered by identifier.
func Catalog() []Control {
	out := make([]Control, 0, len(catalog))
	for _, c := range catalog {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ForFramework returns one framework's controls, ordered by identifier.
func ForFramework(f Framework) []Control {
	var out []Control
	for _, c := range catalog {
		if c.ID.Framework() == f {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ForSignal returns every control a signal contributes to. This is the
// direction records are tagged in: a finding knows what it is, and the mapping
// says which controls that fact speaks to.
func ForSignal(s Signal) []ID {
	var out []ID
	for id, c := range catalog {
		for _, sig := range c.Signals {
			if sig == s {
				out = append(out, id)
				break
			}
		}
	}
	SortIDs(out)
	return out
}

// ForSignals is ForSignal over a set, deduplicated.
func ForSignals(signals ...Signal) []ID {
	seen := map[ID]bool{}
	var out []ID
	for _, s := range signals {
		for _, id := range ForSignal(s) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	SortIDs(out)
	return out
}
