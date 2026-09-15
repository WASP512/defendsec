package controls

import (
	"fmt"
	"sort"
	"strings"
)

// Crosswalks let one set of hand-written mappings serve several frameworks.
//
// This is the observation Phase 1.7 rests on: CJIS Security Policy v6.0 is
// explicitly mapped to NIST SP 800-53 Rev 5, and 800-171 derives from it. So
// CJIS costs a table, not an architecture (§3.10). The derived entry records
// which hub controls it came from, so an assessor can check the reasoning
// instead of taking the mapping on faith.
//
// A derived control takes the *weakest* coverage of the hub controls it
// depends on. Taking the strongest would let one well-evidenced 800-53 control
// carry four others into a compliance view they do not deserve, which is the
// exact failure mode that makes compliance dashboards untrustworthy.

// crosswalk is one derived control: an identifier, what it asks for, and the
// 800-53 controls that answer it.
type crosswalk struct {
	id    string
	title string
	// family is the framework's own grouping — a requirement family for
	// 800-171, a policy area for CJIS.
	family string
	hub    []string
	// note, when set, is appended to the derived note. Use it where the
	// framework asks for something beyond what the hub controls cover.
	note string
	// noneReason, when set, marks the control as one DefendSec cannot
	// evidence at all, regardless of hub mappings (which must then be empty).
	noneReason string
}

// nist800171 — NIST SP 800-171 Rev 2. CMMC 2.0 Level 2 adopts these same 110
// requirements, so every entry here is emitted under both identifiers.
var nist800171 = []crosswalk{
	{id: "3.1.1", family: "Access Control", title: "Limit system access to authorised users", hub: []string{"nist-800-53:AC-2", "nist-800-53:AC-3", "nist-800-53:IA-2"}},
	{id: "3.1.2", family: "Access Control", title: "Limit system access to the transactions and functions authorised users may execute", hub: []string{"nist-800-53:AC-3", "nist-800-53:CM-5"}},
	{id: "3.1.5", family: "Access Control", title: "Employ the principle of least privilege", hub: []string{"nist-800-53:AC-6(9)", "nist-800-53:CM-5"}},
	{id: "3.1.7", family: "Access Control", title: "Log the execution of privileged functions", hub: []string{"nist-800-53:AC-6(9)", "nist-800-53:AU-3"}},
	{id: "3.1.8", family: "Access Control", title: "Limit unsuccessful logon attempts", hub: []string{"nist-800-53:AC-7"}},
	{id: "3.1.11", family: "Access Control", title: "Terminate a user session after a defined condition", hub: []string{"nist-800-53:AC-12"}},
	{id: "3.2.1", family: "Awareness and Training", title: "Ensure personnel are aware of the security risks of their activities", noneReason: "Training records are not technical telemetry; the agency holds them."},
	{id: "3.3.1", family: "Audit and Accountability", title: "Create and retain audit records sufficient to investigate unlawful or unauthorised activity", hub: []string{"nist-800-53:AU-2", "nist-800-53:AU-3", "nist-800-53:AU-11"}},
	{id: "3.3.2", family: "Audit and Accountability", title: "Ensure the actions of individual users can be uniquely traced to those users", hub: []string{"nist-800-53:AU-10", "nist-800-53:IA-2"}},
	{id: "3.3.4", family: "Audit and Accountability", title: "Alert in the event of an audit logging process failure", hub: []string{"nist-800-53:AU-9"}, note: "Chain verification detects a break, but DefendSec does not currently raise an alert when appending itself fails."},
	{id: "3.3.5", family: "Audit and Accountability", title: "Correlate audit record review and reporting for investigation", hub: []string{"nist-800-53:AU-6"}},
	{id: "3.3.8", family: "Audit and Accountability", title: "Protect audit information and logging tools from unauthorised access, modification and deletion", hub: []string{"nist-800-53:AU-9", "nist-800-53:AU-9(3)"}},
	{id: "3.3.9", family: "Audit and Accountability", title: "Limit management of audit logging functionality to a privileged subset of users", hub: []string{"nist-800-53:AC-6(9)", "nist-800-53:CM-5"}},
	{id: "3.4.1", family: "Configuration Management", title: "Establish and maintain baseline configurations and inventories", hub: []string{"nist-800-53:CM-2", "nist-800-53:CM-8"}},
	{id: "3.4.2", family: "Configuration Management", title: "Establish and enforce security configuration settings", hub: []string{"nist-800-53:CM-6"}},
	{id: "3.4.3", family: "Configuration Management", title: "Track, review, approve and log changes to systems", hub: []string{"nist-800-53:CM-3", "nist-800-53:AU-3"}},
	{id: "3.4.5", family: "Configuration Management", title: "Define, document, approve and enforce access restrictions associated with changes", hub: []string{"nist-800-53:CM-5"}},
	{id: "3.5.1", family: "Identification and Authentication", title: "Identify system users and devices", hub: []string{"nist-800-53:IA-2", "nist-800-53:IA-3"}},
	{id: "3.5.2", family: "Identification and Authentication", title: "Authenticate the identities of users and devices", hub: []string{"nist-800-53:IA-2", "nist-800-53:IA-3", "nist-800-53:SC-8"}},
	{id: "3.5.3", family: "Identification and Authentication", title: "Use multifactor authentication for privileged accounts", hub: []string{"nist-800-53:IA-2(1)"}},
	{id: "3.5.10", family: "Identification and Authentication", title: "Store and transmit only cryptographically-protected passwords", hub: []string{"nist-800-53:IA-5", "nist-800-53:SC-13"}},
	{id: "3.6.1", family: "Incident Response", title: "Establish an operational incident-handling capability", hub: []string{"nist-800-53:IR-4", "nist-800-53:IR-5"}},
	{id: "3.6.2", family: "Incident Response", title: "Track, document and report incidents", hub: []string{"nist-800-53:IR-5", "nist-800-53:AU-10"}},
	{id: "3.8.3", family: "Media Protection", title: "Sanitise or destroy media before disposal or reuse", noneReason: "DefendSec does not perform or witness media sanitisation."},
	{id: "3.9.1", family: "Personnel Security", title: "Screen individuals prior to authorising access", noneReason: "Personnel records are held by the agency."},
	{id: "3.10.1", family: "Physical Protection", title: "Limit physical access to systems and equipment", noneReason: "Physical controls are outside anything an agent can observe."},
	{id: "3.11.2", family: "Risk Assessment", title: "Scan for vulnerabilities periodically and when new vulnerabilities are identified", hub: []string{"nist-800-53:RA-5"}},
	{id: "3.11.3", family: "Risk Assessment", title: "Remediate vulnerabilities in accordance with risk assessments", hub: []string{"nist-800-53:SI-2"}},
	{id: "3.13.8", family: "System and Communications Protection", title: "Implement cryptographic mechanisms to prevent unauthorised disclosure during transmission", hub: []string{"nist-800-53:SC-8", "nist-800-53:SC-13"}},
	{id: "3.13.11", family: "System and Communications Protection", title: "Employ FIPS-validated cryptography to protect the confidentiality of CUI", hub: []string{"nist-800-53:SC-13"}, note: "DefendSec can be constrained to approved algorithms and reports the live posture. Holding a validation certificate for the module is a separate matter and is not DefendSec's to claim."},
	{id: "3.13.16", family: "System and Communications Protection", title: "Protect the confidentiality of CUI at rest", hub: []string{"nist-800-53:SC-28"}, note: "Host disk encryption state is collected and checked per host. Whether CUI itself is encrypted wherever it lives is a larger question DefendSec does not answer."},
	{id: "3.14.1", family: "System and Information Integrity", title: "Identify, report and correct system flaws in a timely manner", hub: []string{"nist-800-53:SI-2", "nist-800-53:RA-5"}},
	{id: "3.14.2", family: "System and Information Integrity", title: "Provide protection from malicious code", noneReason: "DefendSec is not an anti-malware product and does not scan for malware signatures."},
	{id: "3.14.6", family: "System and Information Integrity", title: "Monitor systems, including inbound and outbound communications traffic", hub: []string{"nist-800-53:SI-4"}, note: "Host-level monitoring only; DefendSec does not inspect network traffic."},
	{id: "3.14.7", family: "System and Information Integrity", title: "Identify unauthorised use of systems", hub: []string{"nist-800-53:SI-4", "nist-800-53:SI-7", "nist-800-53:AU-6"}},
}

// cjisv6 — CJIS Security Policy v6.0, by policy area.
//
// The honest coverage breakdown §3.10 requires is expressed here rather than
// written in a document: three areas DefendSec substantially evidences, three
// it partially evidences, and seven it cannot touch at all — each of those
// last carrying the reason, including Mobile Devices, which is MDM and which
// §2 declines deliberately rather than by omission.
var cjisv6 = []crosswalk{
	{id: "1", family: "Information Exchange Agreements", title: "Policy Area 1 — agreements governing exchange of criminal justice information", noneReason: "Agreements are legal documents between agencies. DefendSec holds none of them."},
	{id: "2", family: "Security Awareness Training", title: "Policy Area 2 — role-based security awareness training", noneReason: "Training records are not technical telemetry; the agency holds them."},
	{id: "3", family: "Incident Response", title: "Policy Area 3 — incident detection, handling, reporting and tracking", hub: []string{"nist-800-53:IR-4", "nist-800-53:IR-5", "nist-800-53:SI-4"}, note: "Detection, containment and a tamper-evident record of the response. The written incident response plan, the reporting obligations to the CJIS Systems Agency and the exercises remain the agency's."},
	{id: "4", family: "Auditing and Accountability", title: "Policy Area 4 — events logged, retained, protected from modification and reviewable", hub: []string{"nist-800-53:AU-2", "nist-800-53:AU-3", "nist-800-53:AU-6", "nist-800-53:AU-9", "nist-800-53:AU-9(3)", "nist-800-53:AU-10", "nist-800-53:AU-11", "nist-800-53:AC-6(9)"}, note: "This is the area DefendSec answers best: a hash-chained ledger of individually attributed, signed actions, verifiable offline. Note that the requirement to review the records on a defined frequency is a process DefendSec presents but cannot perform."},
	{id: "5", family: "Access Control", title: "Policy Area 5 — least privilege, account management and session control", hub: []string{"nist-800-53:AC-2", "nist-800-53:AC-3", "nist-800-53:AC-6(9)", "nist-800-53:AC-7", "nist-800-53:AC-12"}, note: "Covers access to DefendSec itself. Access control on the systems that hold criminal justice information is a separate and larger question."},
	{id: "6", family: "Identification and Authentication", title: "Policy Area 6 — unique identification and advanced authentication", hub: []string{"nist-800-53:IA-2", "nist-800-53:IA-2(1)", "nist-800-53:IA-3", "nist-800-53:IA-5"}, note: "Named accounts with TOTP satisfy advanced authentication for DefendSec's own console; whether the agency's other systems do is out of scope here."},
	{id: "7", family: "Configuration Management", title: "Policy Area 7 — baseline configuration, change control and component inventory", hub: []string{"nist-800-53:CM-2", "nist-800-53:CM-3", "nist-800-53:CM-5", "nist-800-53:CM-6", "nist-800-53:CM-8", "nist-800-53:SI-7"}},
	{id: "8", family: "Media Protection", title: "Policy Area 8 — media storage, transport and sanitisation", noneReason: "DefendSec does not handle, track or sanitise media."},
	{id: "9", family: "Physical Protection", title: "Policy Area 9 — physically secure locations and controlled areas", noneReason: "Physical controls are outside anything an agent can observe."},
	{id: "10", family: "Systems and Communications Protection and Information Integrity", title: "Policy Area 10 — boundary protection, encryption in transit, patching and integrity", hub: []string{"nist-800-53:SC-8", "nist-800-53:SC-13", "nist-800-53:SI-2", "nist-800-53:SI-4", "nist-800-53:SI-7", "nist-800-53:RA-5"}, note: "Encryption in transit, flaw remediation and integrity monitoring are evidenced. Boundary protection — firewalls, network segmentation — is not, and encryption at rest is delegated to the platform."},
	{id: "11", family: "Formal Audits", title: "Policy Area 11 — cooperation with CJIS audits and the evidence they require", hub: []string{"nist-800-53:AU-6", "nist-800-53:AU-9(3)", "nist-800-53:AU-10"}, note: "DefendSec produces the signed, offline-verifiable evidence package an audit asks for. Scheduling, responding to findings and the audit itself are the agency's."},
	{id: "12", family: "Personnel Security", title: "Policy Area 12 — personnel screening and separation", noneReason: "Personnel records are held by the agency."},
	{id: "13", family: "Mobile Devices", title: "Policy Area 13 — management of mobile and wireless devices", noneReason: "This is mobile device management. DefendSec declines MDM deliberately — no wipe, lock, enrollment profiles or configuration policies — so it cannot and should not evidence this area."},
}

// derive expands the crosswalks against the native catalog.
func derive(hub map[ID]Control) []Control {
	var out []Control
	emit := func(f Framework, cw crosswalk) {
		id := MustParseID(string(f) + ":" + cw.id)
		c := Control{ID: id, Title: cw.title, Family: cw.family}

		if cw.noneReason != "" {
			if len(cw.hub) > 0 {
				panic(fmt.Sprintf("controls: %s is marked not-evidenced but names hub controls", id))
			}
			c.Coverage = CoverageNone
			c.Note = cw.noneReason
			out = append(out, c)
			return
		}
		if len(cw.hub) == 0 {
			panic(fmt.Sprintf("controls: %s maps to nothing and gives no reason", id))
		}

		// Weakest coverage wins, and the signals are the union — the control
		// is only as well evidenced as its worst-covered dependency, but an
		// assessor should still see everything that speaks to it.
		weakest := CoverageEvidenced
		seen := map[Signal]bool{}
		var notes []string
		for _, raw := range cw.hub {
			hid := MustParseID(raw)
			h, ok := hub[hid]
			if !ok {
				panic(fmt.Sprintf("controls: %s crosswalks to %s, which is not in the catalog", id, hid))
			}
			c.DerivedFrom = append(c.DerivedFrom, hid)
			if h.Coverage.Rank() < weakest.Rank() {
				weakest = h.Coverage
			}
			for _, s := range h.Signals {
				if !seen[s] {
					seen[s] = true
					c.Signals = append(c.Signals, s)
				}
			}
			if h.Coverage != CoverageEvidenced && h.Note != "" {
				notes = append(notes, string(hid)+": "+h.Note)
			}
		}
		c.Coverage = weakest
		SortIDs(c.DerivedFrom)
		sort.Slice(c.Signals, func(i, j int) bool { return c.Signals[i] < c.Signals[j] })

		// Weakest-wins is conservative, and for a broad grouping like a CJIS
		// policy area it can read as damning: one unevidenced dependency out
		// of eight drags the whole area down. State the proportion so an
		// assessor sees the substance rather than only the worst case.
		if len(cw.hub) > 1 {
			full := 0
			for _, raw := range cw.hub {
				if hub[MustParseID(raw)].Coverage == CoverageEvidenced {
					full++
				}
			}
			notes = append([]string{fmt.Sprintf(
				"%d of %d mapped NIST SP 800-53 controls are fully evidenced; this entry takes the weakest of them.",
				full, len(cw.hub))}, notes...)
		}
		if cw.note != "" {
			notes = append([]string{cw.note}, notes...)
		}
		c.Note = strings.Join(notes, " ")
		if c.Coverage != CoverageEvidenced && c.Note == "" {
			panic(fmt.Sprintf("controls: derived %s is %s with nothing to say why", id, c.Coverage))
		}
		out = append(out, c)
	}

	for _, cw := range nist800171 {
		emit(NIST800171, cw)
		// CMMC 2.0 Level 2 is 800-171 by reference, so the same requirement
		// is emitted under both. Listing it twice is not duplication of
		// meaning: an assessor works from one identifier or the other, and a
		// view that only offers the other one is useless to them.
		emit(CMMCL2, cw)
	}
	for _, cw := range cjisv6 {
		emit(CJISv6, cw)
	}
	return out
}
