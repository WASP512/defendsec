package controls

// Tagging helpers used at the point a record is created.
//
// Records store a signal plus the resolved control identifiers. Storing both
// is deliberate redundancy with a reason: the signal is the durable fact and
// survives a framework revision, while the resolved identifiers let an
// assessor's query hit an index instead of re-running the mapping over a
// year of history. When the mapping changes, the stored identifiers are what
// was true when the record was written — which is the honest answer for a
// period that has already closed.

// Tag resolves a signal and any extra control identifiers into the sorted,
// deduplicated list stored on a record.
//
// Extras come from content that names its own controls — an SCA check tagged
// in its pack, for instance. Unparseable extras are dropped rather than
// failing the write: a mis-tagged pack should not stop a real finding from
// being recorded, and the pack loader rejects them at load time where the
// error is actionable.
func Tag(signal Signal, extra ...string) []string {
	ids := ForSignal(signal)
	seen := make(map[ID]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	for _, raw := range extra {
		id, err := ParseID(raw)
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	SortIDs(ids)
	return Strings(ids)
}

// SignalForAlertKind maps DefendSec's alert kinds onto signals, so existing
// generators are tagged without each one having to know about frameworks.
//
// An unrecognised kind returns false rather than a guess. A wrong tag is
// worse than an absent one: it puts a finding behind a control it does not
// speak to, and an assessor has no way to tell.
func SignalForAlertKind(kind string) (Signal, bool) {
	switch kind {
	case "fim":
		return SignalFIM, true
	case "sca":
		return SignalSCA, true
	case "vuln":
		return SignalVulnAssessment, true
	default:
		return "", false
	}
}

// auditActionSignals maps ledger actions onto signals.
//
// This mapping is deliberately deterministic and total over the actions
// DefendSec writes, because of where the tag is stored. The audit chain hashes
// the entry's actor, action, device and detail — not the control tag. A tag
// that could not be recomputed from hashed fields would be an unprotected
// claim sitting next to protected ones, which is exactly the confusion the
// chain exists to remove. Because the tag is a pure function of the action,
// an altered tag is detectable: recompute it and compare.
var auditActionSignals = map[string][]Signal{
	"login":                    {SignalIdentityAccounts, SignalIdentitySession},
	"logout":                   {SignalIdentitySession},
	"login_failed":             {SignalIdentityLockout, SignalIdentityAccounts},
	"login_locked":             {SignalIdentityLockout},
	"user_created":             {SignalIdentityAccounts, SignalIdentityRoles},
	"user_password_changed":    {SignalIdentityAccounts},
	"totp_enrolled":            {SignalIdentityMFA},
	"command_issue":            {SignalCommandSigned, SignalCommandAttributed},
	"command_ack":              {SignalCommandAck},
	"ack_signature_invalid":    {SignalCommandAck},
	"ack_result_hash_mismatch": {SignalCommandAck},
	"device_enrolled":          {SignalTransportMTLS, SignalInventoryHardware},
	"cert_revoke":              {SignalCertRevocation},
	"enroll_secret_rotate":     {SignalTransportMTLS},
	"alert_status":             {SignalAlertLifecycle},
	"baseline_accept":          {SignalFIM},
	"advisories_import":        {SignalVulnAssessment},
	"agent_release_publish":    {SignalManagedUpdate},
	"saved_query_create":       {SignalAuditReview},
}

// SignalsForAuditAction returns the signals an audit action evidences.
//
// An unmapped action returns nothing rather than a guess, and that is not a
// silent failure: an untagged entry is still in the chain and still visible in
// the ledger. It simply does not claim to evidence a control it was never
// mapped to.
func SignalsForAuditAction(action string) []Signal {
	return auditActionSignals[action]
}

// TagAuditAction resolves an action straight to stored control identifiers.
func TagAuditAction(action string) []string {
	sigs := SignalsForAuditAction(action)
	if len(sigs) == 0 {
		return nil
	}
	return Strings(ForSignals(sigs...))
}

// AuditActionSignalName is the single signal recorded on a ledger entry. Where
// an action evidences several, the first is the primary one; the full set is
// always recoverable through SignalsForAuditAction.
func AuditActionSignalName(action string) string {
	sigs := SignalsForAuditAction(action)
	if len(sigs) == 0 {
		return ""
	}
	return string(sigs[0])
}
