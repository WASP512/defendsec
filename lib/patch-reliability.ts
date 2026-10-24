// Whether a host's "pending updates" can be believed (slice 11).
//
// An expired repository key makes apt keep using the index it already has
// without failing, so "0 pending" from such a host means "none that apt can
// see". The agent reports what it read about each enabled repository and apid
// judges it (internal/repohealth); this file holds the wire types and the words
// the console uses so that no page shows a clean zero beside a failed check.
// It imports nothing from the app, so `node --test` can run it.

export type RepoSignature =
  | "good"
  | "expired_key"
  | "no_pubkey"
  | "bad_signature"
  | "revoked_key"
  | "unsigned"
  | "no_index"
  | "not_checked"
  | "unverified";

export type RepoEvidence = {
  id: string;
  label: string;
  uri?: string;
  suite?: string;
  source?: string;
  signature: RepoSignature;
  keyId?: string;
  detail?: string;
  signedBy?: string;
  releaseDate?: string;
  validUntil?: string;
  metadataTime?: string;
  keyExpires?: string;
};

export type RepoProblem = { repoId: string; code: string; severity: "high" | "medium"; title: string; detail: string };

export type Reliability = "reliable" | "unreliable" | "unassessed";

/** The server's verdict on a host's repository evidence. */
export type RepoAssessment = { reliability: Reliability; reasons: string[]; problems: RepoProblem[]; checked: number };

/** What the agent read about the host's repositories, with the server's verdict. */
export type RepoHealthReport = {
  manager: string;
  lastRefresh?: string;
  lastRefreshSource?: string;
  repos: RepoEvidence[];
  limits?: string[];
  assessment?: RepoAssessment;
  assessedAt?: string;
};

export type PatchReliability = {
  /** "n/a": a platform the question does not apply to (Windows, a sample host). */
  state: Reliability | "n/a";
  reasons: string[];
};

/** The reliability of a host's pending-updates list, from what apid stored with it. */
export function patchReliabilityOf(d: { platform: string; sample?: boolean; repoHealth?: RepoHealthReport | null }): PatchReliability {
  if (d.sample || d.platform !== "linux") return { state: "n/a", reasons: [] };
  const a = d.repoHealth?.assessment;
  if (!a) return { state: "unassessed", reasons: [] };
  return { state: a.reliability, reasons: a.reasons };
}

/** True when the list must not be read as "nothing to install". */
export function isUnreliable(r: PatchReliability): boolean {
  return r.state === "unreliable";
}

/**
 * One line for a count of pending updates: the number, and when the list cannot
 * be believed, that it cannot. "0 pending" is never printed for such a host.
 */
export function pendingCountLabel(count: number, r: PatchReliability): string {
  if (r.state === "unreliable") {
    return count === 0 ? "0 pending — unreliable, not zero" : `${count} pending — list may be incomplete`;
  }
  return count === 0 ? "No pending updates" : `${count} pending`;
}

/**
 * What the "No pending patches" policy says for a host whose repository check
 * failed: unknown, never pass, with the reason. Null when the list is not
 * unreliable and the policy judges the count as usual.
 */
export function unreliablePatchPolicy(count: number, r: PatchReliability): { status: "unknown"; detail: string } | null {
  if (!isUnreliable(r)) return null;
  return { status: "unknown", detail: `${pendingCountLabel(count, r)}: ${r.reasons[0] ?? "a repository check failed"}` };
}

/** The headline of the notice shown where pending updates appear. */
export function unreliableTitle(): string {
  return "Pending updates are unreliable (missing evidence)";
}

/** The paragraph under it: what that means, and the reasons. */
export function unreliableExplanation(): string {
  return (
    "A package repository on this host failed a check, so the package manager may be working from an index " +
    "that has stopped refreshing. It can show no updates without failing. Treat this list as what the " +
    "package manager can see, not as what is available."
  );
}

/** A note for a Linux host whose agent reports no repository evidence at all. */
export function unassessedNote(): string {
  return "This host's agent does not report repository health, so its pending updates have not been cross-checked.";
}

const CODE_LABEL: Record<string, string> = {
  key_expired: "signing key expired",
  key_missing: "signing key not trusted",
  key_revoked: "signing key revoked",
  signature_bad: "signature does not verify",
  unsigned: "no valid signature",
  no_index: "no index on the host",
  index_expired: "index expired",
  index_stale: "index stale",
};

/** "signing key expired" for a problem code. */
export function repoCodeLabel(code: string): string {
  return CODE_LABEL[code] ?? code.replaceAll("_", " ");
}

/** What fixes a repository problem, in a phrase for a list row. */
export function repoFixPhrase(code: string): string {
  switch (code) {
    case "key_expired":
    case "key_missing":
    case "key_revoked":
    case "signature_bad":
    case "unsigned":
    case "no_index":
      return "install the vendor's current signing key (signed-by keyring), then apt-get update";
    case "index_expired":
    case "index_stale":
      return "refresh the index and check the periodic refresh runs";
    default:
      return "see the fix text";
  }
}

/** The fleet summary's sentence about hosts whose pending updates cannot be trusted. */
export function unreliableHostsNote(n: number): string {
  if (n <= 0) return "";
  return `${n} ${n === 1 ? "host's" : "hosts'"} pending updates cannot be trusted (repository check failed).`;
}
