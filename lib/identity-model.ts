// Identity posture (slice 12: Microsoft 365; slice 13: Google Workspace) as
// the control plane serves it (GET /v1/identity/*): the wire types and the pure
// helpers the Identity page, the Fleet card and the Fix this week rows share. It
// imports nothing from the app, so `node --test` can run it.

import type { ExposureGroup, IdentitySummary } from "./exposure-model.ts";

/** The check groups, in the order the page lists them. */
export const CHECK_ORDER = ["mfa", "legacy-auth", "admin-roles", "inbox-rules"] as const;

export const CHECK_LABELS: Record<string, string> = {
  mfa: "MFA registration",
  "legacy-auth": "Legacy authentication",
  "admin-roles": "Administrator roles",
  "inbox-rules": "Inbox rules",
};

/** The check groups of a Google Workspace read: there is no legacy-auth group. */
export const CHECK_ORDER_GOOGLE = ["mfa", "admin-roles", "inbox-rules"] as const;

export const CHECK_LABELS_GOOGLE: Record<string, string> = {
  mfa: "2-Step Verification",
  "admin-roles": "Super administrators",
  "inbox-rules": "Gmail forwarding and filters",
};

/** A check group's name in the words of its provider (Microsoft 365's unless it is Google's). */
export function checkLabel(check: string, provider?: string): string {
  const labels = provider === "google" ? CHECK_LABELS_GOOGLE : CHECK_LABELS;
  return labels[check] ?? CHECK_LABELS[check] ?? check;
}

export type IdentitySettings = {
  configured: boolean;
  tenantId: string;
  clientId: string;
  cloud: "global" | "usgov" | "china";
  globalAdminMax: number;
  trustedDomains: string[];
  financeTerms: string[];
  resolveFolders: boolean;
  updatedBy?: string;
  updatedAt?: string;
};

export type GoogleSettings = {
  configured: boolean;
  adminEmail: string;
  /** "settings.basic" (default) is gmail.settings.basic, which cannot read mail; "readonly" is gmail.readonly. */
  gmailScope: "readonly" | "settings.basic";
  superAdminMax: number;
  trustedDomains: string[];
  financeTerms: string[];
  updatedBy?: string;
  updatedAt?: string;
};

export type GoogleCredentials = {
  configured: boolean;
  clientEmail?: string;
  /** The numeric ID entered in the Admin console's domain-wide delegation list. */
  clientId?: string;
  keyId?: string;
  projectId?: string;
  problem?: string;
  warnings: string[];
};

export type IdentityFinding = {
  id: number;
  /** "identity:<12 digits>", the key of the finding's row in the exposure list. */
  key: string;
  provider: string;
  check: string;
  findingId: string;
  subject: string;
  subjectLabel: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  detail: string;
  fix: string;
  evidence: Record<string, unknown>;
  controls: string[];
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  unconfirmed: boolean;
};

export type IdentityCheckState = {
  check: string;
  label: string;
  assessed: boolean;
  reason: string;
  observed: Record<string, unknown>;
  unassessedPrefixes?: string[];
};

export type IdentityRun = {
  id: number;
  provider: string;
  tenant: string;
  triggeredBy: string;
  startedAt: string;
  finishedAt: string;
  status: "ok" | "partial" | "not_assessed";
  reason: string;
  requests: number;
  counts: {
    users: number;
    registrations: number;
    mailboxesEligible: number;
    mailboxesRead: number;
    noMailbox: number;
    unreadable: number;
    skipped: number;
    rules: number;
    globalAdmins: number;
  };
  checks: IdentityCheckState[];
  notAssessed: { what: string; why: string }[];
  findingsOpen: number;
  opened: number;
  resolved: number;
};

export type IdentityPermission = { name: string; required: boolean; why: string };

export type IdentityCredentials = {
  configured: boolean;
  method?: "certificate" | "secret";
  thumbprint?: string;
  thumbprintSha1?: string;
  notAfter?: string;
  problem?: string;
  warnings: string[];
};

export type IdentityStatus = {
  provider: string;
  settings: IdentitySettings;
  credentials: IdentityCredentials;
  summary: IdentitySummary;
  latestRun: IdentityRun | null;
  running: boolean;
  intervalHours: number;
  scheduled: boolean;
  notAssessed: { what: string; why: string }[];
  permissions: IdentityPermission[];
  checkLabels: Record<string, string>;
  generatedAt: string;
  readOnlyNote: string;
};

/** GET /v1/identity/google/status. */
export type GoogleStatus = {
  provider: string;
  settings: GoogleSettings;
  credentials: GoogleCredentials;
  summary: IdentitySummary;
  latestRun: IdentityRun | null;
  running: boolean;
  intervalHours: number;
  scheduled: boolean;
  notAssessed: { what: string; why: string }[];
  /** The OAuth scopes the domain-wide delegation must carry. */
  permissions: IdentityPermission[];
  checkLabels: Record<string, string>;
  checkOrder: string[];
  generatedAt: string;
  readOnlyNote: string;
};

/** What the drawer of an identity row is given. */
export type ExposureIdentityResponse = {
  advisoryId: string;
  source: "identity";
  status: "open" | "resolved";
  detail: {
    key: string;
    finding: IdentityFinding;
    /** Every span the finding was open, oldest first. */
    intervals: { openedAt: string; closedAt?: string | null }[];
    latest: IdentityRun | null;
    /** The latest run's state of the finding's check group. */
    checkState: IdentityCheckState | null;
  };
};

/** The drawer's answer is a vulnerability's, a surface finding's or an identity finding's. */
export function isIdentityResponse(r: { source?: string } | null | undefined): r is ExposureIdentityResponse {
  return !!r && r.source === "identity";
}

/** "casey@example.com · Intuit stuff": the account or rule, with the check it came from. */
export function identityWhere(g: Pick<ExposureGroup, "identity">): string {
  const i = g.identity;
  if (!i) return "";
  return [providerLabel(i.provider), checkLabel(i.check, i.provider), i.subject].join(" · ");
}

export function providerLabel(provider: string): string {
  return provider === "m365" ? "Microsoft 365" : provider === "google" ? "Google Workspace" : provider;
}

/** Said under a row whose check could not run on the latest read. Empty when it did. */
export function identityUnconfirmedNote(g: Pick<ExposureGroup, "identity">): string {
  const i = g.identity;
  if (!i || !i.unconfirmed) return "";
  return `The latest ${checkLabel(i.check, i.provider)} check could not cover this: shown from the last confirmation on ${i.lastSeen.slice(0, 10)}.`;
}

/** How a read went, in the words the page uses. */
export function runResultLabel(status: string): string {
  return status === "ok" ? "read" : status === "partial" ? "partly read" : "not assessed";
}

/** Whether a tenant ID or application ID could be right: the page checks before it asks. */
export function looksLikeGuid(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s.trim());
}

/** Whether an administrator address could be right: one @ and a dotted domain. */
export function looksLikeEmail(s: string): boolean {
  return /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/.test(s.trim()) && !/\.\./.test(s) && !/@\./.test(s) && !/\.$/.test(s.trim());
}

export function looksLikeTenant(s: string): boolean {
  const t = s.trim();
  return looksLikeGuid(t) || /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(t);
}

/** One term per line or comma, trimmed, lower-cased, without blanks or repeats. */
export function parseList(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/[\n,]/)) {
    const v = raw.trim().toLowerCase();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/** The days left on a certificate, or null when its end date is not known. */
export function certDaysLeft(notAfter: string | undefined, now: number = Date.now()): number | null {
  if (!notAfter) return null;
  const ms = Date.parse(notAfter) - now;
  return Number.isFinite(ms) ? Math.floor(ms / 86_400_000) : null;
}
