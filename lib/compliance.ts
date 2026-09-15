import { cookies } from "next/headers";

import { ADMIN_COOKIE } from "./auth-tokens.ts";
import { APID_ADMIN_URL } from "./commands.ts";

// Client for the audit layer (roadmap 1.9).
//
// As with identity, the console does not decide anything here. It forwards the
// operator's own session token and asks defendsec-apid, which owns the control
// mapping and the assessment rules. Recomputing any of it in the console would
// create a second answer to the same question, and the two would drift.

export type Coverage = "evidenced" | "partial" | "not-evidenced";

export type ControlStatusValue =
  | "satisfied"
  | "deficient"
  | "excepted"
  | "no-evidence"
  | "not-evidenced";

export type CatalogControl = {
  id: string;
  title: string;
  family?: string;
  coverage: Coverage;
  signals?: string[];
  note?: string;
  derivedFrom?: string[];
};

export type FrameworkSummary = {
  id: string;
  title: string;
  evidenced: number;
  partial: number;
  notEvidenced: number;
  total: number;
};

export type ControlException = {
  id: string;
  controlId: string;
  periodId?: string;
  reason: string;
  remediation?: string;
  owner?: string;
  openedAt: string;
  openedBy?: string;
  expiresAt: string;
  closedAt?: string;
};

export type ControlStatus = {
  control: CatalogControl;
  status: ControlStatusValue;
  evidence: {
    alerts: number;
    openAlerts: number;
    openAtEnd: number;
    commands: number;
    auditEntries: number;
  };
  qualified: boolean;
  exceptions?: ControlException[];
  statement: string;
};

export type AuditPeriod = {
  id: string;
  name: string;
  framework: string;
  startsAt: string;
  endsAt: string;
  notes?: string;
  createdAt: string;
  createdBy?: string;
  closedAt?: string;
  closedBy?: string;
};

export type Assessment = {
  framework: string;
  title: string;
  period: AuditPeriod;
  controls: ControlStatus[];
  counts: Partial<Record<ControlStatusValue, number>>;
  generatedAt: string;
  caveats: string[];
};

export class ComplianceUnavailableError extends Error {}

const REQUEST_TIMEOUT_MS = 15000;

async function apid(path: string): Promise<Response> {
  const jar = await cookies();
  const token = jar.get(ADMIN_COOKIE)?.value ?? "";
  const headers = new Headers({ "content-type": "application/json" });
  if (token) headers.set("authorization", `Bearer ${token}`);
  try {
    return await fetch(`${APID_ADMIN_URL}${path}`, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (cause) {
    throw new ComplianceUnavailableError(
      "Control plane is not reachable. Start defendsec-apid.",
      { cause },
    );
  }
}

export async function loadFrameworks(): Promise<FrameworkSummary[]> {
  const res = await apid("/v1/controls");
  if (!res.ok) {
    throw new ComplianceUnavailableError(
      `Control plane returned ${res.status}.`,
    );
  }
  const body = (await res.json()) as { frameworks?: FrameworkSummary[] };
  return body.frameworks ?? [];
}

export async function loadAssessment(
  framework: string,
  periodId?: string,
): Promise<Assessment> {
  const params = new URLSearchParams({ framework });
  if (periodId) params.set("periodId", periodId);
  const res = await apid(`/v1/audit/assessment?${params.toString()}`);
  if (!res.ok) {
    let detail = `Control plane returned ${res.status}.`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) detail = body.error;
    } catch {
      // non-JSON error body
    }
    throw new ComplianceUnavailableError(detail);
  }
  return (await res.json()) as Assessment;
}

export async function loadAuditPeriods(): Promise<AuditPeriod[]> {
  const res = await apid("/v1/audit/periods");
  if (!res.ok) {
    throw new ComplianceUnavailableError(
      `Control plane returned ${res.status}.`,
    );
  }
  const body = (await res.json()) as { periods?: AuditPeriod[] };
  return body.periods ?? [];
}

// Worst first. Someone who reads only the top of the page should have seen the
// things that need attention, not a screen of passes.
export const STATUS_ORDER: ControlStatusValue[] = [
  "deficient",
  "excepted",
  "no-evidence",
  "not-evidenced",
  "satisfied",
];

export const STATUS_LABEL: Record<ControlStatusValue, string> = {
  deficient: "Deficient",
  excepted: "Accepted deficiency",
  "no-evidence": "No evidence recorded",
  "not-evidenced": "Outside DefendSec",
  satisfied: "Satisfied",
};

export const STATUS_HINT: Record<ControlStatusValue, string> = {
  deficient: "Findings were still open when the window closed.",
  excepted:
    "Still open, but a documented, time-limited exception covers it. This is an accepted gap, not a pass.",
  "no-evidence":
    "DefendSec can evidence this, and recorded nothing. Usually that means the check never ran.",
  "not-evidenced":
    "DefendSec cannot evidence this at all. It has to be covered another way.",
  satisfied: "Evidence across the window, nothing outstanding at the close.",
};
