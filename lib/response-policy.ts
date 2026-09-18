import { cookies } from "next/headers";

import { ADMIN_COOKIE } from "./auth-tokens.ts";
import { APID_ADMIN_URL } from "./commands.ts";
import { partitionApprovals, type PendingCommand } from "./proposals.ts";

// Client for policy-governed response (roadmap 2.1-2.6).
//
// As with identity and compliance, the console decides nothing. It forwards
// the operator's session token and asks defendsec-apid, which owns the policy
// engine. Evaluating rules here as well would create a second answer to the
// same question, and the two would drift — with the console's answer being
// the one that is wrong, since it is not the one that gates the signer.

export type PolicyEffect = "permit" | "deny" | "require-approval";

export type PolicyRule = {
  id: string;
  effect: PolicyEffect;
  commands: string[];
  roles?: string[];
  actors?: string[];
  host_classes?: string[];
  exclude_host_classes?: string[];
  require_approvals?: number;
  reason?: string;
};

export type PolicyLimit = {
  id: string;
  commands: string[];
  scope: "fleet" | "host";
  max: number;
  per: string;
};

export type PolicyStatus = {
  loaded: boolean;
  name?: string;
  hash?: string;
  source?: string;
  timezone?: string;
  rules?: PolicyRule[];
  limits?: PolicyLimit[];
  detail: string;
};

export type PolicyDecision = {
  id: string;
  at: string;
  actor: string;
  role?: string;
  commandType: string;
  deviceId?: string;
  hostname?: string;
  hostClasses?: string[];
  effect: PolicyEffect;
  ruleId?: string;
  reason: string;
  policyName?: string;
  limitExceeded?: string;
  breakGlassId?: string;
  commandId?: string;
};

// PendingCommand and the proposal predicate live in proposals.ts, which
// imports nothing server-only. They are re-exported here so existing callers
// are unaffected — and so a client component can reach them without dragging
// next/headers into the browser bundle, which is a constraint only `next
// build` enforces.
export type { PendingCommand };
export { isProposal as fromAgent } from "./proposals.ts";

export type BreakGlass = {
  id: string;
  justification: string;
  openedBy: string;
  openedAt: string;
  expiresAt: string;
  closedAt?: string;
};

export type BreakGlassStatus = {
  active: BreakGlass | null;
  history: BreakGlass[];
};

export class PolicyUnavailableError extends Error {}

const REQUEST_TIMEOUT_MS = 10000;

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
    throw new PolicyUnavailableError(
      "Control plane is not reachable. Start defendsec-apid.",
      { cause },
    );
  }
}

async function get<T>(path: string, fallback: T): Promise<T> {
  const res = await apid(path);
  if (!res.ok) {
    // A policy view that silently shows nothing would read as "no rules",
    // which is the opposite of what an unreachable control plane means.
    throw new PolicyUnavailableError(`Control plane returned ${res.status}.`);
  }
  const body = (await res.json()) as T;
  return body ?? fallback;
}

export async function loadPolicyStatus(): Promise<PolicyStatus> {
  return get<PolicyStatus>("/v1/policy", {
    loaded: false,
    detail: "No policy information available.",
  });
}

export async function loadPolicyDecisions(
  effect?: string,
): Promise<PolicyDecision[]> {
  const query = effect ? `?effect=${encodeURIComponent(effect)}` : "";
  const body = await get<{ decisions?: PolicyDecision[] }>(
    `/v1/policy/decisions${query}`,
    {},
  );
  return body.decisions ?? [];
}

export async function loadPendingApprovals(): Promise<PendingCommand[]> {
  const body = await get<{ pending?: PendingCommand[] }>(
    "/v1/policy/approvals",
    {},
  );
  return body.pending ?? [];
}

// loadProposals returns only the AI-proposed requests awaiting review.
export async function loadProposals(): Promise<PendingCommand[]> {
  return partitionApprovals(await loadPendingApprovals()).proposals;
}

// loadHumanApprovals returns only the human requests awaiting a second
// approver, so the generic approvals list never silently includes a proposal
// whose case is not being shown.
export async function loadHumanApprovals(): Promise<PendingCommand[]> {
  return partitionApprovals(await loadPendingApprovals()).human;
}

export async function loadBreakGlass(): Promise<BreakGlassStatus> {
  return get<BreakGlassStatus>("/v1/policy/break-glass", {
    active: null,
    history: [],
  });
}
