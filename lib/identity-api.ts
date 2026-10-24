import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import type { IdentityFinding, IdentityRun, IdentityStatus } from "@/lib/identity-model";

/**
 * The identity posture collector lives in apid; the console reads it there. A read
 * returns null when the control plane cannot be reached (or is older than the
 * identity API): callers say "unavailable", never an empty list, because an empty
 * list of findings reads as "the accounts are in good order", and a failed read says
 * nothing about them. Writes go through forwardToApid with the caller's own session.
 */
async function get<T>(path: string): Promise<T | null> {
  try {
    const token = await getAdminToken();
    const response = await fetch(new URL(path, APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

export function getIdentityStatus(): Promise<IdentityStatus | null> {
  return get<IdentityStatus>("/v1/identity/status");
}

export async function getIdentityFindings(resolved = false): Promise<IdentityFinding[] | null> {
  const r = await get<{ findings: IdentityFinding[] }>(`/v1/identity/findings${resolved ? "?resolved=1" : ""}`);
  return r ? r.findings : null;
}

export async function getIdentityRuns(limit = 10): Promise<IdentityRun[] | null> {
  const r = await get<{ runs: IdentityRun[] }>(`/v1/identity/runs?limit=${limit}`);
  return r ? r.runs : null;
}
