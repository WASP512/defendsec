import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import type { GoogleStatus, IdentityFinding, IdentityRun, IdentityStatus } from "@/lib/identity-model";

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

export function getGoogleStatus(): Promise<GoogleStatus | null> {
  return get<GoogleStatus>("/v1/identity/google/status");
}

/** Findings of one provider ("m365" or "google"), or of every provider when none is named. */
export async function getIdentityFindings(resolved = false, provider?: "m365" | "google"): Promise<IdentityFinding[] | null> {
  const q = new URLSearchParams();
  if (resolved) q.set("resolved", "1");
  if (provider) q.set("provider", provider);
  const r = await get<{ findings: IdentityFinding[] }>(`/v1/identity/findings${q.toString() ? `?${q}` : ""}`);
  return r ? r.findings : null;
}

/** The reads of one provider; Microsoft 365's when none is named. */
export async function getIdentityRuns(limit = 10, provider: "m365" | "google" = "m365"): Promise<IdentityRun[] | null> {
  const r = await get<{ runs: IdentityRun[] }>(`/v1/identity/runs?limit=${limit}&provider=${provider}`);
  return r ? r.runs : null;
}
