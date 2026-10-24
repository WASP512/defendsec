import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import type { AutotaskRun, AutotaskStatus, AutotaskTicket } from "@/lib/autotask-model";

/**
 * The Autotask ticketing state lives in apid; the console reads it there. A read
 * returns null when the control plane cannot be reached (or is older than the
 * Autotask API): callers say "unavailable", never an empty list, because an empty
 * list of tickets reads as "nothing was opened" and a failed read says nothing.
 * Writes go through forwardToApid with the caller's own session.
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

export function getAutotaskStatus(): Promise<AutotaskStatus | null> {
  return get<AutotaskStatus>("/v1/autotask/status");
}

export async function getAutotaskRuns(limit = 10): Promise<AutotaskRun[] | null> {
  const r = await get<{ runs: AutotaskRun[] }>(`/v1/autotask/runs?limit=${limit}`);
  return r ? r.runs : null;
}

export async function getAutotaskTickets(): Promise<AutotaskTicket[] | null> {
  const r = await get<{ tickets: AutotaskTicket[] }>("/v1/autotask/tickets");
  return r ? r.tickets : null;
}
