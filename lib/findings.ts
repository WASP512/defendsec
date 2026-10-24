import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import type {
  DeviceFindingsSummary,
  FindingDetail,
  FindingKind,
  FindingsResponse,
  FindingsSummaryResponse,
} from "@/lib/findings-model";

/**
 * Findings are computed by apid and read here. Every function returns null if
 * the control plane cannot be reached (admin API down, or an apid older than the
 * findings API): callers show "findings unavailable", never an empty list, since
 * an empty list reads as "all clear".
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

export function getFindings(
  opts: { deviceId?: string; kind?: FindingKind; resolved?: boolean; limit?: number } = {},
): Promise<FindingsResponse | null> {
  const q = new URLSearchParams();
  if (opts.deviceId) q.set("deviceId", opts.deviceId);
  if (opts.kind) q.set("kind", opts.kind);
  if (opts.resolved) q.set("resolved", "1");
  if (opts.limit) q.set("limit", String(opts.limit));
  const qs = q.toString();
  return get<FindingsResponse>(`/v1/findings${qs ? `?${qs}` : ""}`);
}

export function getFindingDetail(id: number): Promise<FindingDetail | null> {
  return get<FindingDetail>(`/v1/findings/${id}`);
}

/** Per-host standing for the fleet views; null if unavailable. */
export async function getFindingsSummary(deviceId?: string): Promise<Map<string, DeviceFindingsSummary> | null> {
  const body = await get<FindingsSummaryResponse>(
    `/v1/findings/summary${deviceId ? `?deviceId=${encodeURIComponent(deviceId)}` : ""}`,
  );
  if (!body) return null;
  return new Map(body.devices.map((d) => [d.deviceId, d]));
}
