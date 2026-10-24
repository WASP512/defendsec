import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import type { RmmDeviceDetail, RmmDeviceRow, RmmStatus, RmmSync } from "@/lib/rmm-model";

/**
 * The Datto RMM collector lives in apid; the console reads it there. A read
 * returns null when the control plane cannot be reached (or is older than the
 * RMM API): callers say "unavailable", never an empty list, because an empty list
 * of Windows devices reads as "no Windows devices", and a failed read says nothing
 * about them. Writes go through forwardToApid with the caller's own session.
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

export function getRmmStatus(): Promise<RmmStatus | null> {
  return get<RmmStatus>("/v1/rmm/status");
}

export async function getRmmDevices(): Promise<RmmDeviceRow[] | null> {
  const r = await get<{ devices: RmmDeviceRow[] }>("/v1/rmm/devices");
  return r ? r.devices : null;
}

export function getRmmDevice(id: string): Promise<RmmDeviceDetail | null> {
  return get<RmmDeviceDetail>(`/v1/rmm/devices/${encodeURIComponent(id)}`);
}

export async function getRmmSyncs(limit = 10): Promise<RmmSync[] | null> {
  const r = await get<{ syncs: RmmSync[] }>(`/v1/rmm/syncs?limit=${limit}`);
  return r ? r.syncs : null;
}
