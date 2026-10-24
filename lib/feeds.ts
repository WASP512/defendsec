import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import type { FeedsResponse } from "@/lib/feed-banner";

/**
 * Per-feed sync state from the control plane (GET /v1/feeds). Returns null if
 * it cannot be read (admin API down, or an apid older than the feeds service);
 * the banner treats that as "unknown", never as "fine".
 */
export async function getFeedStatus(): Promise<FeedsResponse | null> {
  try {
    const token = await getAdminToken();
    const response = await fetch(new URL("/v1/feeds", APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as FeedsResponse;
  } catch {
    return null;
  }
}
