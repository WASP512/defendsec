import { getAdminToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";
import type { OsRelease } from "@/lib/os-lifecycle";
import { currentOsCalendar, setOsCalendar } from "@/lib/supported-os";

// The Windows release calendar (endoflife.date, loaded by defendsec-feeds)
// from the control plane. Cached for five minutes; a failed read keeps the last
// good calendar, and with none the Windows judgement is "unknown", never
// "unsupported".

const TTL_MS = 5 * 60 * 1000;
let loadedAt = 0;
let inflight: Promise<void> | null = null;

async function load(): Promise<void> {
  try {
    const token = await getAdminToken();
    const response = await fetch(new URL("/v1/lifecycle/os", APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!response.ok) return;
    const body = (await response.json()) as { releases?: OsRelease[] };
    if (Array.isArray(body.releases) && body.releases.length > 0) {
      setOsCalendar(body.releases);
      loadedAt = Date.now();
    }
  } catch {
    // keep what we have
  }
}

export async function warmOsCalendar(): Promise<void> {
  if (currentOsCalendar() && Date.now() - loadedAt < TTL_MS) return;
  inflight ??= load().finally(() => {
    inflight = null;
  });
  await inflight;
}
