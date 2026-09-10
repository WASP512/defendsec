import { query } from "@/lib/pg";
import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";

export async function getMeta(key: string): Promise<string | null> {
  const rows = await query<{ value: string }>(`SELECT value FROM meta WHERE key = $1`, [key]);
  return rows[0]?.value ?? null;
}

export async function getOsvLastIngest(): Promise<string | null> {
  const fromDb = await getMeta("osv_last_ingest");
  if (fromDb) return fromDb;
  try {
    const token = await getAdminToken();
    const response = await fetch(new URL("/v1/meta", APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { osvLastIngest?: string };
    return body.osvLastIngest ?? null;
  } catch {
    return null;
  }
}
