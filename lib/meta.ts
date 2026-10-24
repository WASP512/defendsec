import { isMissingRelationError, query } from "@/lib/pg";

export async function getMeta(key: string): Promise<string | null> {
  try {
    const rows = await query<{ value: string }>(`SELECT value FROM meta WHERE key = $1`, [key]);
    return rows[0]?.value ?? null;
  } catch (error) {
    if (isMissingRelationError(error)) return null;
    throw error;
  }
}
