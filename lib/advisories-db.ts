import type { Advisory } from "./types";
import { query } from "./pg";
import { ADVISORIES } from "./advisories";

export async function loadAdvisories(): Promise<Advisory[]> {
  const rows = await query<{
    id: string;
    cve: string;
    package: string;
    below: string;
    severity: string;
    summary: string;
  }>(`SELECT id, cve, package, below, severity, summary FROM advisories ORDER BY severity, package`);
  if (rows.length === 0) return ADVISORIES;
  return rows.map((row) => ({
    id: row.id,
    cve: row.cve,
    package: row.package,
    below: row.below,
    severity: row.severity as Advisory["severity"],
    summary: row.summary,
  }));
}
