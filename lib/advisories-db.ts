import type { Advisory } from "./types";
import { isMissingRelationError, query } from "./pg";
import { ADVISORIES } from "./advisories";

export async function loadAdvisories(): Promise<Advisory[]> {
  try {
    // Advisories written by defendsec-feeds keep their versions in
    // advisory_ranges and have an empty package/below. This matcher only
    // understands the legacy single-floor rows, so it must not see them (an
    // empty package would be matched against everything). Same filter as
    // storepg.ListAdvisories. The distro-aware matcher replaces this.
    const rows = await query<{
      id: string;
      cve: string;
      package: string;
      below: string;
      severity: string;
      summary: string;
    }>(`SELECT id, cve, package, below, severity, summary FROM advisories WHERE package <> '' ORDER BY severity, package`);
    if (rows.length === 0) return ADVISORIES;
    return rows.map((row) => ({
      id: row.id,
      cve: row.cve,
      package: row.package,
      below: row.below,
      severity: row.severity as Advisory["severity"],
      summary: row.summary,
    }));
  } catch (error) {
    // Optional catalog: fall back to the bundled list when migrations are absent.
    if (isMissingRelationError(error)) return ADVISORIES;
    throw error;
  }
}
