import { Pool, type QueryResultRow } from "pg";

let pool: Pool | null | undefined;

export function databaseURL(): string {
  return (
    process.env.DATABASE_URL?.trim() ||
    process.env.DEFENDSEC_DATABASE_URL?.trim() ||
    ""
  );
}

export function getPool(): Pool | null {
  if (pool !== undefined) return pool;
  const url = databaseURL();
  if (!url) {
    pool = null;
    return pool;
  }
  pool = new Pool({ connectionString: url, max: 4 });
  return pool;
}

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<T[]> {
  const p = getPool();
  if (!p) return [];
  const result = await p.query<T>(text, params);
  return result.rows;
}

export type AuditRow = {
  id: number;
  at: string;
  actor: string;
  action: string;
  deviceId: string;
  detail: unknown;
};

export async function listAudit(limit = 100): Promise<AuditRow[]> {
  const rows = await query<{
    id: number;
    at: Date;
    actor: string;
    action: string;
    device_id: string;
    detail: unknown;
  }>(
    `SELECT id, at, actor, action, device_id, detail
     FROM audit_log
     ORDER BY at DESC
     LIMIT $1`,
    [limit],
  );
  return rows.map((row) => ({
    id: row.id,
    at: new Date(row.at).toISOString(),
    actor: row.actor,
    action: row.action,
    deviceId: row.device_id,
    detail: row.detail,
  }));
}
