import { query } from "@/lib/pg";
import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";

export type AlertStatus = "open" | "acknowledged" | "resolved" | "suppressed";
export type AlertKind = "fim" | "sca" | "vuln" | "response" | "system";
export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export type Alert = {
  id: string;
  createdAt: string;
  updatedAt: string;
  deviceId: string;
  hostname: string;
  kind: AlertKind;
  severity: AlertSeverity;
  title: string;
  summary: string;
  status: AlertStatus;
  sourceType: string;
  sourceId: string;
  detail: Record<string, unknown>;
};

export type AlertFilters = {
  status?: string;
  kind?: string;
  deviceId?: string;
  limit?: number;
};

function mapRow(row: {
  id: string;
  created_at: Date;
  updated_at: Date;
  device_id: string;
  hostname: string;
  kind: string;
  severity: string;
  title: string;
  summary: string;
  status: string;
  source_type: string;
  source_id: string;
  detail: unknown;
}): Alert {
  return {
    id: row.id,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    deviceId: row.device_id,
    hostname: row.hostname,
    kind: row.kind as AlertKind,
    severity: row.severity as AlertSeverity,
    title: row.title,
    summary: row.summary,
    status: row.status as AlertStatus,
    sourceType: row.source_type,
    sourceId: row.source_id,
    detail: (row.detail as Record<string, unknown>) ?? {},
  };
}

export async function listAlerts(filters: AlertFilters = {}): Promise<Alert[]> {
  const limit = filters.limit ?? 200;
  const rows = await query<{
    id: string;
    created_at: Date;
    updated_at: Date;
    device_id: string;
    hostname: string;
    kind: string;
    severity: string;
    title: string;
    summary: string;
    status: string;
    source_type: string;
    source_id: string;
    detail: unknown;
  }>(
    `SELECT id, created_at, updated_at, device_id, hostname, kind, severity,
            title, summary, status, source_type, source_id, detail
     FROM alerts
     WHERE ($1 = '' OR status = $1)
       AND ($2 = '' OR kind = $2)
       AND ($3 = '' OR device_id = $3)
     ORDER BY created_at DESC
     LIMIT $4`,
    [filters.status ?? "", filters.kind ?? "", filters.deviceId ?? "", limit],
  );
  return rows.map(mapRow);
}

export async function updateAlertStatus(id: string, status: AlertStatus): Promise<boolean> {
  const rows = await query<{ id: string }>(
    `UPDATE alerts SET status = $2, updated_at = now() WHERE id = $1 RETURNING id`,
    [id, status],
  );
  return rows.length > 0;
}

export async function listAlertsFromApid(filters: AlertFilters = {}): Promise<Alert[]> {
  const token = await getAdminToken();
  const url = new URL("/v1/alerts", APID_ADMIN_URL);
  if (filters.status) url.searchParams.set("status", filters.status);
  if (filters.kind) url.searchParams.set("kind", filters.kind);
  if (filters.deviceId) url.searchParams.set("deviceId", filters.deviceId);
  if (filters.limit) url.searchParams.set("limit", String(filters.limit));
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`apid alerts: ${response.status}`);
  }
  const body = (await response.json()) as { alerts?: Alert[] };
  return body.alerts ?? [];
}

export async function updateAlertStatusViaApid(id: string, status: AlertStatus): Promise<void> {
  const token = await getAdminToken();
  const response = await fetch(new URL("/v1/alerts/status", APID_ADMIN_URL), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ id, status }),
  });
  if (!response.ok) {
    throw new Error(`apid alert status: ${response.status}`);
  }
}
