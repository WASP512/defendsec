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
  detectedAt?: string;
  ingestedAt?: string;
  deviceId: string;
  hostname: string;
  kind: AlertKind;
  severity: AlertSeverity;
  title: string;
  summary: string;
  status: AlertStatus;
  sourceType: string;
  sourceId: string;
  generatorId?: string;
  generatorVersion?: string;
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
  detected_at?: Date | null;
  ingested_at?: Date | null;
  device_id: string;
  hostname: string;
  kind: string;
  severity: string;
  title: string;
  summary: string;
  status: string;
  source_type: string;
  source_id: string;
  generator_id?: string | null;
  generator_version?: string | null;
  detail: unknown;
}): Alert {
  return {
    id: row.id,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    detectedAt: row.detected_at ? new Date(row.detected_at).toISOString() : undefined,
    ingestedAt: row.ingested_at ? new Date(row.ingested_at).toISOString() : undefined,
    deviceId: row.device_id,
    hostname: row.hostname,
    kind: row.kind as AlertKind,
    severity: row.severity as AlertSeverity,
    title: row.title,
    summary: row.summary,
    status: row.status as AlertStatus,
    sourceType: row.source_type,
    sourceId: row.source_id,
    generatorId: row.generator_id ?? undefined,
    generatorVersion: row.generator_version ?? undefined,
    detail: (row.detail as Record<string, unknown>) ?? {},
  };
}

export async function listAlerts(filters: AlertFilters = {}): Promise<Alert[]> {
  const limit = filters.limit ?? 200;
  const rows = await query<{
    id: string;
    created_at: Date;
    updated_at: Date;
    detected_at: Date | null;
    ingested_at: Date | null;
    device_id: string;
    hostname: string;
    kind: string;
    severity: string;
    title: string;
    summary: string;
    status: string;
    source_type: string;
    source_id: string;
    generator_id: string | null;
    generator_version: string | null;
    detail: unknown;
  }>(
    `SELECT id, created_at, updated_at,
            COALESCE(detected_at, created_at) AS detected_at,
            COALESCE(ingested_at, created_at) AS ingested_at,
            device_id, hostname, kind, severity,
            title, summary, status, source_type, source_id,
            COALESCE(generator_id, '') AS generator_id,
            COALESCE(generator_version, '') AS generator_version,
            detail
     FROM alerts
     WHERE ($1 = '' OR status = $1)
       AND ($2 = '' OR kind = $2)
       AND ($3 = '' OR device_id = $3)
     ORDER BY COALESCE(detected_at, created_at) DESC
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
