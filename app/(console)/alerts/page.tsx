import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ActivityItem, ActivityList, EmptyState, PageHeader } from "@/components/console-ui";
import { AlertActions } from "@/components/alert-actions";
import { AlertSuggestActions } from "@/components/alert-suggest-actions";
import { isReadOnlySession } from "@/lib/auth";
import { SeverityBadge } from "@/components/status-badge";
import { databaseURL, isMissingRelationError } from "@/lib/pg";
import { listAlerts, type Alert, type AlertStatus } from "@/lib/alerts";
import { relativeTime } from "@/lib/format";
import { BellRing, Filter } from "lucide-react";

export const dynamic = "force-dynamic";

const STATUSES: AlertStatus[] = ["open", "acknowledged", "resolved", "suppressed"];
const KINDS = ["", "fim", "sca", "vuln", "response", "system"];

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string; kind?: string; deviceId?: string }>;
}) {
  const params = await searchParams;
  const status = params.status ?? "";
  const kind = params.kind ?? "";
  const deviceId = params.deviceId ?? "";
  const configured = Boolean(databaseURL());
  const readOnly = await isReadOnlySession();

  let alerts: Alert[] = [];
  let error = "";
  let storageSetupRequired = false;
  if (configured) {
    try {
      alerts = await listAlerts({ status, kind, deviceId, limit: 200 });
    } catch (cause) {
      storageSetupRequired = isMissingRelationError(cause);
      if (!storageSetupRequired) {
        error = cause instanceof Error ? cause.message : "Could not read alerts";
      }
    }
  }

  function filterHref(next: { status?: string; kind?: string; deviceId?: string }) {
    const q = new URLSearchParams();
    const s = next.status ?? status;
    const k = next.kind ?? kind;
    const d = next.deviceId ?? deviceId;
    if (s) q.set("status", s);
    if (k) q.set("kind", k);
    if (d) q.set("deviceId", d);
    const qs = q.toString();
    return qs ? `/alerts?${qs}` : "/alerts";
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <PageHeader
        title="Alerts"
        description="FIM changes, SCA failures, and other detections from enrolled hosts."
      />

      {!configured ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Postgres not configured</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Set <code className="text-foreground">DATABASE_URL</code> or{" "}
            <code className="text-foreground">DEFENDSEC_DATABASE_URL</code> and restart defendsec-apid.
            Alerts are dual-written when Postgres is enabled.
          </CardContent>
        </Card>
      ) : null}

      <div className="rounded-xl border bg-card p-3">
        <div className="mb-3 flex items-center gap-2 text-sm font-medium">
          <Filter className="size-4" />
          Filter alerts
        </div>
        <div className="flex flex-wrap gap-1">
        <Link
          href={filterHref({ status: "" })}
          className={status === "" ? "rounded-md bg-primary px-2.5 py-1 text-xs text-primary-foreground" : "rounded-md px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted"}
        >
          all
        </Link>
        {STATUSES.map((item) => (
          <Link
            key={item}
            href={filterHref({ status: item })}
            className={status === item ? "rounded-md bg-primary px-2.5 py-1 text-xs text-primary-foreground" : "rounded-md px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted"}
          >
            {item}
          </Link>
        ))}
        </div>
        <div className="my-3 border-t" />
        <div className="flex flex-wrap gap-1">
        {KINDS.map((item) => (
          <Link
            key={item || "all"}
            href={filterHref({ kind: item })}
            className={kind === item ? "rounded-md bg-secondary px-2.5 py-1 text-xs font-medium" : "rounded-md px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted"}
          >
            {item || "all kinds"}
          </Link>
        ))}
        </div>
      </div>

      {deviceId ? (
        <p className="text-sm text-muted-foreground">
          Filtered to device <code className="text-foreground">{deviceId}</code> ·{" "}
          <Link href="/alerts" className="underline">
            clear
          </Link>
        </p>
      ) : null}

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {storageSetupRequired ? (
        <EmptyState
          title="Alert storage needs setup"
          description="Restart the control plane with DEFENDSEC_DATABASE_URL configured. DefendSec now applies embedded migrations automatically at startup."
          icon={BellRing}
          action={<code className="rounded-md bg-muted px-3 py-2 text-xs">sudo systemctl restart defendsec-apid</code>}
          compact
        />
      ) : null}

      {configured && !error && !storageSetupRequired && alerts.length === 0 ? (
        <EmptyState
          title="No matching alerts"
          description="No detections match the current status, kind, and device filters."
          icon={BellRing}
          compact
        />
      ) : null}

      <ActivityList>
        {alerts.map((alert) => (
          <ActivityItem
            key={alert.id}
            tone={alert.severity === "critical" || alert.severity === "high" ? "critical" : alert.severity === "medium" ? "warning" : "neutral"}
            title={
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{alert.title}</span>
                <SeverityBadge severity={alert.severity === "info" ? "low" : alert.severity} />
                <Badge variant="outline">{alert.kind}</Badge>
                <Badge variant={alert.status === "open" ? "default" : "secondary"}>{alert.status}</Badge>
              </div>
            }
            description={alert.summary}
            meta={
              <p className="text-xs text-muted-foreground">
                <Link href={`/devices/${alert.deviceId}`} className="underline">
                  {alert.hostname || alert.deviceId}
                </Link>
                {" · detected "}
                {relativeTime(alert.detectedAt || alert.createdAt)}
                {alert.ingestedAt && alert.detectedAt && alert.ingestedAt !== alert.detectedAt
                  ? ` · ingested ${relativeTime(alert.ingestedAt)}`
                  : null}
                {alert.generatorId ? ` · ${alert.generatorId}` : null}
              </p>
            }
            actions={<div className="flex flex-col items-end gap-2">
              <AlertSuggestActions alert={alert} readOnly={readOnly} />
              <AlertActions alertId={alert.id} status={alert.status} readOnly={readOnly} />
            </div>}
          />
        ))}
      </ActivityList>
    </div>
  );
}
