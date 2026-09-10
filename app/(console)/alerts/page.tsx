import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertActions } from "@/components/alert-actions";
import { AlertSuggestActions } from "@/components/alert-suggest-actions";
import { isReadOnlySession } from "@/lib/auth";
import { SeverityBadge } from "@/components/status-badge";
import { databaseURL } from "@/lib/pg";
import { listAlerts, type Alert, type AlertStatus } from "@/lib/alerts";
import { relativeTime } from "@/lib/format";

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
  if (configured) {
    try {
      alerts = await listAlerts({ status, kind, deviceId, limit: 200 });
    } catch (cause) {
      error = cause instanceof Error ? cause.message : "Could not read alerts";
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
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Alerts</h1>
        <p className="mt-1 text-muted-foreground">
          FIM changes, SCA failures, and other detections from enrolled hosts.
        </p>
      </div>

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

      <div className="flex flex-wrap gap-2 text-sm">
        <span className="text-muted-foreground">Status:</span>
        <Link
          href={filterHref({ status: "" })}
          className={status === "" ? "font-medium underline" : "text-muted-foreground hover:underline"}
        >
          all
        </Link>
        {STATUSES.map((item) => (
          <Link
            key={item}
            href={filterHref({ status: item })}
            className={status === item ? "font-medium underline" : "text-muted-foreground hover:underline"}
          >
            {item}
          </Link>
        ))}
      </div>

      <div className="flex flex-wrap gap-2 text-sm">
        <span className="text-muted-foreground">Kind:</span>
        {KINDS.map((item) => (
          <Link
            key={item || "all"}
            href={filterHref({ kind: item })}
            className={kind === item ? "font-medium underline" : "text-muted-foreground hover:underline"}
          >
            {item || "all"}
          </Link>
        ))}
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

      {configured && !error && alerts.length === 0 ? (
        <p className="text-sm text-muted-foreground">No alerts match these filters.</p>
      ) : null}

      <ul className="divide-y rounded-xl border">
        {alerts.map((alert) => (
          <li key={alert.id} className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{alert.title}</span>
                <SeverityBadge severity={alert.severity === "info" ? "low" : alert.severity} />
                <Badge variant="outline">{alert.kind}</Badge>
                <Badge variant={alert.status === "open" ? "default" : "secondary"}>{alert.status}</Badge>
              </div>
              <p className="text-sm text-muted-foreground">{alert.summary}</p>
              <p className="text-xs text-muted-foreground">
                <Link href={`/devices/${alert.deviceId}`} className="underline">
                  {alert.hostname || alert.deviceId}
                </Link>
                {" · "}
                {relativeTime(alert.createdAt)}
              </p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <AlertSuggestActions alert={alert} readOnly={readOnly} />
              <AlertActions alertId={alert.id} status={alert.status} readOnly={readOnly} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
