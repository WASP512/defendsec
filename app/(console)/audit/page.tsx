import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { databaseURL, listAudit } from "@/lib/pg";
import { relativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const configured = Boolean(databaseURL());
  let events: Awaited<ReturnType<typeof listAudit>> = [];
  let error = "";
  if (configured) {
    try {
      events = await listAudit(150);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : "Could not read audit log";
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Audit</h1>
        <p className="mt-1 text-muted-foreground">
          Control-plane actions written to Postgres when{" "}
          <code className="text-foreground">DATABASE_URL</code> /{" "}
          <code className="text-foreground">DEFENDSEC_DATABASE_URL</code> is set.
        </p>
      </div>

      {!configured ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Postgres not configured</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Start Postgres (`docker compose up -d postgres`), set{" "}
            <code className="text-foreground">
              DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec
            </code>
            , and restart defendsec-apid. Enroll, commands, revoke, and advisory imports will then appear
            here.
          </CardContent>
        </Card>
      ) : null}

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {configured && !error && events.length === 0 ? (
        <p className="text-sm text-muted-foreground">No audit events yet.</p>
      ) : null}

      <ul className="divide-y rounded-xl border">
        {events.map((event) => (
          <li key={event.id} className="px-4 py-3 text-sm">
            <p className="font-medium">
              {event.action} · {event.actor}
              {event.deviceId ? ` · ${event.deviceId}` : ""}
            </p>
            <p className="text-muted-foreground">
              {relativeTime(event.at)} · {JSON.stringify(event.detail ?? {})}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
