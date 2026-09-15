import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { databaseURL, isMissingRelationError, listAudit } from "@/lib/pg";
import { relativeTime } from "@/lib/format";
import {
  ActivityItem,
  ActivityList,
  EmptyState,
  PageHeader,
} from "@/components/console-ui";
import { ScrollText } from "lucide-react";
import { AnchorPanel } from "@/components/anchor-panel";
import { loadAnchorStatus, type AnchorStatus } from "@/lib/compliance";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const configured = Boolean(databaseURL());
  let events: Awaited<ReturnType<typeof listAudit>> = [];
  let error = "";
  let storageSetupRequired = false;
  if (configured) {
    try {
      events = await listAudit(150);
    } catch (cause) {
      storageSetupRequired = isMissingRelationError(cause);
      if (!storageSetupRequired) {
        error =
          cause instanceof Error ? cause.message : "Could not read audit log";
      }
    }
  }

  // The ledger is only as trustworthy as the checks against it, so the anchor
  // comparison sits on the same page as the entries rather than somewhere an
  // operator has to think to look.
  let anchors: AnchorStatus | null = null;
  if (configured) {
    try {
      anchors = await loadAnchorStatus();
    } catch {
      // Anchor status is supplementary; the ledger still renders without it.
      anchors = null;
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <PageHeader
        title="Audit"
        description={
          <>
            Control-plane actions written to Postgres when{" "}
            <code className="text-foreground">DATABASE_URL</code> /{" "}
            <code className="text-foreground">DEFENDSEC_DATABASE_URL</code> is
            set.
          </>
        }
      />

      {configured ? <AnchorPanel status={anchors} /> : null}

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
            , and restart defendsec-apid. Enroll, commands, revoke, and advisory
            imports will then appear here.
          </CardContent>
        </Card>
      ) : null}

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {storageSetupRequired ? (
        <EmptyState
          title="Audit storage needs setup"
          description="Restart the control plane with DEFENDSEC_DATABASE_URL configured. DefendSec now applies embedded migrations automatically at startup."
          icon={ScrollText}
          action={
            <code className="rounded-md bg-muted px-3 py-2 text-xs">
              sudo systemctl restart defendsec-apid
            </code>
          }
          compact
        />
      ) : null}

      {configured && !error && !storageSetupRequired && events.length === 0 ? (
        <EmptyState
          title="No audit events"
          description="Control-plane activity appears here after an admin action."
          icon={ScrollText}
          compact
        />
      ) : null}

      <ActivityList>
        {events.map((event) => (
          <ActivityItem
            key={event.id}
            title={
              <>
                {event.action} · {event.actor}
                {event.deviceId ? ` · ${event.deviceId}` : ""}
              </>
            }
            meta={
              <p className="text-muted-foreground">
                {relativeTime(event.at)} · {JSON.stringify(event.detail ?? {})}
              </p>
            }
          />
        ))}
      </ActivityList>
    </div>
  );
}
