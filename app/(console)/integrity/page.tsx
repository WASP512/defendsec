import Link from "next/link";
import { ensureStore } from "@/lib/store";
import { relativeTime } from "@/lib/format";
import { loadFleet, loadMtlsFimEvents } from "@/lib/mtls-agents";
import { ActivityItem, ActivityList, EmptyState, PageHeader } from "@/components/console-ui";
import { FileCheck2 } from "lucide-react";

export const dynamic = "force-dynamic";

export default async function IntegrityPage() {
  const store = await ensureStore();
  const fleet = await loadFleet(store.devices);
  const events = [...(await loadMtlsFimEvents()), ...store.fimEvents];
  const watched = fleet.reduce((n, d) => n + d.fim.length, 0);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="File integrity"
        description={
          <>
          The agent hashes watched files each check-in. The first report becomes the baseline.
          Later changes fail policy until you accept the current hashes. This page is the audit
          log; {watched} path{watched === 1 ? "" : "s"} are currently reported.
          </>
        }
      />
      {events.length === 0 ? (
        <EmptyState
          title="No integrity drift"
          description="Enroll a host and change a watched file to generate an event."
          icon={FileCheck2}
        />
      ) : (
        <ActivityList>
          {events.map((event) => (
            <ActivityItem
              key={event.id}
              tone="critical"
              title={event.path}
              description={
              <p className="text-sm">
                <Link href={`/devices/${event.deviceId}`} className="underline">
                  {event.hostname}
                </Link>
                {event.sample ? " · sample" : ""}
              </p>
              }
              meta={
              <p className="break-all font-mono text-xs text-muted-foreground">
                {event.previous.slice(0, 16)}… → {event.current.slice(0, 16)}… · {relativeTime(event.detectedAt)}
              </p>
              }
            />
          ))}
        </ActivityList>
      )}
    </div>
  );
}
