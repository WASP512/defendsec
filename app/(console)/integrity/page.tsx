import Link from "next/link";
import { ensureStore } from "@/lib/store";
import { relativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function IntegrityPage() {
  const store = await ensureStore();
  const watched = store.devices.reduce((n, d) => n + d.fim.length, 0);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">File integrity</h1>
        <p className="mt-1 max-w-2xl text-muted-foreground">
          The agent hashes watched files each check-in. The first report becomes the baseline.
          Later changes fail policy until you accept the current hashes. This page is the audit
          log; {watched} path{watched === 1 ? "" : "s"} are currently reported.
        </p>
      </div>
      {store.fimEvents.length === 0 ? (
        <p className="rounded-xl border border-dashed p-10 text-center text-muted-foreground">
          No integrity drift recorded. Enroll a host and change a watched file to generate an
          event.
        </p>
      ) : (
        <ul className="divide-y rounded-xl border">
          {store.fimEvents.map((event) => (
            <li key={event.id} className="space-y-1 px-4 py-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="font-medium">{event.path}</p>
                <p className="text-sm text-muted-foreground">{relativeTime(event.detectedAt)}</p>
              </div>
              <p className="text-sm">
                <Link href={`/devices/${event.deviceId}`} className="underline">
                  {event.hostname}
                </Link>
                {event.sample ? " · sample" : ""}
              </p>
              <p className="break-all font-mono text-xs text-muted-foreground">
                {event.previous} → {event.current}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
