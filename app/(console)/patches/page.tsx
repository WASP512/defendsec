import Link from "next/link";
import { ensureStore } from "@/lib/store";
import { loadFleet } from "@/lib/mtls-agents";

export const dynamic = "force-dynamic";

export default async function PatchesPage() {
  const store = await ensureStore();
  const rows = (await loadFleet(store.devices)).flatMap((device) =>
    device.pendingUpdates.map((item) => ({ device, item })),
  );

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Patches</h1>
        <p className="mt-1 max-w-2xl text-muted-foreground">
          Outstanding updates the agent reported (apt upgradable on Debian/Ubuntu, plus sample
          fleet stubs). DefendSec records the gap; it does not push patches to the host.
        </p>
      </div>
      {rows.length === 0 ? (
        <p className="rounded-xl border border-dashed p-10 text-center text-muted-foreground">
          No pending patches reported.
        </p>
      ) : (
        <ul className="divide-y rounded-xl border">
          {rows.map(({ device, item }) => (
            <li
              key={`${device.id}-${item.name}-${item.available}`}
              className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div>
                <p className="font-medium">{item.name}</p>
                <p className="text-sm text-muted-foreground">
                  <Link href={`/devices/${device.id}`} className="underline">
                    {device.hostname}
                  </Link>
                </p>
              </div>
              <p className="text-sm text-muted-foreground">
                {item.current} → {item.available}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
