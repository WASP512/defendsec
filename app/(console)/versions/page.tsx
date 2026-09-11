import Link from "next/link";
import { ensureStore } from "@/lib/store";
import { loadFleet } from "@/lib/mtls-agents";
import { Badge } from "@/components/ui/badge";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { Boxes } from "lucide-react";

export const dynamic = "force-dynamic";

export default async function VersionsPage() {
  const store = await ensureStore();
  const byName = new Map<string, { version: string; hostname: string; deviceId: string }[]>();
  for (const device of await loadFleet(store.devices)) {
    for (const item of device.software) {
      const list = byName.get(item.name) ?? [];
      list.push({ version: item.version || "unknown", hostname: device.hostname, deviceId: device.id });
      byName.set(item.name, list);
    }
  }
  const packages = [...byName.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Versions"
        description={
          <>
          Software version records across the fleet. Split versions on one package are the first
          signal that a host missed a patch.
          </>
        }
      />
      {packages.length === 0 ? (
        <EmptyState
          title="No software inventory"
          description="Software records appear after an enrolled agent checks in."
          icon={Boxes}
        />
      ) : (
        <div className="space-y-4">
          {packages.map(([name, rows]) => {
            const versions = new Set(rows.map((row) => row.version));
            return (
              <section key={name} className="rounded-xl border p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="font-medium">{name}</h2>
                  {versions.size > 1 ? <Badge variant="secondary">mixed versions</Badge> : null}
                </div>
                <ul className="mt-3 space-y-1 text-sm">
                  {rows.map((row) => (
                    <li key={`${row.deviceId}-${row.version}`} className="flex justify-between gap-4">
                      <Link href={`/devices/${row.deviceId}`} className="underline">
                        {row.hostname}
                      </Link>
                      <span className="text-muted-foreground">{row.version}</span>
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}
