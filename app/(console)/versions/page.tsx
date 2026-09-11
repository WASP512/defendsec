import { ensureStore } from "@/lib/store";
import { loadFleet } from "@/lib/mtls-agents";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { Boxes } from "lucide-react";
import { VersionTable, type VersionRow } from "@/components/version-table";

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
  const rows: VersionRow[] = packages.flatMap(([packageName, records]) => {
    const mixed = new Set(records.map((row) => row.version)).size > 1;
    return records.map((row) => ({ packageName, mixed, ...row }));
  });

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
        <VersionTable rows={rows} />
      )}
    </div>
  );
}
