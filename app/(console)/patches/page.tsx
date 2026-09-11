import Link from "next/link";
import { ensureStore } from "@/lib/store";
import { loadFleet } from "@/lib/mtls-agents";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { PackageCheck } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export const dynamic = "force-dynamic";

export default async function PatchesPage() {
  const store = await ensureStore();
  const rows = (await loadFleet(store.devices)).flatMap((device) =>
    device.pendingUpdates.map((item) => ({ device, item })),
  );

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Patches"
        description={
          <>
          Outstanding updates the agent reported (apt upgradable on Debian/Ubuntu, plus sample
          fleet stubs). DefendSec records the gap; it does not push patches to the host.
          </>
        }
      />
      {rows.length === 0 ? (
        <EmptyState
          title="Fleet is up to date"
          description="No enrolled host currently reports a pending patch."
          icon={PackageCheck}
        />
      ) : (
        <div className="overflow-hidden rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Current</TableHead>
                <TableHead>Available</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(({ device, item }) => (
                <TableRow key={`${device.id}-${item.name}-${item.available}`}>
                  <TableCell className="font-medium">{item.name}</TableCell>
                  <TableCell>
                  <Link href={`/devices/${device.id}`} className="underline">
                    {device.hostname}
                  </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{item.current}</TableCell>
                  <TableCell>{item.available}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
