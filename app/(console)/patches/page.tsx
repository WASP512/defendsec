import Link from "next/link";
import { ensureStore } from "@/lib/store";
import { isUnreliable, patchReliabilityOf, unreliableExplanation, unreliableHostsNote } from "@/lib/patch-reliability";
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
  const fleet = await loadFleet(store.devices);
  const rows = fleet.flatMap((device) => device.pendingUpdates.map((item) => ({ device, item })));
  // A host whose repository check failed may show nothing without being up to date.
  const unreliable = fleet
    .map((device) => ({ device, reliability: patchReliabilityOf(device) }))
    .filter((h) => isUnreliable(h.reliability));

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
      {unreliable.length > 0 ? (
        <div
          role="alert"
          data-patches-unreliable
          className="rounded-lg border border-amber-500/50 bg-amber-500/10 px-4 py-3 text-sm text-amber-900 dark:text-amber-200"
        >
          <p className="font-medium">{unreliableHostsNote(unreliable.length)}</p>
          <p className="opacity-90">{unreliableExplanation()}</p>
          <ul className="list-disc space-y-0.5 pl-5 pt-1">
            {unreliable.map(({ device, reliability }) => (
              <li key={device.id}>
                <Link href={`/devices/${device.id}`} className="font-medium underline">
                  {device.hostname}
                </Link>
                : {reliability.reasons[0] ?? "a repository check failed"}
                {reliability.reasons.length > 1 ? ` (and ${reliability.reasons.length - 1} more)` : ""}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {rows.length === 0 && unreliable.length > 0 ? (
        <EmptyState
          title="No pending patches visible"
          description="That is not the same as up to date: the hosts listed above cannot be trusted to show their updates."
          icon={PackageCheck}
        />
      ) : rows.length === 0 ? (
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
