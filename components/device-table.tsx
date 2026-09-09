import Link from "next/link";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { OnlineBadge } from "@/components/status-badge";
import { formatBytesMb, onlineFromLastSeen, platformLabel, relativeTime } from "@/lib/format";
import type { PublicDevice } from "@/lib/types";

export function DeviceTable({ devices }: { devices: PublicDevice[] }) {
  if (devices.length === 0) {
    return (
      <div className="rounded-xl border border-dashed p-10 text-center">
        <p className="font-medium">No hosts yet</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Enroll an agent, or load the sample fleet to see the console with data.
        </p>
        <Link href="/enroll" className="mt-4 inline-block text-sm underline">
          Install an agent
        </Link>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Hostname</TableHead>
            <TableHead>Platform</TableHead>
            <TableHead className="hidden md:table-cell">User</TableHead>
            <TableHead className="hidden lg:table-cell">Memory</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="hidden sm:table-cell">Last seen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.map((device) => (
            <TableRow key={device.id}>
              <TableCell>
                <Link href={`/devices/${device.id}`} className="font-medium hover:underline">
                  {device.hostname}
                </Link>
                {device.sample ? (
                  <Badge variant="outline" className="ml-2">
                    sample
                  </Badge>
                ) : null}
              </TableCell>
              <TableCell>
                {platformLabel(device.platform)}
                <span className="block text-xs text-muted-foreground">
                  {device.osName} {device.osVersion}
                </span>
              </TableCell>
              <TableCell className="hidden md:table-cell">{device.username || "—"}</TableCell>
              <TableCell className="hidden lg:table-cell">
                {formatBytesMb(device.memoryMb)}
              </TableCell>
              <TableCell>
                <OnlineBadge online={onlineFromLastSeen(device.lastSeen)} />
              </TableCell>
              <TableCell className="hidden sm:table-cell text-muted-foreground">
                {relativeTime(device.lastSeen)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
