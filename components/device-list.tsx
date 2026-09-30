import Link from "next/link";
import { Monitor } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/console-ui";
import { OnlineBadge } from "@/components/status-badge";
import { platformLabel, relativeTime } from "@/lib/format";
import type { Platform } from "@/lib/types";
import {
  nextHref,
  pageNumber,
  PAGE_SIZE,
  prevHref,
  type DeviceListQuery,
  type DevicePage,
} from "@/lib/device-list";

// Server-rendered: filters are a GET form and paging is links, so the page
// works without client JavaScript and every view has a shareable URL.
export function DeviceList({ query, page }: { query: DeviceListQuery; page: DevicePage }) {
  const filtered = Boolean(query.q || query.platform || query.status);
  const prev = prevHref(query);
  const next = nextHref(query, page.next);
  const first = (pageNumber(query) - 1) * PAGE_SIZE;

  return (
    <div className="space-y-3">
      <form method="get" action="/devices" className="flex flex-wrap items-center gap-2">
        <Input
          name="q"
          defaultValue={query.q}
          placeholder="Hostname, serial, user, OS or IP"
          className="max-w-xs"
          aria-label="Search hosts"
        />
        <select name="platform" defaultValue={query.platform} aria-label="Platform"
          className="h-9 rounded-md border bg-background px-2 text-sm">
          <option value="">All platforms</option>
          <option value="linux">Linux</option>
          <option value="windows">Windows</option>
        </select>
        <select name="status" defaultValue={query.status} aria-label="Status"
          className="h-9 rounded-md border bg-background px-2 text-sm">
          <option value="">Any status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="isolated">Isolated</option>
        </select>
        <button type="submit" className="h-9 rounded-md border px-3 text-sm font-medium hover:bg-muted">
          Filter
        </button>
        {filtered ? (
          <Link href="/devices" className="text-sm text-muted-foreground underline">Clear</Link>
        ) : null}
      </form>

      {page.devices.length === 0 ? (
        filtered ? (
          <p className="rounded-xl border p-6 text-center text-sm text-muted-foreground">No hosts match these filters.</p>
        ) : (
          <EmptyState
            title="No hosts yet"
            description="Enroll an agent to see it here."
            icon={Monitor}
            action={<Link href="/enroll" className="text-sm font-medium underline">Install an agent</Link>}
          />
        )
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>Platform</TableHead>
                <TableHead className="hidden md:table-cell">User</TableHead>
                <TableHead className="hidden lg:table-cell">Software</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden sm:table-cell">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.devices.map((d) => (
                <TableRow key={d.id}>
                  <TableCell className="min-w-40">
                    <Link href={`/devices/${d.id}`} className="font-medium hover:underline">{d.hostname}</Link>
                    {d.isolated ? <Badge variant="destructive" className="ml-2">isolated</Badge> : null}
                  </TableCell>
                  <TableCell>
                    {platformLabel(d.platform as Platform)}
                    <span className="block text-xs text-muted-foreground">{d.osName} {d.osVersion}</span>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">{d.username || "—"}</TableCell>
                  <TableCell className="hidden lg:table-cell">
                    {d.softwareCount}
                    {d.pendingUpdates ? <span className="text-muted-foreground"> · {d.pendingUpdates} updates</span> : null}
                  </TableCell>
                  <TableCell><OnlineBadge online={d.online} /></TableCell>
                  <TableCell className="hidden text-muted-foreground sm:table-cell">{relativeTime(d.lastSeen)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>
          {page.total === 0
            ? "0 hosts"
            : `${first + 1}–${first + page.devices.length} of ${page.total} host${page.total === 1 ? "" : "s"}`}
        </span>
        <div className="flex items-center gap-2">
          {prev ? <Link href={prev} className="rounded-md border px-3 py-1 hover:bg-muted">Previous</Link> : null}
          <span>Page {pageNumber(query)}</span>
          {next ? <Link href={next} className="rounded-md border px-3 py-1 hover:bg-muted">Next</Link> : null}
        </div>
      </div>
    </div>
  );
}
