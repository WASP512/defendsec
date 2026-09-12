"use client";

import Link from "next/link";
import {
  type ColumnDef,
  columnFilteringFeature,
  createFilteredRowModel,
  createPaginatedRowModel,
  createSortedRowModel,
  globalFilteringFeature,
  rowPaginationFeature,
  rowSortingFeature,
  tableFeatures,
  type SortingState,
  useTable,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronsUpDown, Monitor, Search } from "lucide-react";
import { useMemo, useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/console-ui";
import { OnlineBadge } from "@/components/status-badge";
import { formatBytesMb, platformLabel, relativeTime } from "@/lib/format";
import { isOnline } from "@/lib/policies";
import type { PublicDevice } from "@/lib/types";

const features = tableFeatures({
  columnFilteringFeature,
  globalFilteringFeature,
  rowSortingFeature,
  rowPaginationFeature,
  filteredRowModel: createFilteredRowModel(),
  sortedRowModel: createSortedRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
});

export function DeviceTable({ devices }: { devices: PublicDevice[] }) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [globalFilter, setGlobalFilter] = useState("");

  const columns = useMemo<ColumnDef<typeof features, PublicDevice>[]>(
    () => [
      {
        accessorKey: "hostname",
        header: "Hostname",
        cell: ({ row }) => (
          <div className="min-w-40">
            <Link href={`/devices/${row.original.id}`} className="font-medium hover:underline">
              {row.original.hostname}
            </Link>
            <div className="mt-1 flex flex-wrap gap-1">
              {row.original.sample ? <Badge variant="outline">sample</Badge> : null}
              {row.original.hardwareModel === "mTLS gRPC agent" || row.original.mtlsDeviceId ? (
                <Badge variant="outline">mTLS</Badge>
              ) : null}
              {row.original.isolated ? <Badge variant="destructive">isolated</Badge> : null}
            </div>
          </div>
        ),
      },
      {
        id: "platform",
        accessorFn: (device) => `${platformLabel(device.platform)} ${device.osName} ${device.osVersion}`,
        header: "Platform",
        cell: ({ row }) => (
          <>
            {platformLabel(row.original.platform)}
            <span className="block text-xs text-muted-foreground">
              {row.original.osName} {row.original.osVersion}
            </span>
          </>
        ),
      },
      {
        accessorKey: "username",
        header: "User",
        cell: ({ row }) => row.original.username || "—",
        meta: { className: "hidden md:table-cell" },
      },
      {
        accessorKey: "memoryMb",
        header: "Memory",
        cell: ({ row }) => formatBytesMb(row.original.memoryMb),
        meta: { className: "hidden lg:table-cell" },
      },
      {
        id: "status",
        accessorFn: (device) => (isOnline(device) ? "online" : "offline"),
        header: "Status",
        cell: ({ row }) => <OnlineBadge online={isOnline(row.original)} />,
      },
      {
        accessorKey: "lastSeen",
        header: "Last seen",
        cell: ({ row }) => relativeTime(row.original.lastSeen),
        meta: { className: "hidden sm:table-cell text-muted-foreground" },
      },
    ],
    [],
  );

  const table = useTable({
    features,
    data: devices,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    initialState: { pagination: { pageIndex: 0, pageSize: 10 } },
  });

  if (devices.length === 0) {
    return (
      <EmptyState
        title="No hosts yet"
        description="Enroll an agent, or load the sample fleet to see the console with data."
        icon={Monitor}
        action={<Link href="/enroll" className="text-sm font-medium underline">Install an agent</Link>}
      />
    );
  }

  return (
    <div className="space-y-3">
      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={globalFilter}
          onChange={(event) => setGlobalFilter(event.target.value)}
          placeholder="Search hosts, platforms, users…"
          className="pl-9"
          aria-label="Search hosts"
        />
      </div>
      <div className="overflow-x-auto rounded-xl border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  const meta = header.column.columnDef.meta as { className?: string } | undefined;
                  return (
                    <TableHead key={header.id} className={meta?.className}>
                      {header.isPlaceholder ? null : (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className="inline-flex items-center gap-1.5 font-medium hover:text-foreground"
                        >
                          <table.FlexRender header={header} />
                          {sorted === "asc" ? <ArrowUp className="size-3.5" /> : sorted === "desc" ? (
                            <ArrowDown className="size-3.5" />
                          ) : <ChevronsUpDown className="size-3.5 opacity-40" />}
                        </button>
                      )}
                    </TableHead>
                  );
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? table.getRowModel().rows.map((row) => (
              <TableRow key={row.id}>
                {row.getAllCells().map((cell) => {
                  const meta = cell.column.columnDef.meta as { className?: string } | undefined;
                  return (
                    <TableCell key={cell.id} className={meta?.className}>
                      <table.FlexRender cell={cell} />
                    </TableCell>
                  );
                })}
              </TableRow>
            )) : (
              <TableRow>
                <TableCell colSpan={columns.length} className="h-28 text-center text-muted-foreground">
                  No hosts match “{globalFilter}”.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>{table.getFilteredRowModel().rows.length} host{table.getFilteredRowModel().rows.length === 1 ? "" : "s"}</span>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>
            Previous
          </Button>
          <span>Page {table.state.pagination.pageIndex + 1} of {Math.max(table.getPageCount(), 1)}</span>
          <Button variant="outline" size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
