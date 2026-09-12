"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Filter, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export type VersionRow = {
  packageName: string;
  version: string;
  hostname: string;
  deviceId: string;
  mixed: boolean;
};

export function VersionTable({ rows }: { rows: VersionRow[] }) {
  const [query, setQuery] = useState("");
  const [mixedOnly, setMixedOnly] = useState(false);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (mixedOnly && !row.mixed) return false;
      return !needle || `${row.packageName} ${row.version} ${row.hostname}`.toLowerCase().includes(needle);
    });
  }, [mixedOnly, query, rows]);

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative w-full max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search packages, versions, hosts…"
            className="pl-9"
            aria-label="Search software versions"
          />
        </div>
        <Button
          type="button"
          variant={mixedOnly ? "default" : "outline"}
          size="sm"
          onClick={() => setMixedOnly((value) => !value)}
          aria-pressed={mixedOnly}
        >
          <Filter />
          Mixed versions only
        </Button>
      </div>
      <div className="overflow-hidden rounded-xl border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Package</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Host</TableHead>
              <TableHead className="text-right">Consistency</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length ? (
              filtered.map((row) => (
                <TableRow key={`${row.packageName}-${row.deviceId}-${row.version}`}>
                  <TableCell className="font-medium">{row.packageName}</TableCell>
                  <TableCell className="font-mono text-xs">{row.version}</TableCell>
                  <TableCell>
                    <Link href={`/devices/${row.deviceId}`} className="hover:underline">
                      {row.hostname}
                    </Link>
                  </TableCell>
                  <TableCell className="text-right">
                    {row.mixed ? <Badge variant="secondary">mixed</Badge> : <span className="text-muted-foreground">aligned</span>}
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={4} className="h-28 text-center text-muted-foreground">
                  No software versions match these filters.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <p className="text-sm text-muted-foreground">
        Showing {filtered.length} of {rows.length} version records.
      </p>
    </div>
  );
}
