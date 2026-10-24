import Link from "next/link";
import { KeyRound } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/console-ui";
import { SeverityBadge } from "@/components/status-badge";
import { checkLabel, providerLabel, runResultLabel, type IdentityFinding, type IdentityRun } from "@/lib/identity-model";
import { agoLabel } from "@/lib/surface-exposure";
import { cn } from "@/lib/utils";

/** Switch between the providers' pages. */
export function IdentityTabs({ active }: { active: "m365" | "google" }) {
  const tabs = [
    { id: "m365", href: "/identity", label: providerLabel("m365") },
    { id: "google", href: "/identity/google", label: providerLabel("google") },
  ] as const;
  return (
    <nav className="flex gap-1 border-b" aria-label="Identity providers" data-identity-tabs>
      {tabs.map((t) => (
        <Link
          key={t.id}
          href={t.href}
          aria-current={t.id === active ? "page" : undefined}
          className={cn(
            "-mb-px border-b-2 px-3 py-2 text-sm",
            t.id === active ? "border-foreground font-medium" : "border-transparent text-muted-foreground hover:text-foreground",
          )}
        >
          {t.label}
        </Link>
      ))}
    </nav>
  );
}

/**
 * The open findings of one provider. An empty list says nothing about the accounts
 * until a read has assessed the checks, and the empty state says so.
 */
export function IdentityFindingsSection({
  findings,
  lastStatus,
  noun,
  now,
}: {
  findings: IdentityFinding[] | null;
  lastStatus: string | undefined;
  /** "tenant" or "domain". */
  noun: string;
  now: number;
}) {
  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold">Open findings</h2>
      {findings === null ? (
        <p className="text-sm text-muted-foreground">The findings could not be read.</p>
      ) : findings.length === 0 ? (
        <EmptyState
          title={lastStatus ? "No identity finding is open" : "Nothing has been read yet"}
          description={
            lastStatus === "ok"
              ? "The latest read assessed every check and found nothing. Anything listed under “What this does not cover” was not looked at."
              : `An empty list says nothing about the accounts until a read has assessed the checks. Connect the ${noun} and read it.`
          }
          icon={KeyRound}
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Account or rule</TableHead>
                <TableHead className="hidden md:table-cell">Check</TableHead>
                <TableHead className="hidden md:table-cell">First seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((f) => (
                <TableRow key={f.key} data-identity-finding={f.findingId}>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="max-w-md">
                    <Link href={`/advisories?advisory=${encodeURIComponent(f.key)}`} className="font-medium hover:underline">
                      {f.title}
                    </Link>
                    {f.unconfirmed ? (
                      <Badge variant="outline" className="ml-2" title="The latest read could not cover this; shown from the last confirmation">
                        not confirmed lately
                      </Badge>
                    ) : null}
                  </TableCell>
                  <TableCell className="break-all">{f.subjectLabel}</TableCell>
                  <TableCell className="hidden md:table-cell">{checkLabel(f.check, f.provider)}</TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell" title={f.firstSeen}>
                    {agoLabel(f.firstSeen, now)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

/** The history of reads of one provider. */
export function IdentityRunsSection({ runs, now }: { runs: IdentityRun[] | null; now: number }) {
  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold">Recent reads</h2>
      {runs === null || runs.length === 0 ? (
        <p className="text-sm text-muted-foreground">{runs === null ? "The history could not be read." : "No read yet."}</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Finished</TableHead>
                <TableHead>Result</TableHead>
                <TableHead className="hidden md:table-cell">Opened / closed</TableHead>
                <TableHead className="hidden md:table-cell">Requests</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((r) => (
                <TableRow key={r.id}>
                  <TableCell title={r.finishedAt}>{agoLabel(r.finishedAt, now)}</TableCell>
                  <TableCell>
                    <Badge variant={r.status === "ok" ? "default" : "outline"}>{runResultLabel(r.status)}</Badge>
                    {r.reason ? <span className="mt-1 block max-w-md text-xs text-muted-foreground">{r.reason}</span> : null}
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    {r.opened} opened, {r.resolved} closed, {r.findingsOpen} open
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{r.requests}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}
