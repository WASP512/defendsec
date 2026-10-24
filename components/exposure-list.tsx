import Link from "next/link";
import { ShieldCheck, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/console-ui";
import { SeverityBadge } from "@/components/status-badge";
import {
  ageLabel,
  closeDrawerHref,
  drawerHref,
  EXPOSURE_PAGE_SIZE,
  filterHref,
  fixedLabel,
  hostsLabel,
  isRanked,
  nextHref,
  pageNumber,
  prevHref,
  rankReason,
  watchLabel,
  type ExposureListQuery,
  type ExposurePageResponse,
  type Rankable,
} from "@/lib/exposure-model";
import { cn } from "@/lib/utils";

/** The ranking line: why this row is where it is. KEV rows are marked red. */
export function WhyRanksHere({ group }: { group: Rankable }) {
  const why = rankReason(group);
  return (
    <p className="text-sm" data-rank-reason>
      <span className={cn("font-medium", group.kev && "text-destructive")}>{why.headline}</span>
      {why.details.map((d) => (
        <span key={d} className="text-muted-foreground">
          {" · "}
          {d}
        </span>
      ))}
    </p>
  );
}

function Tab({ href, active, children }: { href: string; active: boolean; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "rounded-md border px-3 py-1.5 text-sm",
        active ? "border-primary bg-primary/10 font-medium" : "text-muted-foreground hover:bg-muted",
      )}
    >
      {children}
    </Link>
  );
}

/** Which list is shown: fix this week, the watch list, or what has been resolved. */
export function ExposureTabs({ query, fixCount }: { query: ExposureListQuery; fixCount: number | null }) {
  return (
    <nav aria-label="Exposure lists" className="flex flex-wrap items-center gap-2">
      <Tab href={filterHref("fix", "open")} active={query.bucket === "fix" && query.status === "open"}>
        Fix this week{fixCount === null ? "" : ` · ${fixCount}`}
      </Tab>
      <Tab href={filterHref("watch", "open")} active={query.bucket === "watch" && query.status === "open"}>
        Watch: nothing to install yet
      </Tab>
      <Tab href={filterHref(query.bucket, "resolved")} active={query.status === "resolved"}>
        Resolved
      </Tab>
    </nav>
  );
}

/**
 * The ranked list, one row per advisory with the hosts it affects. Server
 * rendered and paged with a keyset cursor: the control plane ranks and cuts the
 * page, and this component never sees more than EXPOSURE_PAGE_SIZE rows.
 */
export function ExposureList({ query, page }: { query: ExposureListQuery; page: ExposurePageResponse }) {
  const prev = prevHref(query);
  const next = nextHref(query, page.next);
  const first = (pageNumber(query) - 1) * EXPOSURE_PAGE_SIZE;
  const ranked = isRanked(page.findings);
  const watch = query.bucket === "watch";
  const resolved = query.status === "resolved";

  return (
    <div className="space-y-3" data-exposure-list={query.bucket}>
      {!ranked ? (
        <p className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-900 dark:text-amber-200">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" />
          The control plane returned this page out of rank order. The list below may not be in priority order; update
          the control plane and the console together.
        </p>
      ) : null}

      {page.findings.length === 0 ? (
        <EmptyState
          title={
            resolved
              ? "Nothing has been resolved yet"
              : watch
                ? "Nothing on the watch list"
                : "No findings with a fix available"
          }
          description={
            resolved
              ? "A finding appears here after the host's inventory shows the fix, or the package is gone."
              : watch
                ? "No assessed host has a vulnerability that is waiting on a vendor fix."
                : "No assessed host has a vulnerability with a fix to install. Hosts that are not assessed are counted above: an empty list says nothing about them."
          }
          icon={ShieldCheck}
        />
      ) : (
        <ol className="space-y-2">
          {page.findings.map((g, i) => (
            <li
              key={g.advisoryId}
              data-advisory={g.advisoryId}
              className={cn(
                "flex gap-4 rounded-xl border bg-card p-4",
                g.kev && !resolved && "border-destructive/40",
              )}
            >
              <div className="w-8 shrink-0 pt-0.5 text-right text-sm font-medium tabular-nums text-muted-foreground">
                {first + i + 1}
              </div>
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Link
                    href={drawerHref(query, g.advisoryId)}
                    scroll={false}
                    className="font-medium underline-offset-2 hover:underline"
                  >
                    {g.eol ? `${g.eol.productLabel} ${g.eol.cycle}` : g.cve || g.advisoryId}
                  </Link>
                  {g.eol ? (
                    <Badge variant="outline">{g.eol.stage === "eol" ? "End of life" : "Past active support"}</Badge>
                  ) : null}
                  {g.cve && g.cve !== g.advisoryId ? (
                    <span className="text-xs text-muted-foreground">{g.advisoryId}</span>
                  ) : null}
                  <SeverityBadge severity={g.severity} />
                  {g.kev ? <Badge variant="destructive">KEV</Badge> : null}
                  <Badge variant="outline">{resolved ? "resolved" : "open"}</Badge>
                </div>
                <WhyRanksHere group={g} />
                {g.summary ? <p className="text-sm text-muted-foreground">{g.summary}</p> : null}
                <p className="text-sm">
                  {hostsLabel(g)}
                  <span className="text-muted-foreground">
                    {" — "}
                    {g.packages.join(", ")}
                    {watch ? ` · ${watchLabel(g)}` : ` · ${fixedLabel(g)}`}
                  </span>
                </p>
                <p className="text-xs text-muted-foreground">
                  {ageLabel(g.firstSeen, resolved ? g.resolvedAt : null)}
                  {g.findingCount !== g.hostCount ? ` · ${g.findingCount} findings` : ""}
                </p>
              </div>
            </li>
          ))}
        </ol>
      )}

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>
          {page.total === 0
            ? "0 advisories"
            : `${first + 1}–${first + page.findings.length} of ${page.total} ${page.total === 1 ? "advisory" : "advisories"}`}
        </span>
        <div className="flex items-center gap-2">
          {prev ? (
            <Link href={prev} className="rounded-md border px-3 py-1 hover:bg-muted">
              Previous
            </Link>
          ) : null}
          <span>Page {pageNumber(query)}</span>
          {next ? (
            <Link href={next} className="rounded-md border px-3 py-1 hover:bg-muted">
              Next
            </Link>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export { closeDrawerHref };
