import Link from "next/link";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/status-badge";
import {
  fixedLabel,
  hostsLabel,
  kevWatchNotice,
  rankReason,
  watchLabel,
  type ExposureGroup,
  type ExposureSummary,
} from "@/lib/exposure-model";
import { cn } from "@/lib/utils";

function plural(n: number, one: string, many: string = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * Red callout: exploited in the wild and nothing to install, so a patch cannot
 * close it. Shown above the ranked list, with the advisories named. Renders
 * nothing when there is none.
 */
export function KevWatchCallout({ summary }: { summary: ExposureSummary }) {
  const notice = kevWatchNotice(summary.watch.kev.advisories);
  if (!notice) return null;
  return (
    <div
      role="alert"
      data-kev-watch
      className="flex items-start gap-3 rounded-lg border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-900 dark:text-red-200"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 space-y-1">
        <p className="font-medium">{notice.title}</p>
        <p className="opacity-90">{notice.detail}</p>
        <ul className="space-y-0.5 pt-1">
          {summary.kevWatch.map((g) => (
            <li key={g.advisoryId}>
              <Link href={`/advisories?bucket=watch&advisory=${encodeURIComponent(g.advisoryId)}`} className="font-medium underline">
                {g.cve || g.advisoryId}
              </Link>{" "}
              on {plural(g.hostCount, "host")} · {watchLabel(g)}
              {g.kevAdded ? ` · exploited since ${g.kevAdded}` : ""}
            </li>
          ))}
        </ul>
        {summary.watch.kev.advisories > summary.kevWatch.length ? (
          <p className="opacity-90">
            and {summary.watch.kev.advisories - summary.kevWatch.length} more on the{" "}
            <Link href="/advisories?bucket=watch" className="underline">
              watch list
            </Link>
          </p>
        ) : null}
      </div>
    </div>
  );
}

function FixRow({ group, rank }: { group: ExposureGroup; rank: number }) {
  const why = rankReason(group);
  return (
    <li className="flex gap-3 py-3 first:pt-0 last:pb-0" data-fix-row={group.advisoryId}>
      <span className="w-5 shrink-0 pt-0.5 text-right text-sm font-medium tabular-nums text-muted-foreground">{rank}</span>
      <div className="min-w-0 flex-1 space-y-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href={`/advisories?advisory=${encodeURIComponent(group.advisoryId)}`}
            className="font-medium underline-offset-2 hover:underline"
          >
            {group.cve || group.advisoryId}
          </Link>
          <SeverityBadge severity={group.severity} />
          {group.kev ? <Badge variant="destructive">KEV</Badge> : null}
        </div>
        <p className="text-sm">
          <span className={cn("font-medium", group.kev && "text-destructive")}>{why.headline}</span>
          {why.details.map((d) => (
            <span key={d} className="text-muted-foreground">
              {" · "}
              {d}
            </span>
          ))}
        </p>
        <p className="text-sm text-muted-foreground">
          {hostsLabel(group)} · {group.packages.join(", ")} · {fixedLabel(group)}
        </p>
      </div>
    </li>
  );
}

/**
 * The Monday card: the top of the fix list by rank, each with the hosts it is
 * on. An empty list is only good news if every host was actually assessed, so
 * the card says how many were not.
 */
export function FixThisWeekCard({ summary }: { summary: ExposureSummary }) {
  const { fixable, hosts } = summary;
  const rows = summary.fixThisWeek;
  return (
    <Card data-fix-this-week>
      <CardHeader>
        <CardTitle className="text-lg">Fix this week</CardTitle>
        <CardDescription>
          {fixable.advisories === 0
            ? "Nothing with a fix to install."
            : `${plural(fixable.advisories, "vulnerability", "vulnerabilities")} with a fix to install, across ${plural(fixable.hosts, "host")}. The top ${rows.length}, most urgent first:`}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.length === 0 ? (
          <p className="flex items-start gap-2 text-sm">
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-600" />
            {hosts.assessed === 0
              ? "No host has been assessed yet, so this says nothing about the fleet."
              : `Nothing to install on the ${plural(hosts.assessed, "assessed host")}.`}
            {hosts.notAssessed > 0 ? ` ${plural(hosts.notAssessed, "host")} not assessed.` : ""}
          </p>
        ) : (
          <ol className="divide-y">
            {rows.map((g, i) => (
              <FixRow key={g.advisoryId} group={g} rank={i + 1} />
            ))}
          </ol>
        )}
        {fixable.advisories > rows.length ? (
          <Link href="/advisories" className="inline-block text-sm font-medium underline">
            All {fixable.advisories} on the exposure list
          </Link>
        ) : null}
      </CardContent>
    </Card>
  );
}

const SCA_ORDER = ["critical", "high", "medium", "low"];

export type UnsupportedHost = { id: string; hostname: string; os: string };

/**
 * The rest of the Monday list: hosts on an unsupported OS, hosts that have gone
 * quiet, failed configuration checks by severity, and the watch list.
 */
export function AlsoCheckCard({
  summary,
  unsupported,
  unsupportedTotal,
}: {
  summary: ExposureSummary;
  unsupported: UnsupportedHost[];
  unsupportedTotal: number;
}) {
  const sca = summary.sca;
  const severities = [
    ...SCA_ORDER.filter((s) => sca.bySeverity[s]),
    ...Object.keys(sca.bySeverity).filter((s) => !SCA_ORDER.includes(s)),
  ];
  const watchN = summary.watch.unfixed.findings + summary.watch.awaitingVendor.findings;
  return (
    <Card data-also-check>
      <CardHeader>
        <CardTitle className="text-lg">Also check</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <section data-eol-hosts>
          <h3 className="font-medium">Unsupported operating system</h3>
          {unsupportedTotal === 0 ? (
            <p className="text-muted-foreground">No host reports an unsupported OS.</p>
          ) : (
            <>
              <p className="text-destructive">{plural(unsupportedTotal, "host")} no longer get vendor security updates.</p>
              <ul className="text-muted-foreground">
                {unsupported.map((h) => (
                  <li key={h.id}>
                    <Link href={`/devices/${h.id}`} className="underline">
                      {h.hostname}
                    </Link>{" "}
                    · {h.os}
                  </li>
                ))}
                {unsupportedTotal > unsupported.length ? <li>and {unsupportedTotal - unsupported.length} more</li> : null}
              </ul>
            </>
          )}
        </section>
        <section data-silent-hosts>
          <h3 className="font-medium">Silent for more than 7 days</h3>
          {summary.hosts.silent === 0 ? (
            <p className="text-muted-foreground">Every host has reported this week.</p>
          ) : (
            <>
              <p className="text-amber-700 dark:text-amber-400">
                {plural(summary.hosts.silent, "host")} not reporting: findings for them are stale.
              </p>
              <ul className="text-muted-foreground">
                {summary.hosts.silentList.map((h) => (
                  <li key={h.deviceId}>
                    <Link href={`/devices/${h.deviceId}`} className="underline">
                      {h.hostname}
                    </Link>{" "}
                    · last seen {h.lastSeen.slice(0, 10)}
                  </li>
                ))}
                {summary.hosts.silent > summary.hosts.silentList.length ? (
                  <li>and {summary.hosts.silent - summary.hosts.silentList.length} more</li>
                ) : null}
              </ul>
            </>
          )}
        </section>
        <section data-sca>
          <h3 className="font-medium">Failed configuration checks</h3>
          {sca.total === 0 ? (
            <p className="text-muted-foreground">No open failed checks.</p>
          ) : (
            <p className="flex flex-wrap items-center gap-2">
              {severities.map((s) => (
                <Badge key={s} variant={s === "critical" || s === "high" ? "destructive" : "secondary"}>
                  {sca.bySeverity[s]} {s}
                </Badge>
              ))}
              <span className="text-muted-foreground">on {plural(sca.hosts, "host")}</span>
            </p>
          )}
        </section>
        <section data-watch>
          <h3 className="font-medium">Watch: nothing to install yet</h3>
          {watchN === 0 ? (
            <p className="text-muted-foreground">Nothing is waiting on a vendor fix.</p>
          ) : (
            <p className="text-muted-foreground">
              {summary.watch.unfixed.findings} with no fix published, {summary.watch.awaitingVendor.findings} fixed by
              Red Hat and awaiting Rocky/Alma.{" "}
              <Link href="/advisories?bucket=watch" className="underline">
                Watch list
              </Link>
            </p>
          )}
        </section>
      </CardContent>
    </Card>
  );
}
