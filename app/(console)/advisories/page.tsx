import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/status-badge";
import { FindingActions } from "@/components/finding-actions";
import { ensureStore } from "@/lib/store";
import { allFindings, severityRank } from "@/lib/advisories";
import { loadAdvisories } from "@/lib/advisories-db";

import { loadFleet } from "@/lib/mtls-agents";
import { getOsvLastIngest } from "@/lib/meta";
import { listAlerts } from "@/lib/alerts";
import { relativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function AdvisoriesPage() {
  const store = await ensureStore();
  const [advisories, osvLastIngest, vulnAlerts] = await Promise.all([
    loadAdvisories(),
    getOsvLastIngest(),
    listAlerts({ kind: "vuln", status: "open", limit: 500 }),
  ]);
  const alertBySource = new Map(
    vulnAlerts.map((alert) => [`${alert.deviceId}:${alert.sourceId}`, alert]),
  );
  const findings = allFindings(await loadFleet(store.devices), store.triages, advisories).sort(
    (a, b) =>
      severityRank(a.advisory.severity) - severityRank(b.advisory.severity) ||
      a.hostname.localeCompare(b.hostname),
  );

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Advisories</h1>
        <p className="mt-1 max-w-2xl text-muted-foreground">
          CVE matches from the Postgres advisories catalog (OSV ingest or bundled fallback).
          High/critical matches also raise <code>vuln</code> alerts on inventory report.
        </p>
        {osvLastIngest ? (
          <p className="mt-2 text-sm text-muted-foreground">
            Last OSV ingest: {relativeTime(osvLastIngest)} ({osvLastIngest})
          </p>
        ) : null}
      </div>
      {findings.length === 0 ? (
        <p className="rounded-xl border border-dashed p-10 text-center text-muted-foreground">
          No advisory matches on reported software.
        </p>
      ) : (
        <ul className="divide-y rounded-xl border">
          {findings.map((finding) => {
            const alert = alertBySource.get(`${finding.deviceId}:${finding.advisory.id}`);
            return (
              <li
                key={`${finding.deviceId}-${finding.advisory.id}-${finding.packageName}`}
                className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-start sm:justify-between"
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{finding.advisory.cve || finding.advisory.id}</span>
                    <SeverityBadge severity={finding.advisory.severity} />
                    {finding.status === "acknowledged" ? (
                      <Badge variant="outline">acknowledged</Badge>
                    ) : (
                      <Badge>open</Badge>
                    )}
                    {alert ? (
                      <Link
                        href={`/alerts?kind=vuln&deviceId=${finding.deviceId}`}
                        className="text-xs underline text-muted-foreground"
                      >
                        vuln alert
                      </Link>
                    ) : null}
                  </div>
                  <p className="text-sm">
                    {finding.packageName} {finding.version} on{" "}
                    <Link href={`/devices/${finding.deviceId}`} className="underline">
                      {finding.hostname}
                    </Link>{" "}
                    (patched floor {finding.advisory.below})
                  </p>
                  <p className="text-sm text-muted-foreground">{finding.advisory.summary}</p>
                </div>
                <FindingActions findingKey={finding.key} status={finding.status} />
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
