import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/status-badge";
import { FindingActions } from "@/components/finding-actions";
import { ActivityItem, ActivityList, EmptyState, PageHeader } from "@/components/console-ui";
import { ensureStore } from "@/lib/store";
import { allFindings, severityRank } from "@/lib/advisories";
import { loadAdvisories } from "@/lib/advisories-db";

import { loadFleet } from "@/lib/mtls-agents";
import { getOsvLastIngest } from "@/lib/meta";
import { listAlerts } from "@/lib/alerts";
import { relativeTime } from "@/lib/format";
import { isReadOnlySession } from "@/lib/auth";
import { ShieldCheck } from "lucide-react";

export const dynamic = "force-dynamic";

export default async function AdvisoriesPage() {
  const store = await ensureStore();
  const readOnly = await isReadOnlySession();
  const [advisories, osvLastIngest, vulnAlerts] = await Promise.all([
    loadAdvisories(),
    getOsvLastIngest(),
    listAlerts({ kind: "vuln", status: "open", limit: 500 }).catch(() => [] as Awaited<
      ReturnType<typeof listAlerts>
    >),
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
      <PageHeader
        title="Advisories"
        description={
          <>
          CVE matches from the Postgres advisories catalog (OSV ingest or bundled fallback).
          High/critical matches also raise <code>vuln</code> alerts on inventory report.
          </>
        }
      />
      <div>
        {osvLastIngest ? (
          <p className="text-sm text-muted-foreground">
            Last OSV ingest: {relativeTime(osvLastIngest)} ({osvLastIngest})
          </p>
        ) : null}
      </div>
      {findings.length === 0 ? (
        <EmptyState
          title="No advisory matches"
          description="Reported software does not match the current vulnerability catalog."
          icon={ShieldCheck}
        />
      ) : (
        <ActivityList>
          {findings.map((finding) => {
            const alert = alertBySource.get(`${finding.deviceId}:${finding.advisory.id}`);
            return (
              <ActivityItem
                key={`${finding.deviceId}-${finding.advisory.id}-${finding.packageName}`}
                tone={finding.advisory.severity === "critical" || finding.advisory.severity === "high" ? "critical" : "warning"}
                title={
                  <>
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
                  </>
                }
                actions={!readOnly ? (
                  <FindingActions findingKey={finding.key} status={finding.status} />
                ) : null}
              />
            );
          })}
        </ActivityList>
      )}
    </div>
  );
}
