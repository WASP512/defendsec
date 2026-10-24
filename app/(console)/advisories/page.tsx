import Link from "next/link";
import { FindingActions } from "@/components/finding-actions";
import { CoverageBanner, FindingSummary } from "@/components/finding-summary";
import { ActivityItem, ActivityList, EmptyState, PageHeader } from "@/components/console-ui";
import { FeedAgeBanner } from "@/components/feed-age-banner";
import { ensureStore } from "@/lib/store";
import { getFeedStatus } from "@/lib/feeds";
import { getFindings, getFindingsSummary } from "@/lib/findings";
import { findingStatus } from "@/lib/findings-model";
import { listAlerts } from "@/lib/alerts";
import { isReadOnlySession } from "@/lib/auth";
import { ShieldCheck } from "lucide-react";

export const dynamic = "force-dynamic";

export default async function AdvisoriesPage() {
  const store = await ensureStore();
  const readOnly = await isReadOnlySession();
  const [feedStatus, result, summaries, vulnAlerts] = await Promise.all([
    getFeedStatus(),
    getFindings({ kind: "finding", limit: 500 }),
    getFindingsSummary(),
    listAlerts({ kind: "vuln", status: "open", limit: 500 }).catch(
      () => [] as Awaited<ReturnType<typeof listAlerts>>,
    ),
  ]);
  const alertBySource = new Map(vulnAlerts.map((alert) => [`${alert.deviceId}:${alert.sourceId}`, alert]));
  const findings = result?.findings ?? [];
  const unassessed = summaries ? [...summaries.values()].filter((s) => s.coverage !== "covered").length : 0;
  const unfixed = summaries ? [...summaries.values()].reduce((n, s) => n + s.unfixed, 0) : 0;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Advisories"
        description={
          <>
            Installed packages matched against the advisories your distribution publishes
            (synced by <code>defendsec-feeds</code>), using the distribution&apos;s own fixed versions, so a
            backported fix is not reported as a vulnerability. Most urgent first: CISA KEV, then severity,
            then EPSS. KEV and critical findings also raise <code>vuln</code> alerts.
          </>
        }
      />
      <FeedAgeBanner status={feedStatus} />
      {result === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Findings unavailable",
            detail:
              "The control plane could not be reached, or it is older than the findings API. An empty page here would not mean the fleet is clean.",
          }}
        />
      ) : null}
      {unassessed > 0 ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: `${unassessed} host${unassessed === 1 ? "" : "s"} not assessed`,
            detail:
              "No advisory feed covers these hosts' distribution and release, or the agent did not report one, so they have no findings because nothing was checked. Open a host to see which.",
          }}
        />
      ) : null}
      {result?.truncated ? (
        <p className="text-sm text-muted-foreground">Showing the first {result.total} findings, most urgent first.</p>
      ) : null}
      {result !== null && findings.length === 0 ? (
        <EmptyState
          title="No findings with a fix available"
          description={
            unfixed > 0
              ? `No assessed host has a vulnerability with a fix to install. ${unfixed} finding${unfixed === 1 ? " has" : "s have"} no fix published yet; they are listed on each host.`
              : "No assessed host has a vulnerability with a fix to install."
          }
          icon={ShieldCheck}
        />
      ) : (
        <ActivityList>
          {findings.map((finding) => {
            const status = findingStatus(finding.key, store.triages);
            const alert = alertBySource.get(`${finding.deviceId}:${finding.advisoryId}`);
            return (
              <ActivityItem
                key={finding.id}
                tone={finding.kev || finding.severity === "critical" || finding.severity === "high" ? "critical" : "warning"}
                title={
                  <div className="space-y-1">
                    <FindingSummary finding={finding} status={status} showHost />
                    {alert ? (
                      <Link
                        href={`/alerts?kind=vuln&deviceId=${finding.deviceId}`}
                        className="text-xs underline text-muted-foreground"
                      >
                        vuln alert
                      </Link>
                    ) : null}
                  </div>
                }
                actions={!readOnly ? <FindingActions findingKey={finding.key} status={status} /> : null}
              />
            );
          })}
        </ActivityList>
      )}
    </div>
  );
}
