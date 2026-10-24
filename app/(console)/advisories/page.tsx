import { ExposureDetail } from "@/components/exposure-detail";
import { SurfaceExposureDetail } from "@/components/surface-exposure-detail";
import { ExposureDrawer } from "@/components/exposure-drawer";
import { ExposureList, ExposureTabs } from "@/components/exposure-list";
import { CoverageBanner } from "@/components/finding-summary";
import { PageHeader } from "@/components/console-ui";
import { FeedAgeBanner } from "@/components/feed-age-banner";
import { KevWatchCallout } from "@/components/fix-this-week";
import { isReadOnlySession } from "@/lib/auth";
import { ensureStore } from "@/lib/store";
import { getFeedStatus } from "@/lib/feeds";
import { getExposureAdvisory, getExposurePage, getExposureSummary } from "@/lib/exposure";
import { closeDrawerHref, parseExposureQuery } from "@/lib/exposure-model";
import { fixTotal, isSurfaceResponse } from "@/lib/surface-exposure";

export const dynamic = "force-dynamic";

type Search = Promise<Record<string, string | string[] | undefined>>;

/**
 * The exposure list: what is exploitable right now, ranked KEV, then EPSS,
 * then CVSS, with the reason each row is where it is. The control plane ranks
 * and pages it; this page asks for one page at a time. A row opens a drawer
 * with the hosts, the installed and fixed versions, and the feed snapshot the
 * finding came from.
 */
export default async function AdvisoriesPage({ searchParams }: { searchParams: Search }) {
  const query = parseExposureQuery(await searchParams);
  const store = await ensureStore();
  const readOnly = await isReadOnlySession();
  const [feedStatus, page, summary, detail] = await Promise.all([
    getFeedStatus(),
    getExposurePage(query),
    getExposureSummary(1),
    query.advisory ? getExposureAdvisory(query.advisory, query.bucket, query.status) : Promise.resolve(null),
  ]);
  const group = page?.findings.find((g) => g.advisoryId === query.advisory) ?? null;
  const surfaceDetail = isSurfaceResponse(detail) ? detail : null;
  const vulnDetail = detail && !isSurfaceResponse(detail) ? detail : null;
  const unassessed = summary?.hosts.notAssessed ?? 0;
  const watchTotal = summary ? summary.watch.unfixed.findings + summary.watch.awaitingVendor.findings : 0;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Exposure"
        description={
          <>
            What to fix, most urgent first: vulnerabilities attackers are using (CISA KEV, newest first), then
            critical and high findings on your external surface (an open SMB port, an expired certificate: live
            for anyone on the internet), then by EPSS, then CVSS. Medium and low external findings rank with the
            vulnerabilities that have no EPSS score. Only findings with something to fix are on the fix
            list; the rest wait on the watch list. Fixed versions are the distribution&apos;s own, so a backported
            fix is not reported as a vulnerability.
          </>
        }
      />
      <FeedAgeBanner status={feedStatus} />
      {summary ? <KevWatchCallout summary={summary} /> : null}
      {page === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Exposure unavailable",
            detail:
              "The control plane could not be reached, or it is older than the exposure API. An empty page here would not mean the fleet is clean.",
          }}
        />
      ) : null}
      {unassessed > 0 ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: `${unassessed} host${unassessed === 1 ? "" : "s"} not assessed`,
            detail:
              "No advisory feed covers these hosts' distribution and release, the agent did not report one, or no match has run yet, so they have no findings because nothing was checked. Open a host to see which.",
          }}
        />
      ) : null}
      <ExposureTabs query={query} fixCount={summary ? fixTotal(summary.fixable) : null} />
      {query.bucket === "watch" && query.status === "open" && summary ? (
        <p className="text-sm text-muted-foreground">
          {watchTotal} finding{watchTotal === 1 ? "" : "s"} across the fleet have nothing to install yet:{" "}
          {summary.watch.unfixed.findings} with no fix published, {summary.watch.awaitingVendor.findings} fixed by Red
          Hat and awaiting Rocky or AlmaLinux. They are never counted as work for this week.
        </p>
      ) : null}
      {page ? <ExposureList query={query} page={page} /> : null}

      {query.advisory ? (
        <ExposureDrawer
          title={surfaceDetail ? surfaceDetail.detail.finding.title : group?.cve || vulnDetail?.advisory?.cve || query.advisory}
          description={
            surfaceDetail
              ? "What the scan saw, how long it has been open, and how to fix it."
              : "Where this finding came from and which hosts it is on."
          }
          closeHref={closeDrawerHref(query)}
        >
          {surfaceDetail ? (
            <SurfaceExposureDetail group={group} response={surfaceDetail} />
          ) : vulnDetail ? (
            <ExposureDetail group={group} detail={vulnDetail} triages={store.triages} readOnly={readOnly} />
          ) : (
            <p className="text-sm text-muted-foreground">
              No open findings for this advisory in this list. It may have been resolved, or moved to another list.
            </p>
          )}
        </ExposureDrawer>
      ) : null}
    </div>
  );
}
