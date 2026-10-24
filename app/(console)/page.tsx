import { DeviceTable } from "@/components/device-table";
import { DeviceList } from "@/components/device-list";
import { parseDeviceListQuery } from "@/lib/device-list";
import { loadDevicePage } from "@/lib/devices-server";
import { SampleToggle } from "@/components/sample-toggle";
import { PageHeader, StatCard } from "@/components/console-ui";
import { CoverageBanner } from "@/components/finding-summary";
import { FeedAgeBanner } from "@/components/feed-age-banner";
import { AlsoCheckCard, FixThisWeekCard, KevWatchCallout } from "@/components/fix-this-week";
import { ExposureTrendCard } from "@/components/exposure-trend-card";
import { SurfaceSummaryCard } from "@/components/surface-summary-card";
import { IdentitySummaryCard } from "@/components/identity-summary-card";
import { RmmSummaryCard } from "@/components/rmm-summary-card";
import { getRmmDevices, getRmmStatus } from "@/lib/rmm";
import { rmmCard, unsupportedRmm } from "@/lib/rmm-model";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadFleet, loadMtlsFimEvents } from "@/lib/mtls-agents";
import { isOnline } from "@/lib/policies";
import { isUnreliable, patchReliabilityOf, unreliableHostsNote } from "@/lib/patch-reliability";
import { fleetAggregates } from "@/lib/fleet-aggregates";
import { getFindingsSummary } from "@/lib/findings";
import { getFeedStatus } from "@/lib/feeds";
import { getExposureSummary, getExposureTrend } from "@/lib/exposure";
import { parseTrendQuery } from "@/lib/exposure-model";
import { loadAuditPeriods } from "@/lib/compliance";
import { supportedOs } from "@/lib/supported-os";
import { isReadOnlySession } from "@/lib/auth";
import { FileWarning, MonitorCheck, Package, ShieldAlert } from "lucide-react";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const trendQuery = parseTrendQuery(await searchParams);
  const store = await ensureStore();
  const readOnly = await isReadOnlySession();
  const fleet = await loadFleet(store.devices);
  const fimEvents = [...(await loadMtlsFimEvents()), ...store.fimEvents];
  // The host table is the control plane's first page, not the whole fleet:
  // shipping every host to the browser was 42 MB at 10,000 hosts.
  const firstPage = await loadDevicePage(parseDeviceListQuery({}));
  const online = fleet.filter((d) => isOnline(d)).length;
  const aggregates = fleetAggregates(fleet, store.triages, await getFindingsSummary());
  const failing = aggregates.policies.reduce(
    (n, p) => n + p.failing,
    0,
  );
  const samples = store.devices.some((d) => d.sample);
  // null when the control plane could not be asked: shown as unknown, not zero.
  const serious = aggregates.serious;
  const patches = fleet.reduce((n, d) => n + d.pendingUpdates.length, 0);
  // Hosts whose pending-updates list cannot be believed: a clean count must not be shown for them.
  const patchUnreliable = fleet.filter((d) => isUnreliable(patchReliabilityOf(d))).length;
  // Everything the Monday view needs comes from the control plane a page at a
  // time or as counts; the fleet itself stays on the server.
  const [exposure, trend, feedStatus, periods, rmmStatus] = await Promise.all([
    getExposureSummary(5),
    getExposureTrend(trendQuery),
    getFeedStatus(),
    loadAuditPeriods().catch(() => []),
    getRmmStatus(),
  ]);
  // Windows devices read through Datto RMM are not in the fleet above (they are not
  // agents); their OS support is judged here the same way.
  const rmmDevices = rmmStatus && rmmStatus.summary.devices > 0 ? ((await getRmmDevices()) ?? []) : [];
  // The OS support policy lives in the console (DEFENDSEC_SUPPORTED_OS), so the
  // unsupported hosts are counted here, from the fleet the page already holds.
  const unsupported = fleet
    .filter((d) => !d.sample && supportedOs(d) === false)
    .map((d) => ({ id: d.id, hostname: d.hostname, os: `${d.osName} ${d.osVersion}`.trim() }))
    .concat(unsupportedRmm(rmmDevices.filter((d) => !d.mergedInto)))
    .sort((a, b) => a.hostname.localeCompare(b.hostname));

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <PageHeader
        title="Fleet"
        description={
          <>
            Exposure for the machines you enroll: what is exploitable now (installed
            packages against the security advisories your distribution publishes), what is unpatched,
            and what changed. No MDM lock/wipe, no subscriptions.
          </>
        }
        actions={!readOnly ? (
          <div className="flex flex-wrap gap-2">
            <SampleToggle hasSamples={samples} />
            <Link
              href="/enroll"
              className="inline-flex h-8 items-center rounded-lg bg-primary px-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/80"
            >
              Enroll a host
            </Link>
          </div>
        ) : null}
      />

      <FeedAgeBanner status={feedStatus} />
      {exposure ? <KevWatchCallout summary={exposure} /> : null}
      {exposure === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Exposure unavailable",
            detail:
              "The control plane could not be reached, or it is older than the exposure API. Nothing below says the fleet is clean.",
          }}
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <FixThisWeekCard summary={exposure} />
          </div>
          <div className="space-y-4">
            <SurfaceSummaryCard summary={exposure.surface} />
            <IdentitySummaryCard summary={exposure.identity} />
            {rmmCard(rmmStatus).state !== "not-configured" ? <RmmSummaryCard status={rmmStatus} /> : null}
            <AlsoCheckCard summary={exposure} unsupported={unsupported.slice(0, 5)} unsupportedTotal={unsupported.length} />
          </div>
        </div>
      )}
      <ExposureTrendCard trend={trend} query={trendQuery} periods={periods} />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Hosts online"
          value={online}
          subtitle={`${fleet.length} enrolled`}
          icon={MonitorCheck}
          tone={online === fleet.length && fleet.length > 0 ? "good" : "neutral"}
        />
        <StatCard
          title="Fix these"
          value={serious ?? "?"}
          subtitle={
            serious === null
              ? "Findings unavailable from the control plane"
              : "Open critical, high or KEV findings with a fix"
          }
          icon={ShieldAlert}
          tone={serious === null ? "neutral" : serious > 0 ? "critical" : "good"}
        />
        <StatCard
          title="Pending patches"
          value={patches}
          subtitle={
            patchUnreliable > 0
              ? `${unreliableHostsNote(patchUnreliable)} The count is a floor.`
              : "Updates reported across the fleet"
          }
          icon={Package}
          tone={patches > 0 || patchUnreliable > 0 ? "warning" : "good"}
        />
        <StatCard
          title="Integrity events"
          value={fimEvents.length}
          subtitle={`${failing} policy check${failing === 1 ? "" : "s"} failing`}
          icon={FileWarning}
          tone={fimEvents.length > 0 ? "critical" : "good"}
        />
      </div>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Hosts</h2>
          <Link href="/devices" className="text-sm text-muted-foreground underline">
            View all
          </Link>
        </div>
        {"page" in firstPage ? (
          <DeviceList query={parseDeviceListQuery({})} page={firstPage.page} />
        ) : (
          <DeviceTable devices={fleet.slice(0, 200).map(publicDevice)} />
        )}
      </section>
    </div>
  );
}
