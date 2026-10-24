import Link from "next/link";
import { Globe } from "lucide-react";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { SurfaceAssetCard } from "@/components/surface-view";
import { CoverageBanner } from "@/components/finding-summary";
import { getSurfaceFindings } from "@/lib/surface";
import { groupByAsset } from "@/lib/surface-model";

export const dynamic = "force-dynamic";

export default async function SurfacePage() {
  // Closed findings come too: "open on date A, closed on date B" is the point.
  const result = await getSurfaceFindings({ resolved: true, limit: 2000 });
  const groups = result ? groupByAsset(result.assets, result.findings) : [];

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Surface"
        description={
          <>
            What the internet sees of your declared domains, hostnames and IP addresses: email authentication, DNS, TLS
            certificates and reachable ports, checked from outside. Most urgent first. Add or confirm assets on{" "}
            <Link href="/assets" className="underline">
              Assets
            </Link>
            .
          </>
        }
      />
      {result === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Surface findings unavailable",
            detail:
              "The control plane could not be reached, or it is older than the surface API. An empty page here would not mean nothing is exposed.",
          }}
        />
      ) : null}
      {result !== null && groups.length === 0 ? (
        <EmptyState
          title="No assets declared"
          description={
            <>
              Nothing is checked until you declare an asset and confirm you are authorised to test it. Start on the{" "}
              <Link href="/assets" className="underline">
                Assets
              </Link>{" "}
              page.
            </>
          }
          icon={Globe}
        />
      ) : null}
      {result?.truncated ? (
        <p className="text-sm text-muted-foreground">Showing the first {result.total} findings, most urgent first.</p>
      ) : null}
      <div className="space-y-4">
        {groups.map((g) => (
          <SurfaceAssetCard key={g.asset.id} group={g} />
        ))}
      </div>
    </div>
  );
}
