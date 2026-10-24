import { PageHeader } from "@/components/console-ui";
import { AssetsPanel } from "@/components/assets-panel";
import { CoverageBanner } from "@/components/finding-summary";
import { isReadOnlySession } from "@/lib/auth";
import { getAssets } from "@/lib/surface";

export const dynamic = "force-dynamic";

export default async function AssetsPage() {
  const readOnly = await isReadOnlySession();
  const result = await getAssets();

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <PageHeader
        title="Assets"
        description={
          <>
            The domains, hostnames and public IP addresses you declare for external checks. Each needs a confirmation that
            you are authorised to test it; nothing else is ever scanned. Scans run daily and on demand, and the results
            are on <strong>Surface</strong>.
          </>
        }
      />
      {result === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Assets unavailable",
            detail: "The control plane could not be reached, or it is older than the surface API.",
          }}
        />
      ) : (
        <AssetsPanel assets={result.assets} readOnly={readOnly} />
      )}
    </div>
  );
}
