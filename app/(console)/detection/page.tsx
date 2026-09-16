import { redirect } from "next/navigation";

import { PageHeader } from "@/components/console-ui";
import { DetectionView } from "@/components/detection-view";
import { isAdminSession, isReadOnlySession } from "@/lib/auth";
import {
  DetectionUnavailableError,
  loadDetectionCoverage,
  loadForwardingStatus,
} from "@/lib/detection-server";

export const dynamic = "force-dynamic";

export default async function DetectionPage() {
  // Viewers are allowed: knowing what the fleet cannot see is exactly the
  // sort of thing someone without response authority needs to be able to
  // read and argue about.
  if (!(await isAdminSession()) && !(await isReadOnlySession())) {
    redirect("/login");
  }

  let coverage = null;
  let error = null;
  try {
    coverage = await loadDetectionCoverage();
  } catch (cause) {
    error =
      cause instanceof DetectionUnavailableError
        ? cause.message
        : "Could not load detection coverage from the control plane.";
  }

  // Admin-only on the control plane; a viewer simply gets null and the
  // forwarding section is left out rather than shown broken.
  const forwarding = coverage ? await loadForwardingStatus() : null;

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        title="Detection"
        description={
          <>
            What the behavioural rules can see, and — more usefully — what they
            cannot. Blind spots come first: rules that cannot fire because no
            sensor reports their event kind, rules that failed to load, and
            hosts that dropped events. No coverage percentage is given, because
            ATT&amp;CK has no denominator that would make one honest.
          </>
        }
      />
      {coverage ? (
        <DetectionView coverage={coverage} forwarding={forwarding} />
      ) : (
        <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
