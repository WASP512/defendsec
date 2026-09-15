import { redirect } from "next/navigation";

import { ComplianceView, FrameworkPicker } from "@/components/compliance-view";
import { PageHeader } from "@/components/console-ui";
import { isAdminSession, isReadOnlySession } from "@/lib/auth";
import {
  ComplianceUnavailableError,
  loadAssessment,
  loadFrameworks,
} from "@/lib/compliance";

export const dynamic = "force-dynamic";

export default async function CompliancePage({
  searchParams,
}: {
  searchParams: Promise<{ framework?: string; periodId?: string }>;
}) {
  // Viewers are allowed here: the person assembling evidence before an audit
  // is often not the person allowed to isolate a host.
  if (!(await isAdminSession()) && !(await isReadOnlySession())) {
    redirect("/login");
  }

  const params = await searchParams;
  let frameworks;
  try {
    frameworks = await loadFrameworks();
  } catch (error) {
    return (
      <div className="mx-auto max-w-4xl space-y-6">
        <PageHeader
          title="Compliance"
          description="Per-control status for an audit period."
        />
        <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {error instanceof ComplianceUnavailableError
            ? error.message
            : "Could not load the control catalog."}
        </p>
      </div>
    );
  }

  const framework = params.framework ?? frameworks[0]?.id ?? "cis-v8";

  // Fetch inside the try, render outside it: JSX built in a try block is not
  // actually covered by it, because React renders later.
  let assessment = null;
  let assessmentError = null;
  try {
    assessment = await loadAssessment(framework, params.periodId);
  } catch (error) {
    assessmentError =
      error instanceof ComplianceUnavailableError
        ? error.message
        : "Could not assess this period.";
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        title="Compliance"
        description={
          <>
            Per-control status over an audit window, with the evidence behind it
            and what DefendSec cannot evidence stated plainly. No overall score
            is given — a percentage lets a control nobody has looked at
            disappear into a rounding error.
          </>
        }
      />
      <FrameworkPicker
        frameworks={frameworks}
        active={framework}
        periodId={params.periodId}
      />
      {assessment ? (
        <ComplianceView assessment={assessment} />
      ) : (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm">
          {assessmentError} The audit layer needs a configured database.
        </p>
      )}
    </div>
  );
}
