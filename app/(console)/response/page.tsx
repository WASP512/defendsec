import { redirect } from "next/navigation";

import { PageHeader } from "@/components/console-ui";
import {
  BreakGlassBanner,
  PendingApprovals,
  PolicySummary,
  RecentDecisions,
} from "@/components/policy-view";
import { isAdminSession, isReadOnlySession } from "@/lib/auth";
import {
  loadBreakGlass,
  loadPendingApprovals,
  loadPolicyDecisions,
  loadPolicyStatus,
  PolicyUnavailableError,
  type BreakGlassStatus,
  type PendingCommand,
  type PolicyDecision,
  type PolicyStatus,
} from "@/lib/response-policy";

export const dynamic = "force-dynamic";

export default async function ResponsePage() {
  // Viewers may read the rules: an operator who cannot see why a command would
  // be refused opens a ticket instead of reading the rule.
  if (!(await isAdminSession()) && !(await isReadOnlySession())) {
    redirect("/login");
  }

  // Fetch inside try, render outside: JSX built in a try block is not covered
  // by it, because React renders later.
  let status: PolicyStatus | null = null;
  let error: string | null = null;

  try {
    status = await loadPolicyStatus();
  } catch (cause) {
    error =
      cause instanceof PolicyUnavailableError
        ? cause.message
        : "Could not read the response policy.";
  }

  // These need a database; a deployment without one still shows the rules,
  // which is the point of the page. Each is settled independently so one
  // missing piece does not blank the others.
  const settle = async <T,>(
    load: () => Promise<T>,
    fallback: T,
  ): Promise<T> => {
    try {
      return await load();
    } catch {
      return fallback;
    }
  };
  const [decisions, pending, breakGlass] = await Promise.all([
    settle<PolicyDecision[]>(loadPolicyDecisions, []),
    settle<PendingCommand[]>(loadPendingApprovals, []),
    settle<BreakGlassStatus | null>(loadBreakGlass, null),
  ]);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        title="Response policy"
        description={
          <>
            Deny by default. A command no rule permits is never signed, so it
            cannot run even if the console is bypassed entirely — the agent
            checks a signature that was never produced.
          </>
        }
      />

      <BreakGlassBanner status={breakGlass} />

      {error ? (
        <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </p>
      ) : status ? (
        <PolicySummary status={status} />
      ) : null}

      <PendingApprovals pending={pending} />
      <RecentDecisions decisions={decisions} />
    </div>
  );
}
