import Link from "next/link";
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
  loadHumanApprovals,
  loadPolicyDecisions,
  loadPolicyStatus,
  loadProposals,
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
  // Human requests and AI proposals are split deliberately. They are the
  // same object in storage — neither is signed — but they are not the same
  // thing to review, and showing a proposal in this list as a bare pending
  // command would invite approving it without the reasoning that is the only
  // thing making it reviewable.
  const [decisions, pending, proposals, breakGlass] = await Promise.all([
    settle<PolicyDecision[]>(loadPolicyDecisions, []),
    settle<PendingCommand[]>(loadHumanApprovals, []),
    settle<PendingCommand[]>(loadProposals, []),
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

      {proposals.length > 0 ? (
        <section className="rounded-xl border border-primary/40 bg-primary/5 p-5">
          <h2 className="text-sm font-medium">
            {proposals.length === 1
              ? "1 AI proposal awaiting review"
              : `${proposals.length} AI proposals awaiting review`}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            These are unsigned and cannot run until a human approves them.
            They are reviewed on their own page rather than here, because
            approving one without reading the model&rsquo;s reasoning is the
            failure worth designing against.
          </p>
          <Link
            href="/proposals"
            className="mt-3 inline-block rounded-md bg-foreground px-3 py-1.5 text-sm text-background"
          >
            Review proposals
          </Link>
        </section>
      ) : null}

      <RecentDecisions decisions={decisions} />
    </div>
  );
}
