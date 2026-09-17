import { redirect } from "next/navigation";

import { PageHeader } from "@/components/console-ui";
import { ProposalList } from "@/components/proposal-view";
import { isAdminSession, isReadOnlySession } from "@/lib/auth";
import { loadProposals, type PendingCommand } from "@/lib/response-policy";

export const dynamic = "force-dynamic";

export default async function ProposalsPage() {
  const admin = await isAdminSession();
  // Viewers may read proposals. Someone without response authority arguing
  // about whether a recommendation is sound is the review process working.
  if (!admin && !(await isReadOnlySession())) {
    redirect("/login");
  }

  // Fetch inside try, render outside: JSX built in a try block is not covered
  // by it, because React renders later.
  let proposals: PendingCommand[] = [];
  let error: string | null = null;
  try {
    proposals = await loadProposals();
  } catch {
    error =
      "Could not read proposals. They need a configured database and a running control plane.";
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        title="Proposals"
        description={
          <>
            Responses an AI agent has recommended and a human has not yet
            approved. Each one is recorded <strong>unsigned</strong> — no
            signature exists for it and none can be produced until somebody
            approves it here. The model&rsquo;s case is shown before the
            controls, because a proposal approved without its reasoning is the
            one thing this page exists to prevent.
          </>
        }
      />
      {error ? (
        <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </p>
      ) : (
        <ProposalList proposals={proposals} canApprove={admin} />
      )}
    </div>
  );
}
