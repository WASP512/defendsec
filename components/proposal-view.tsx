"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

// Imported from proposals.ts rather than response-policy.ts: this is a
// client component, and response-policy imports next/headers.
import { isProposal, type PendingCommand } from "@/lib/proposals";

// The proposal review surface (roadmap 4.2).
//
// A proposal and a human request awaiting approval are the same object in
// storage — neither carries a signature, which is the point. They are not the
// same thing to review, and this page exists because of one specific failure
// mode: approving an AI proposal from a queue that shows it as a bare pending
// command, without the reasoning that is the only thing making it reviewable.
//
// So the model's case comes first, before the approve control. An operator
// who has scrolled past the reasoning to reach the button has at least been
// shown it.

function prettyPayload(raw: string): string {
  if (!raw || raw === "{}") return "";
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 text-sm">{children}</dd>
    </div>
  );
}

function ProposalCard({
  proposal,
  canApprove,
}: {
  proposal: PendingCommand;
  canApprove: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [outcome, setOutcome] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  const act = async (reject: boolean) => {
    setOutcome(null);
    setFailed(false);
    try {
      const res = await fetch("/api/approvals", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ pendingId: proposal.id, reject }),
      });
      const body = (await res.json()) as {
        status?: string;
        detail?: string;
        reason?: string;
        error?: string;
      };
      if (!res.ok) {
        setFailed(true);
        // The control plane's own wording, not a friendlier local version:
        // a refusal here is recorded in the ledger as the control plane
        // phrased it, and a second account of it would not match.
        setOutcome(body.error ?? body.reason ?? `Refused (${res.status}).`);
        return;
      }
      setOutcome(body.detail ?? body.status ?? "Recorded.");
      startTransition(() => router.refresh());
    } catch {
      setFailed(true);
      setOutcome("Could not reach the control plane.");
    }
  };

  const payload = prettyPayload(proposal.payload);
  const evidence = proposal.proposalEvidence ?? [];

  return (
    <li className="rounded-xl border bg-background p-5">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-[11px] text-primary">
          AI proposal
        </span>
        <code className="text-sm font-medium">{proposal.commandType}</code>
        <span className="text-sm text-muted-foreground">
          on {proposal.hostname || proposal.deviceId}
        </span>
        <span className="text-xs text-muted-foreground">
          {proposal.approvals.length} of {proposal.requiredApprovals} approvals
        </span>
      </div>

      <p className="mt-2 text-xs text-muted-foreground">
        Not signed. No signature exists for this command and none can be
        produced until a human approves it.
      </p>

      {/* The case, before the controls. */}
      <section className="mt-4 rounded-lg border-l-2 border-primary/40 bg-muted/30 py-3 pl-4">
        <h3 className="text-xs font-medium text-muted-foreground">
          What the model argued
        </h3>
        <p className="mt-1 text-sm whitespace-pre-wrap">
          {proposal.proposalReasoning || "No reasoning was recorded."}
        </p>
        {evidence.length > 0 ? (
          <div className="mt-3">
            <h3 className="text-xs font-medium text-muted-foreground">
              Evidence it cited
            </h3>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {evidence.map((e) => (
                <li
                  key={e}
                  className="rounded border bg-background px-1.5 py-0.5 font-mono text-[11px]"
                >
                  {e}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {proposal.proposalPrompt ? (
          <div className="mt-3">
            <h3 className="text-xs font-medium text-muted-foreground">
              What it says it was asked to do
            </h3>
            <p className="mt-1 text-sm whitespace-pre-wrap text-muted-foreground">
              {proposal.proposalPrompt}
            </p>
          </div>
        ) : null}
      </section>

      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
        <Field label="Proposed by">
          <code className="text-xs">{proposal.requestedBy}</code>
        </Field>
        <Field label="Model">
          {proposal.proposalModel ? (
            <span title="Self-reported by the operator who registered this principal. DefendSec cannot verify which model is behind a token.">
              <code className="text-xs">{proposal.proposalModel}</code>
              <span className="ml-1 text-[11px] text-muted-foreground">
                (self-reported)
              </span>
            </span>
          ) : (
            <span className="text-muted-foreground">not declared</span>
          )}
        </Field>
        <Field label="Policy rule">
          {proposal.ruleId ? (
            <code className="text-xs">{proposal.ruleId}</code>
          ) : (
            <span className="text-muted-foreground">none named</span>
          )}
        </Field>
        <Field label="Expires">
          {new Date(proposal.expiresAt)
            .toISOString()
            .replace("T", " ")
            .slice(0, 16)}
          {" UTC"}
        </Field>
      </dl>

      <div className="mt-4">
        <h3 className="text-xs font-medium text-muted-foreground">
          The exact command
        </h3>
        <pre className="mt-1 overflow-x-auto rounded-lg border bg-muted/40 p-3 text-xs">
          {proposal.commandType}
          {payload ? `\n${payload}` : "\n(no arguments)"}
        </pre>
      </div>

      {canApprove ? (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={pending}
            onClick={() => act(false)}
            className="rounded-md bg-foreground px-3 py-1.5 text-sm text-background disabled:opacity-50"
          >
            Approve and sign
          </button>
          <button
            type="button"
            disabled={pending}
            onClick={() => act(true)}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
          >
            Reject
          </button>
          <span className="text-xs text-muted-foreground">
            Policy is re-evaluated at the moment of signing, so an approval is
            not a guarantee this will issue.
          </span>
        </div>
      ) : (
        <p className="mt-4 text-xs text-muted-foreground">
          You have read-only access. Approving requires an administrator.
        </p>
      )}

      {outcome ? (
        <p
          className={`mt-3 rounded-md border p-2 text-xs ${
            failed
              ? "border-destructive/40 bg-destructive/10 text-destructive"
              : "border-emerald-500/40 bg-emerald-500/10"
          }`}
        >
          {outcome}
        </p>
      ) : null}
    </li>
  );
}

export function ProposalList({
  proposals,
  canApprove,
}: {
  proposals: PendingCommand[];
  canApprove: boolean;
}) {
  const agentOnly = proposals.filter(isProposal);

  if (agentOnly.length === 0) {
    return (
      <div className="rounded-xl border border-dashed bg-muted/20 p-6 text-center">
        <p className="text-sm font-medium">No proposals awaiting review.</p>
        <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
          An agent that has been registered and permitted by policy can record
          proposals here. Nothing it proposes runs until somebody approves it.
        </p>
      </div>
    );
  }

  return (
    <ul className="space-y-4">
      {agentOnly.map((p) => (
        <ProposalCard key={p.id} proposal={p} canApprove={canApprove} />
      ))}
    </ul>
  );
}
