// Partitioning pending requests into human requests and AI proposals
// (roadmap 4.2).
//
// Kept separate from response-policy.ts, which imports next/headers and so
// cannot be tested in isolation. The partition is the security-relevant part:
// a proposal that leaks into the human approvals list is shown as a bare
// pending command, and approving it there means approving it without the
// reasoning that is the only thing making it reviewable.

export type PendingCommand = {
  id: string;
  createdAt: string;
  expiresAt: string;
  deviceId: string;
  hostname?: string;
  commandType: string;
  payload: string;
  requestedBy: string;
  requiredApprovals: number;
  ruleId?: string;
  approvals: string[];

  // Proposal provenance (roadmap 4.2). Present only on an AI proposal; a
  // human request has none of it.
  proposedByAgent?: string;
  proposalModel?: string;
  proposalReasoning?: string;
  proposalEvidence?: string[];
  proposalPrompt?: string;
};

// AgentFields is the provenance an AI proposal carries and a human request
// does not.
export type AgentFields = {
  proposedByAgent?: string;
  proposalModel?: string;
  proposalReasoning?: string;
  proposalEvidence?: string[];
  proposalPrompt?: string;
};

// isProposal reports whether a pending request came from an AI agent.
//
// Keyed on the proposing agent's name rather than on the presence of
// reasoning or a model: those are recorded alongside it but a proposal with
// neither is still a proposal, and treating it as a human request because a
// field was empty is the wrong direction to fail in.
export function isProposal<T extends AgentFields>(p: T): boolean {
  return typeof p.proposedByAgent === "string" && p.proposedByAgent.length > 0;
}

// partitionApprovals splits pending requests by origin.
//
// Every input lands in exactly one output. A request that is neither — which
// cannot happen, but would be the dangerous case if it did — would be dropped
// by a filter pair written independently, so this is one pass over the list.
export function partitionApprovals<T extends AgentFields>(
  pending: T[],
): { proposals: T[]; human: T[] } {
  const proposals: T[] = [];
  const human: T[] = [];
  for (const p of pending) {
    if (isProposal(p)) {
      proposals.push(p);
    } else {
      human.push(p);
    }
  }
  return { proposals, human };
}
