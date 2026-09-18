import assert from "node:assert/strict";
import test from "node:test";

import { isProposal, partitionApprovals } from "./proposals.ts";

test("a request with a proposing agent is a proposal", () => {
  assert.equal(isProposal({ proposedByAgent: "triage" }), true);
});

test("a human request is not a proposal", () => {
  assert.equal(isProposal({}), false);
  assert.equal(isProposal({ proposedByAgent: "" }), false);
  assert.equal(isProposal({ proposedByAgent: undefined }), false);
});

// A proposal whose reasoning failed to record is still a proposal. Treating
// it as a human request because a field was empty is the wrong direction to
// fail in: it would appear in the generic queue with no case attached, which
// is exactly what the split exists to prevent.
test("a proposal with no reasoning or model is still a proposal", () => {
  assert.equal(isProposal({ proposedByAgent: "triage" }), true);
  assert.equal(
    isProposal({ proposedByAgent: "triage", proposalReasoning: "" }),
    true,
  );
});

test("every pending request lands in exactly one bucket", () => {
  const pending = [
    { id: "h1" },
    { id: "a1", proposedByAgent: "triage" },
    { id: "h2", proposedByAgent: "" },
    { id: "a2", proposedByAgent: "other" },
  ];
  const { proposals, human } = partitionApprovals(pending);

  assert.deepEqual(
    proposals.map((p) => p.id),
    ["a1", "a2"],
  );
  assert.deepEqual(
    human.map((p) => p.id),
    ["h1", "h2"],
  );
  assert.equal(proposals.length + human.length, pending.length);
});

test("an empty list partitions into two empty lists", () => {
  const { proposals, human } = partitionApprovals([]);
  assert.deepEqual(proposals, []);
  assert.deepEqual(human, []);
});

// The ordering within each bucket is the order it arrived in, so the
// control plane's own ordering is preserved rather than reshuffled here.
test("order within each bucket is preserved", () => {
  const { proposals } = partitionApprovals([
    { id: "second", proposedByAgent: "b" },
    { id: "first", proposedByAgent: "a" },
  ]);
  assert.deepEqual(
    proposals.map((p) => p.id),
    ["second", "first"],
  );
});
