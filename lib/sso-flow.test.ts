import assert from "node:assert/strict";
import test from "node:test";

import { decodeFlow, encodeFlow, stateMatches } from "./sso-flow.ts";

test("the flow cookie round-trips", () => {
  const f = { state: "s", nonce: "n", verifier: "v" };
  assert.deepEqual(decodeFlow(encodeFlow(f)), f);
});

test("a malformed or incomplete cookie is rejected", () => {
  assert.equal(decodeFlow(undefined), null);
  assert.equal(decodeFlow("not base64 json"), null);
  assert.equal(decodeFlow(Buffer.from('{"state":"s"}').toString("base64url")), null);
});

// Login CSRF: a callback whose state is missing or different must fail.
test("state must match exactly", () => {
  assert.equal(stateMatches("abc", "abc"), true);
  assert.equal(stateMatches("abc", "abd"), false);
  assert.equal(stateMatches("abc", null), false);
  assert.equal(stateMatches("", ""), false);
  assert.equal(stateMatches("abc", "abcd"), false);
});
