import assert from "node:assert/strict";
import test from "node:test";

import { cleanInvite, loginState, validateSetup, type SetupStatus } from "./login-state.ts";

const base: SetupStatus = {
  databaseConfigured: true,
  accountsExist: false,
  setupOpen: false,
  detail: "",
};

test("a fresh install with setup open offers setup", () => {
  const s = loginState({ ...base, setupOpen: true, secondsRemaining: 1799 });
  assert.equal(s.kind, "setup");
  assert.equal(s.kind === "setup" && s.minutesRemaining, 30);
});

// The bug this replaces: an unreachable or unauthenticated control plane was
// read as "accounts exist", which hid setup on every fresh install.
test("an unreachable control plane is reported, not guessed at", () => {
  assert.equal(loginState(null).kind, "unavailable");
});

test("once accounts exist, it is ordinary sign-in", () => {
  assert.equal(loginState({ ...base, accountsExist: true, setupOpen: true }).kind, "signin");
});

test("no accounts and a closed window says so", () => {
  assert.equal(loginState(base).kind, "setup-closed");
});

test("no database means the token is the only way in", () => {
  assert.equal(loginState({ ...base, databaseConfigured: false }).kind, "token-only");
});

test("a window in its last seconds still reads as open", () => {
  const s = loginState({ ...base, setupOpen: true, secondsRemaining: 5 });
  assert.equal(s.kind === "setup" && s.minutesRemaining, 1);
});

test("setup input is checked before it is sent", () => {
  assert.equal(validateSetup({ username: "mason", password: "long enough pw", confirm: "long enough pw" }), null);
  assert.match(validateSetup({ username: "m", password: "long enough pw", confirm: "long enough pw" }) ?? "", /username/);
  assert.match(validateSetup({ username: "mason", password: "short", confirm: "short" }) ?? "", /12 characters/);
  assert.match(validateSetup({ username: "mason", password: "long enough pw", confirm: "different pw!!" }) ?? "", /do not match/);
});

test("a valid one-time link opens setup even after the window", () => {
  const s = loginState({ ...base, setupOpen: true, viaInvite: true });
  assert.deepEqual(s, { kind: "setup", minutesRemaining: 0, viaInvite: true });
});

test("a refused link is reported, not silently ignored", () => {
  const s = loginState({ ...base, inviteInvalid: true });
  assert.deepEqual(s, { kind: "setup-closed", inviteInvalid: true });
});

test("invite tokens are shape-checked before use", () => {
  assert.equal(cleanInvite("  AbC-_123456789012345678901234  "), "AbC-_123456789012345678901234");
  assert.equal(cleanInvite("short"), "");
  assert.equal(cleanInvite("x".repeat(30) + "&admin=1"), "");
  assert.equal(cleanInvite(undefined), "");
});
