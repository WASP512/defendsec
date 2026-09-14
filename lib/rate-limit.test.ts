import assert from "node:assert/strict";
import test from "node:test";

import { clearAttempts, isRateLimited, loginRateLimitKey, recordFailedAttempt } from "./rate-limit.ts";

function req(forwardedFor?: string) {
  return new Request("https://example.test/api/login", {
    headers: forwardedFor ? { "x-forwarded-for": forwardedFor } : {},
  });
}

test("loginRateLimitKey", async (t) => {
  await t.test("uses the first hop of X-Forwarded-For", () => {
    assert.equal(loginRateLimitKey(req("203.0.113.9, 10.0.0.1")), "203.0.113.9");
  });

  await t.test("falls back to a shared key when the header is absent", () => {
    assert.equal(loginRateLimitKey(req()), "unattributed");
  });
});

test("isRateLimited / recordFailedAttempt", async (t) => {
  await t.test("allows attempts under the threshold", () => {
    const key = `test-${Math.random()}`;
    const now = 1_000_000;
    for (let i = 0; i < 4; i++) {
      assert.equal(isRateLimited(key, now).limited, false);
      recordFailedAttempt(key, now);
    }
    assert.equal(isRateLimited(key, now).limited, false);
  });

  await t.test("blocks after the threshold, with a positive retry-after", () => {
    const key = `test-${Math.random()}`;
    const now = 2_000_000;
    for (let i = 0; i < 5; i++) recordFailedAttempt(key, now);
    const result = isRateLimited(key, now);
    assert.equal(result.limited, true);
    assert.ok(result.retryAfterSeconds > 0);
  });

  await t.test("clearAttempts resets the bucket", () => {
    const key = `test-${Math.random()}`;
    const now = 3_000_000;
    for (let i = 0; i < 5; i++) recordFailedAttempt(key, now);
    assert.equal(isRateLimited(key, now).limited, true);
    clearAttempts(key);
    assert.equal(isRateLimited(key, now).limited, false);
  });

  await t.test("the window resets after it elapses", () => {
    const key = `test-${Math.random()}`;
    const start = 4_000_000;
    for (let i = 0; i < 5; i++) recordFailedAttempt(key, start);
    assert.equal(isRateLimited(key, start).limited, true);
    const afterWindow = start + 5 * 60 * 1000 + 1;
    assert.equal(isRateLimited(key, afterWindow).limited, false);
  });

  await t.test("different keys don't interfere with each other", () => {
    const a = `test-a-${Math.random()}`;
    const b = `test-b-${Math.random()}`;
    const now = 5_000_000;
    for (let i = 0; i < 5; i++) recordFailedAttempt(a, now);
    assert.equal(isRateLimited(a, now).limited, true);
    assert.equal(isRateLimited(b, now).limited, false);
  });
});
