import assert from "node:assert/strict";
import test from "node:test";

// getAdminToken() caches on first call, so the admin token must be fixed via
// env before anything in this file imports/calls into lib/auth-tokens.ts.
// (lib/auth.ts itself can't be imported here at all: it pulls in
// "next/headers", which only resolves inside Next's own bundler, not plain
// node --test — that's why the bearer-auth logic lives in auth-tokens.ts.)
process.env.DEFENDSEC_ADMIN_TOKEN = "test-admin-token-1234567890";
process.env.DEFENDSEC_VIEWER_TOKEN = "test-viewer-token-0987654321";

import {
  adminCookieOptions,
  getApidAuthTokenWithSession,
  isAdminRequestWithSession,
  isAuthenticatedRequestWithSession,
  safeEqual,
} from "./auth-tokens.ts";

// No request ever needs the cookie fallback in these tests (every request
// below carries a bearer header, which short-circuits before this runs),
// so it only needs to exist to satisfy the type signature.
function unusedSessionToken(): Promise<string> {
  throw new Error("sessionToken should not be called for a bearer-header request");
}

const ADMIN_TOKEN = "test-admin-token-1234567890";
const VIEWER_TOKEN = "test-viewer-token-0987654321";

function bearerRequest(token: string) {
  return new Request("https://example.test/api", {
    headers: { authorization: `Bearer ${token}` },
  });
}

test("safeEqual", async (t) => {
  await t.test("matches identical values", () => {
    assert.equal(safeEqual("secret", "secret"), true);
  });

  await t.test("rejects different values", () => {
    assert.equal(safeEqual("secret", "different"), false);
  });

  await t.test("rejects when either side is empty", () => {
    assert.equal(safeEqual("", "secret"), false);
    assert.equal(safeEqual("secret", ""), false);
    assert.equal(safeEqual("", ""), false);
  });
});

// These exercise the exact bearer-header path used by every app/api/*
// route's unauthorizedIfNotAdmin/unauthorizedIfNotAuthenticated gate.
test("isAdminRequest / isAuthenticatedRequest via bearer header", async (t) => {
  await t.test("admin bearer token is admin and authenticated", async () => {
    const req = bearerRequest(ADMIN_TOKEN);
    assert.equal(await isAdminRequestWithSession(req, unusedSessionToken), true);
    assert.equal(await isAuthenticatedRequestWithSession(req, unusedSessionToken), true);
  });

  await t.test("viewer bearer token is authenticated but never admin", async () => {
    const req = bearerRequest(VIEWER_TOKEN);
    assert.equal(await isAdminRequestWithSession(req, unusedSessionToken), false);
    assert.equal(await isAuthenticatedRequestWithSession(req, unusedSessionToken), true);
  });

  await t.test("unrecognized bearer token is neither", async () => {
    const req = bearerRequest("not-a-real-token");
    assert.equal(await isAdminRequestWithSession(req, unusedSessionToken), false);
    assert.equal(await isAuthenticatedRequestWithSession(req, unusedSessionToken), false);
  });
});

// getApidAuthToken is the function that used to fall back to the real admin
// token for an unauthenticated request (fixed in the "fail closed" change).
// These cover the bearer-header success paths it's actually called with by
// the apid proxy routes: it must return the caller's own token, never
// silently upgrade a viewer to admin.
test("getApidAuthToken resolves to the caller's own bearer token", async (t) => {
  await t.test("admin bearer resolves to the admin token", async () => {
    const req = bearerRequest(ADMIN_TOKEN);
    assert.equal(await getApidAuthTokenWithSession(unusedSessionToken, req), ADMIN_TOKEN);
  });

  await t.test("viewer bearer resolves to the viewer token, not the admin token", async () => {
    const req = bearerRequest(VIEWER_TOKEN);
    assert.equal(await getApidAuthTokenWithSession(unusedSessionToken, req), VIEWER_TOKEN);
  });

  await t.test("throws instead of falling back to the admin token when unauthenticated", async () => {
    await assert.rejects(() =>
      getApidAuthTokenWithSession(async () => "", undefined),
    );
  });
});

test("adminCookieOptions", async (t) => {
  const original = process.env.DEFENDSEC_COOKIE_SECURE;
  t.after(() => {
    if (original === undefined) delete process.env.DEFENDSEC_COOKIE_SECURE;
    else process.env.DEFENDSEC_COOKIE_SECURE = original;
  });

  await t.test("is httpOnly, lax, root-scoped, and lasts 14 days", () => {
    const opts = adminCookieOptions();
    assert.equal(opts.httpOnly, true);
    assert.equal(opts.sameSite, "lax");
    assert.equal(opts.path, "/");
    assert.equal(opts.maxAge, 60 * 60 * 24 * 14);
  });

  await t.test("honors an explicit DEFENDSEC_COOKIE_SECURE override", () => {
    process.env.DEFENDSEC_COOKIE_SECURE = "true";
    assert.equal(adminCookieOptions().secure, true);
    process.env.DEFENDSEC_COOKIE_SECURE = "false";
    assert.equal(adminCookieOptions().secure, false);
  });
});
