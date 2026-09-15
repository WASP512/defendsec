import { cache } from "react";

import { cookies } from "next/headers";

import { apidSession, type SessionInfo } from "./identity.ts";
import {
  ADMIN_COOKIE,
  classifySessionToken,
  getAdminToken,
  getApidAuthTokenWithSession,
  getViewerToken,
  isAdminRequestWithSession,
  isAuthenticatedRequestWithSession,
  safeEqual,
} from "./auth-tokens";

export {
  ADMIN_COOKIE,
  adminCookieOptions,
  getAdminToken,
  getViewerToken,
  isDevFallbackToken,
  safeEqual,
} from "./auth-tokens";

async function sessionTokenValue() {
  const jar = await cookies();
  return jar.get(ADMIN_COOKIE)?.value ?? "";
}

// Identity resolution. A cookie holding one of the shared bootstrap tokens is
// settled locally; anything else is an account session token that only the
// control plane can validate, so it is resolved there. cache() keeps that to
// one lookup per request rather than one per call site.
const resolveSession = cache(async (): Promise<SessionInfo | null> => {
  const token = await sessionTokenValue();
  if ((await classifySessionToken(token)) !== "session") return null;
  try {
    return await apidSession(token);
  } catch {
    // Control plane unreachable: treat as unauthenticated rather than
    // failing open.
    return null;
  }
});

/** The signed-in account, or null for a shared-token or anonymous session. */
export async function currentUser() {
  return (await resolveSession())?.user ?? null;
}

/** Who the audit ledger will record for this request. */
export async function currentActorIdentity() {
  const session = await resolveSession();
  if (session?.identity) return session.identity;
  const token = await sessionTokenValue();
  if ((await classifySessionToken(token)) === "shared") {
    return "unattributed:shared-bootstrap-token";
  }
  return "";
}

export async function isAdminSession() {
  const token = await getAdminToken();
  if (safeEqual(await sessionTokenValue(), token)) return true;
  return (await resolveSession())?.role === "admin";
}

export async function isViewerSession() {
  const viewer = getViewerToken();
  if (viewer && safeEqual(await sessionTokenValue(), viewer)) return true;
  return (await resolveSession())?.role === "viewer";
}

export async function isAuthenticatedSession() {
  return (await isAdminSession()) || (await isViewerSession());
}

export async function isReadOnlySession() {
  return (await isViewerSession()) && !(await isAdminSession());
}

export async function isAdminRequest(request: Request) {
  return isAdminRequestWithSession(request, sessionTokenValue);
}

export async function isAuthenticatedRequest(request: Request) {
  return isAuthenticatedRequestWithSession(request, sessionTokenValue);
}

export async function getApidAuthToken(request?: Request) {
  return getApidAuthTokenWithSession(sessionTokenValue, request);
}
