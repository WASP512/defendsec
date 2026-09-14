import { cookies } from "next/headers";
import {
  ADMIN_COOKIE,
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

export async function isAdminSession() {
  const token = await getAdminToken();
  return safeEqual(await sessionTokenValue(), token);
}

export async function isViewerSession() {
  const viewer = getViewerToken();
  if (!viewer) return false;
  return safeEqual(await sessionTokenValue(), viewer);
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
