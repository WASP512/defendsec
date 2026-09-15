import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { DEV_ADMIN_TOKEN } from "./auth-public.ts";
import { dataDir } from "./data-paths.ts";

// Token/bearer-auth logic that doesn't need a Next.js request scope (no
// cookies()), split out from lib/auth.ts so it's importable from a plain
// Node test runner — lib/auth.ts pulls in "next/headers", which only
// resolves inside Next's own bundler.

export const ADMIN_COOKIE = "defendsec_admin";
const DATA_DIR = dataDir();
const TOKEN_PATH = join(DATA_DIR, "admin-token.txt");

let cachedToken: string | null = null;
let loadToken: Promise<string> | null = null;

function digest(value: string) {
  return createHmac("sha256", "defendsec-admin").update(value).digest();
}

export function safeEqual(left: string, right: string) {
  if (!left || !right) return false;
  const a = digest(left);
  const b = digest(right);
  return timingSafeEqual(a, b);
}

async function loadOrCreateToken() {
  const fromEnv = process.env.DEFENDSEC_ADMIN_TOKEN?.trim();
  if (fromEnv) return fromEnv;
  try {
    const fromFile = (await readFile(TOKEN_PATH, "utf8")).trim();
    if (fromFile) return fromFile;
  } catch {
    // first boot
  }
  const created =
    process.env.NODE_ENV === "production" ? randomBytes(24).toString("hex") : DEV_ADMIN_TOKEN;
  await mkdir(dirname(TOKEN_PATH), { recursive: true });
  await writeFile(TOKEN_PATH, `${created}\n`, { encoding: "utf8", mode: 0o600 });
  return created;
}

export async function getAdminToken() {
  if (cachedToken) return cachedToken;
  if (!loadToken) {
    loadToken = loadOrCreateToken().then((token) => {
      cachedToken = token;
      return token;
    });
  }
  return loadToken;
}

export function getViewerToken() {
  return process.env.DEFENDSEC_VIEWER_TOKEN?.trim() ?? "";
}

export async function isDevFallbackToken() {
  if (process.env.DEFENDSEC_ADMIN_TOKEN) return false;
  return (await getAdminToken()) === DEV_ADMIN_TOKEN;
}

function tokenMatchesSession(token: string, admin: string, viewer: string) {
  if (safeEqual(token, admin)) return "admin";
  if (viewer && safeEqual(token, viewer)) return "viewer";
  return "";
}

export async function isAdminRequestWithSession(request: Request, sessionToken: () => Promise<string>) {
  const admin = await getAdminToken();
  const header = request.headers.get("authorization");
  if (header?.startsWith("Bearer ")) {
    return safeEqual(header.slice("Bearer ".length), admin);
  }
  return safeEqual(await sessionToken(), admin);
}

export async function isAuthenticatedRequestWithSession(
  request: Request,
  sessionToken: () => Promise<string>,
) {
  const admin = await getAdminToken();
  const viewer = getViewerToken();
  const header = request.headers.get("authorization");
  if (header?.startsWith("Bearer ")) {
    return tokenMatchesSession(header.slice("Bearer ".length), admin, viewer) !== "";
  }
  return tokenMatchesSession(await sessionToken(), admin, viewer) !== "";
}

export async function getApidAuthTokenWithSession(
  sessionToken: () => Promise<string>,
  request?: Request,
) {
  const admin = await getAdminToken();
  const viewer = getViewerToken();
  if (request) {
    const header = request.headers.get("authorization");
    if (header?.startsWith("Bearer ")) {
      const token = header.slice("Bearer ".length);
      if (tokenMatchesSession(token, admin, viewer) !== "") return token;
    }
  }
  const session = await sessionToken();
  if (tokenMatchesSession(session, admin, viewer) !== "") return session;
  // Not one of the shared tokens, so it is an account session token. The
  // console cannot validate one — only the control plane can, and it does so
  // on every request — so forward it and let apid decide. Anything invalid
  // comes back 401 from there rather than being guessed at here.
  if (session) return session;
  throw new Error("no authenticated session or bearer token for apid proxy");
}

/**
 * Classifies the cookie value. "shared" means one of the bootstrap tokens,
 * whose actions cannot be attributed to a person; "session" means an opaque
 * account token that only the control plane can resolve.
 */
export async function classifySessionToken(token: string): Promise<"none" | "shared" | "session"> {
  if (!token) return "none";
  const admin = await getAdminToken();
  const viewer = getViewerToken();
  if (tokenMatchesSession(token, admin, viewer) !== "") return "shared";
  return "session";
}

export function adminCookieOptions() {
  const configuredSecure = process.env.DEFENDSEC_COOKIE_SECURE?.trim().toLowerCase();
  const secure =
    configuredSecure === undefined || configuredSecure === ""
      ? process.env.NODE_ENV === "production"
      : ["1", "true", "yes", "on"].includes(configuredSecure);
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    path: "/",
    secure,
    maxAge: 60 * 60 * 24 * 14,
  };
}
