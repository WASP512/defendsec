import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { cookies } from "next/headers";

import { DEV_ADMIN_TOKEN } from "./auth-public";

export const ADMIN_COOKIE = "defendsec_admin";
const TOKEN_PATH = join(process.cwd(), "data", "admin-token.txt");

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

function tokenMatchesSession(token: string, admin: string, viewer: string) {
  if (safeEqual(token, admin)) return "admin";
  if (viewer && safeEqual(token, viewer)) return "viewer";
  return "";
}

export async function isAdminRequest(request: Request) {
  const admin = await getAdminToken();
  const header = request.headers.get("authorization");
  if (header?.startsWith("Bearer ")) {
    return safeEqual(header.slice("Bearer ".length), admin);
  }
  return safeEqual(await sessionTokenValue(), admin);
}

export async function isAuthenticatedRequest(request: Request) {
  const admin = await getAdminToken();
  const viewer = getViewerToken();
  const header = request.headers.get("authorization");
  if (header?.startsWith("Bearer ")) {
    return tokenMatchesSession(header.slice("Bearer ".length), admin, viewer) !== "";
  }
  return tokenMatchesSession(await sessionTokenValue(), admin, viewer) !== "";
}

export async function getApidAuthToken(request?: Request) {
  const admin = await getAdminToken();
  const viewer = getViewerToken();
  if (request) {
    const header = request.headers.get("authorization");
    if (header?.startsWith("Bearer ")) {
      const token = header.slice("Bearer ".length);
      if (tokenMatchesSession(token, admin, viewer) !== "") return token;
    }
  }
  const session = await sessionTokenValue();
  const role = tokenMatchesSession(session, admin, viewer);
  if (role !== "") return session;
  return admin;
}

export function adminCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    path: "/",
    secure: process.env.NODE_ENV === "production",
    maxAge: 60 * 60 * 24 * 14,
  };
}
