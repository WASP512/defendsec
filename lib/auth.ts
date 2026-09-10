import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { cookies } from "next/headers";

import { DEV_ADMIN_TOKEN } from "./auth-public";

export const ADMIN_COOKIE = "keel_admin";
const TOKEN_PATH = join(process.cwd(), "data", "admin-token.txt");

let cachedToken: string | null = null;
let loadToken: Promise<string> | null = null;

function digest(value: string) {
  return createHmac("sha256", "keel-admin").update(value).digest();
}

export function safeEqual(left: string, right: string) {
  const a = digest(left);
  const b = digest(right);
  return timingSafeEqual(a, b);
}

async function loadOrCreateToken() {
  const fromEnv = process.env.KEEL_ADMIN_TOKEN?.trim();
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

export async function isDevFallbackToken() {
  if (process.env.KEEL_ADMIN_TOKEN) return false;
  return (await getAdminToken()) === DEV_ADMIN_TOKEN;
}

export async function isAdminRequest(request: Request) {
  const token = await getAdminToken();
  const header = request.headers.get("authorization");
  if (header?.startsWith("Bearer ") && safeEqual(header.slice("Bearer ".length), token)) {
    return true;
  }
  const jar = await cookies();
  return safeEqual(jar.get(ADMIN_COOKIE)?.value ?? "", token);
}

export async function isAdminSession() {
  const token = await getAdminToken();
  const jar = await cookies();
  return safeEqual(jar.get(ADMIN_COOKIE)?.value ?? "", token);
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
