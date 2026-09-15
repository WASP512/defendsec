import { APID_ADMIN_URL } from "./commands.ts";

// Client for the control plane's identity API (roadmap 1.0).
//
// The console deliberately does not decide who the operator is. It forwards
// the operator's own session token and asks defendsec-apid, which validates
// it against the database. That keeps one source of truth, and it means the
// identity written into the audit ledger is one the control plane established
// itself rather than one the console asserted on its behalf.

export type IdentityRole = "admin" | "viewer";

export type IdentityUser = {
  id: string;
  username: string;
  displayName?: string;
  role: IdentityRole;
  disabled?: boolean;
  totpEnabled: boolean;
  createdAt: string;
  lastLoginAt?: string;
};

export type SessionInfo = {
  role: IdentityRole;
  attributed: boolean;
  identity: string;
  user?: IdentityUser;
  accountsExist?: boolean;
};

export class IdentityUnavailableError extends Error {}

const REQUEST_TIMEOUT_MS = 8000;

async function apid(path: string, init: RequestInit & { token?: string } = {}) {
  const { token, ...rest } = init;
  const headers = new Headers(rest.headers);
  headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  try {
    return await fetch(`${APID_ADMIN_URL}${path}`, {
      ...rest,
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (cause) {
    throw new IdentityUnavailableError(
      "Control plane is not reachable on 127.0.0.1:47264. Start defendsec-apid.",
      { cause },
    );
  }
}

export type LoginOutcome =
  | { ok: true; token: string; user: IdentityUser }
  | { ok: false; totpRequired: true }
  | { ok: false; locked: true }
  | { ok: false; error: string };

export async function apidLogin(
  username: string,
  password: string,
  totpCode: string,
): Promise<LoginOutcome> {
  const res = await apid("/v1/login", {
    method: "POST",
    body: JSON.stringify({ username, password, totpCode }),
  });
  if (res.ok) {
    const body = (await res.json()) as { token: string; user: IdentityUser };
    return { ok: true, token: body.token, user: body.user };
  }
  let body: { error?: string; totpRequired?: boolean } = {};
  try {
    body = (await res.json()) as typeof body;
  } catch {
    // non-JSON error body
  }
  if (res.status === 401 && body.totpRequired) return { ok: false, totpRequired: true };
  if (res.status === 429) return { ok: false, locked: true };
  // Every other failure is reported identically, mirroring the control
  // plane, so the console cannot be used to tell which accounts exist.
  return { ok: false, error: "invalid credentials" };
}

/** Resolves a token to its session, or null when it is not a valid session. */
export async function apidSession(token: string): Promise<SessionInfo | null> {
  if (!token) return null;
  const res = await apid("/v1/session", { method: "GET", token });
  if (!res.ok) return null;
  return (await res.json()) as SessionInfo;
}

export async function apidLogout(token: string): Promise<void> {
  if (!token) return;
  try {
    await apid("/v1/logout", { method: "POST", token });
  } catch {
    // Logging out is best-effort: the cookie is cleared regardless, and a
    // session the control plane still holds expires on its own.
  }
}

/** True when at least one account exists, so the console shows sign-in rather than first-run setup. */
export async function apidAccountsExist(): Promise<boolean> {
  const res = await apid("/v1/session", { method: "GET" });
  if (res.status === 401) {
    // Unauthenticated: the endpoint cannot tell us, so assume accounts exist
    // rather than exposing first-run setup on a configured install.
    return true;
  }
  if (!res.ok) return true;
  const body = (await res.json()) as SessionInfo;
  return body.accountsExist !== false;
}

export async function apidListUsers(token: string): Promise<IdentityUser[]> {
  const res = await apid("/v1/users", { method: "GET", token });
  if (!res.ok) throw new Error(`list users failed: ${res.status}`);
  const body = (await res.json()) as { users: IdentityUser[] };
  return body.users ?? [];
}

export async function apidCreateUser(
  token: string,
  input: { username: string; displayName?: string; role: IdentityRole; password: string },
): Promise<{ ok: true; user: IdentityUser } | { ok: false; error: string }> {
  const res = await apid("/v1/users", { method: "POST", token, body: JSON.stringify(input) });
  if (res.ok) {
    const body = (await res.json()) as { user: IdentityUser };
    return { ok: true, user: body.user };
  }
  let body: { error?: string } = {};
  try {
    body = (await res.json()) as typeof body;
  } catch {
    // non-JSON error body
  }
  return { ok: false, error: body.error ?? `create user failed: ${res.status}` };
}

export async function apidUpdateUser(
  token: string,
  input: { userId: string; password?: string; disabled?: boolean },
): Promise<{ ok: true } | { ok: false; error: string }> {
  const res = await apid("/v1/users/update", {
    method: "POST",
    token,
    body: JSON.stringify(input),
  });
  if (res.ok) return { ok: true };
  let body: { error?: string } = {};
  try {
    body = (await res.json()) as typeof body;
  } catch {
    // non-JSON error body
  }
  return { ok: false, error: body.error ?? `update user failed: ${res.status}` };
}

export async function apidBeginTotp(
  token: string,
): Promise<{ secret: string; uri: string } | null> {
  const res = await apid("/v1/totp", {
    method: "POST",
    token,
    body: JSON.stringify({ step: "begin" }),
  });
  if (!res.ok) return null;
  return (await res.json()) as { secret: string; uri: string };
}

export async function apidConfirmTotp(
  token: string,
  secret: string,
  code: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const res = await apid("/v1/totp", {
    method: "POST",
    token,
    body: JSON.stringify({ step: "confirm", secret, code }),
  });
  if (res.ok) return { ok: true };
  let body: { error?: string } = {};
  try {
    body = (await res.json()) as typeof body;
  } catch {
    // non-JSON error body
  }
  return { ok: false, error: body.error ?? "that code did not match" };
}
