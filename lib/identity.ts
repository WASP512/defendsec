import { APID_ADMIN_URL } from "./commands.ts";
import type { SetupStatus } from "./login-state.ts";

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
  if (res.status === 401 && body.totpRequired)
    return { ok: false, totpRequired: true };
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
// apidSetupStatus reports whether first-run setup is available. Unauthenticated
// by design: it exists to work before any credential does. Returns null when
// the control plane cannot be reached, so the caller can say so rather than
// guess.
export async function apidSetupStatus(invite = ""): Promise<SetupStatus | null> {
  try {
    const q = invite ? `?invite=${encodeURIComponent(invite)}` : "";
    const res = await apid(`/v1/setup${q}`, { method: "GET" });
    if (!res.ok) return null;
    return (await res.json()) as SetupStatus;
  } catch {
    return null;
  }
}

export type SetupOutcome =
  | { ok: true; token?: string }
  | { ok: false; error: string };

// apidSetup creates the first administrator.
export async function apidSetup(input: {
  username: string;
  displayName: string;
  password: string;
  clientAddress: string;
  invite?: string;
}): Promise<SetupOutcome> {
  const res = await apid("/v1/setup", {
    method: "POST",
    body: JSON.stringify(input),
  });
  let body: { token?: string; error?: string } = {};
  try {
    body = (await res.json()) as typeof body;
  } catch {
    // non-JSON error body
  }
  if (res.ok) return { ok: true, token: body.token };
  return { ok: false, error: body.error ?? `The control plane returned ${res.status}.` };
}

export async function apidListUsers(token: string): Promise<IdentityUser[]> {
  const res = await apid("/v1/users", { method: "GET", token });
  if (!res.ok) throw new Error(`list users failed: ${res.status}`);
  const body = (await res.json()) as { users: IdentityUser[] };
  return body.users ?? [];
}

export async function apidCreateUser(
  token: string,
  input: {
    username: string;
    displayName?: string;
    role: IdentityRole;
    password: string;
  },
): Promise<{ ok: true; user: IdentityUser } | { ok: false; error: string }> {
  const res = await apid("/v1/users", {
    method: "POST",
    token,
    body: JSON.stringify(input),
  });
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
  return {
    ok: false,
    error: body.error ?? `create user failed: ${res.status}`,
  };
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
  return {
    ok: false,
    error: body.error ?? `update user failed: ${res.status}`,
  };
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

// Cryptographic posture (roadmap 1.8). Shown to an administrator because
// "is this FIPS mode?" is not answerable from the console's own configuration:
// GODEBUG=fips140=on routes standard-library crypto through the validated
// module but rejects nothing, so a deployment can look compliant while using
// an unapproved password KDF. This reports what the running process is
// actually doing, including the deviations.
export type CryptoPosture = {
  goModuleEnabled: boolean;
  goModuleEnforced: boolean;
  approvedAlgorithmsRequired: boolean;
  passwordKdf: string;
  notes?: string[];
};

export async function apidCryptoPosture(token: string): Promise<CryptoPosture> {
  const res = await apid("/v1/crypto-posture", { token });
  if (!res.ok) {
    throw new IdentityUnavailableError(
      `Control plane returned ${res.status} for the cryptographic posture.`,
    );
  }
  return (await res.json()) as CryptoPosture;
}

// Single sign-on (roadmap 5.4).

export type SSOStatus = { enabled: boolean; displayName?: string };

export async function apidSSOStatus(): Promise<SSOStatus> {
  try {
    const res = await apid("/v1/sso", { method: "GET" });
    if (!res.ok) return { enabled: false };
    return (await res.json()) as SSOStatus;
  } catch {
    return { enabled: false };
  }
}

export type SSOFlow = { authUrl: string; state: string; nonce: string; verifier: string };

export async function apidSSOStart(): Promise<SSOFlow | { error: string }> {
  const res = await apid("/v1/sso/start", { method: "POST" });
  const body = (await res.json().catch(() => ({}))) as SSOFlow & { error?: string };
  if (!res.ok) return { error: body.error ?? `Control plane returned ${res.status}.` };
  return body;
}

export async function apidSSOFinish(input: {
  code: string;
  verifier: string;
  nonce: string;
  clientAddress: string;
}): Promise<{ token: string } | { error: string }> {
  const res = await apid("/v1/sso/finish", { method: "POST", body: JSON.stringify(input) });
  const body = (await res.json().catch(() => ({}))) as { token?: string; error?: string };
  if (res.ok && body.token) return { token: body.token };
  return { error: body.error ?? `Control plane returned ${res.status}.` };
}
