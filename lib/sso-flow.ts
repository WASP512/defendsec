import { timingSafeEqual } from "node:crypto";

// The per-attempt cookie that carries state, nonce and PKCE verifier from the
// redirect to the callback. Kept pure so the state check can be tested.

export const SSO_COOKIE = "defendsec_sso";
// Long enough to sign in at the IdP, short enough that an abandoned attempt
// does not linger.
export const SSO_COOKIE_MAX_AGE = 10 * 60;

export type FlowCookie = { state: string; nonce: string; verifier: string };

export function encodeFlow(f: FlowCookie): string {
  return Buffer.from(JSON.stringify(f)).toString("base64url");
}

export function decodeFlow(raw: string | undefined): FlowCookie | null {
  if (!raw) return null;
  try {
    const f = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Partial<FlowCookie>;
    if (!f.state || !f.nonce || !f.verifier) return null;
    return { state: f.state, nonce: f.nonce, verifier: f.verifier };
  } catch {
    return null;
  }
}

// stateMatches compares the callback's state with the cookie's in constant
// time. A missing or mismatched state is a forged or replayed callback — the
// login-CSRF case, where an attacker gets the victim signed in as the
// attacker — and must fail before the code is ever exchanged.
export function stateMatches(expected: string, got: string | null): boolean {
  if (!expected || !got) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(got);
  return a.length === b.length && timingSafeEqual(a, b);
}
