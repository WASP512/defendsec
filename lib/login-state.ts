// Which sign-in screen to show (first-run setup, roadmap 1.0 follow-up).
//
// Pure, so the decision can be tested without a running control plane. The
// previous version made this decision by asking the control plane whether
// accounts existed without being signed in, receiving a 401, and assuming
// they did — so a fresh install never offered setup at all.

export type SetupStatus = {
  databaseConfigured: boolean;
  accountsExist: boolean;
  setupOpen: boolean;
  secondsRemaining?: number;
  // Setup is open because the request carried a valid one-time link from
  // `defendsec-apid bootstrap-admin`.
  viaInvite?: boolean;
  // A link was presented and refused (unknown, expired or used).
  inviteInvalid?: boolean;
  detail: string;
};

export type LoginState =
  // Create the first administrator, no token needed.
  | { kind: "setup"; minutesRemaining: number; viaInvite: boolean }
  // No accounts, but the window has closed; bootstrap-admin reopens it.
  | { kind: "setup-closed"; inviteInvalid: boolean }
  // Normal sign-in.
  | { kind: "signin" }
  // No database, so there are no accounts to sign in to.
  | { kind: "token-only" }
  // The control plane could not be reached.
  | { kind: "unavailable" };

// loginState decides what the login page shows.
//
// An unreachable control plane is reported as such rather than guessed at.
// Guessing "accounts exist" is what hid setup on fresh installs; guessing
// "no accounts" would offer a setup form that could not work. Saying the
// control plane is down is true, and it is the thing the operator can fix.
export function loginState(status: SetupStatus | null): LoginState {
  if (status === null) return { kind: "unavailable" };
  if (!status.databaseConfigured) return { kind: "token-only" };
  if (status.accountsExist) return { kind: "signin" };
  if (status.setupOpen && status.viaInvite) {
    return { kind: "setup", minutesRemaining: 0, viaInvite: true };
  }
  if (status.setupOpen) {
    const seconds = Math.max(0, status.secondsRemaining ?? 0);
    // Rounded up: "0 minutes left" while it is still open would read as
    // already closed.
    return { kind: "setup", minutesRemaining: Math.max(1, Math.ceil(seconds / 60)), viaInvite: false };
  }
  return { kind: "setup-closed", inviteInvalid: Boolean(status.inviteInvalid) };
}

// An invite token as it appears in ?invite=, or "" if malformed. Validated
// by the control plane; this only keeps junk out of the request.
export function cleanInvite(raw: string | undefined): string {
  const v = (raw ?? "").trim();
  return /^[A-Za-z0-9_-]{20,100}$/.test(v) ? v : "";
}

// validateSetup checks what the browser sent before bothering the control
// plane. The control plane checks again and is the authority; this exists so
// a mistyped confirmation gets a clear message rather than a round trip.
export function validateSetup(input: {
  username: string;
  password: string;
  confirm: string;
}): string | null {
  const username = input.username.trim();
  if (username.length < 2) return "Choose a username of at least 2 characters.";
  if (input.password.length < 12) return "Use a password of at least 12 characters.";
  if (input.password !== input.confirm) return "The two passwords do not match.";
  return null;
}
