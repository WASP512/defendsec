import { cookies } from "next/headers";

import { ADMIN_COOKIE } from "./auth-tokens.ts";
import {
  apidCryptoPosture as fetchCryptoPosture,
  apidListUsers as fetchUsers,
  type CryptoPosture,
  IdentityUnavailableError,
  type IdentityUser,
} from "./identity.ts";

// Server-component helpers. Pages cannot pass a Request to the identity
// client, so these read the session cookie directly and turn failures into
// something renderable rather than throwing inside a render.

export async function apidListUsers(): Promise<{
  users: IdentityUser[];
  error: unknown;
}> {
  const jar = await cookies();
  const token = jar.get(ADMIN_COOKIE)?.value ?? "";
  try {
    return { users: await fetchUsers(token), error: null };
  } catch (error) {
    return { users: [], error };
  }
}

export function getIdentityErrorMessage(error: unknown): string {
  if (error instanceof IdentityUnavailableError) return error.message;
  return "Could not load accounts from the control plane.";
}

export async function apidCryptoPosture(): Promise<CryptoPosture | null> {
  const jar = await cookies();
  const token = jar.get(ADMIN_COOKIE)?.value ?? "";
  try {
    return await fetchCryptoPosture(token);
  } catch {
    // The posture is informational; a page must still render without it.
    return null;
  }
}
