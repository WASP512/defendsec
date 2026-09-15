import { NextResponse } from "next/server";

import { getApidAuthToken, isAdminSession, isAuthenticatedSession } from "@/lib/auth";
import {
  apidCreateUser,
  apidListUsers,
  apidUpdateUser,
  IdentityUnavailableError,
  type IdentityRole,
} from "@/lib/identity";

export const runtime = "nodejs";

// Account management proxies to the control plane, which owns accounts and
// re-checks authorisation itself. The session checks here keep an
// unauthenticated request from reaching it at all; they are not the only
// gate.

function unreachable(err: unknown) {
  if (err instanceof IdentityUnavailableError) {
    return NextResponse.json({ error: err.message }, { status: 503 });
  }
  return null;
}

export async function GET(request: Request) {
  if (!(await isAuthenticatedSession())) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (!(await isAdminSession())) {
    return NextResponse.json({ error: "Admin session required" }, { status: 403 });
  }
  try {
    const users = await apidListUsers(await getApidAuthToken(request));
    return NextResponse.json({ users });
  } catch (err) {
    return unreachable(err) ?? NextResponse.json({ error: "list users failed" }, { status: 502 });
  }
}

export async function POST(request: Request) {
  // Creating the first account is allowed from a shared-token session — that
  // is the bootstrap. The control plane enforces the same rule, and refuses
  // anything beyond the first account without an admin.
  if (!(await isAuthenticatedSession())) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  let body: { username?: string; displayName?: string; role?: string; password?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }
  const role: IdentityRole = body.role === "viewer" ? "viewer" : "admin";
  try {
    const result = await apidCreateUser(await getApidAuthToken(request), {
      username: body.username ?? "",
      displayName: body.displayName ?? "",
      role,
      password: body.password ?? "",
    });
    if (!result.ok) return NextResponse.json({ error: result.error }, { status: 400 });
    return NextResponse.json({ user: result.user }, { status: 201 });
  } catch (err) {
    return unreachable(err) ?? NextResponse.json({ error: "create user failed" }, { status: 502 });
  }
}

export async function PATCH(request: Request) {
  if (!(await isAuthenticatedSession())) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  let body: { userId?: string; password?: string; disabled?: boolean };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }
  if (!body.userId) {
    return NextResponse.json({ error: "userId is required" }, { status: 400 });
  }
  try {
    const result = await apidUpdateUser(await getApidAuthToken(request), {
      userId: body.userId,
      password: body.password,
      disabled: body.disabled,
    });
    if (!result.ok) return NextResponse.json({ error: result.error }, { status: 400 });
    return NextResponse.json({ ok: true });
  } catch (err) {
    return unreachable(err) ?? NextResponse.json({ error: "update user failed" }, { status: 502 });
  }
}
