import { NextResponse } from "next/server";

import { getApidAuthToken, isAuthenticatedSession } from "@/lib/auth";
import { apidBeginTotp, apidConfirmTotp, IdentityUnavailableError } from "@/lib/identity";

export const runtime = "nodejs";

// Second-factor enrollment is two steps: begin returns a secret that is only
// held by the browser, and confirm stores it once a code from the operator's
// authenticator proves it works. Nothing is persisted in between, so a
// mis-scanned code cannot lock anyone out of their own account.

export async function POST(request: Request) {
  if (!(await isAuthenticatedSession())) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  let body: { step?: string; secret?: string; code?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }

  try {
    const token = await getApidAuthToken(request);
    if (body.step === "begin") {
      const started = await apidBeginTotp(token);
      if (!started) {
        return NextResponse.json(
          { error: "Enrollment needs a signed-in account, not a shared token." },
          { status: 400 },
        );
      }
      return NextResponse.json(started);
    }
    if (body.step === "confirm") {
      const result = await apidConfirmTotp(token, body.secret ?? "", body.code ?? "");
      if (!result.ok) return NextResponse.json({ error: result.error }, { status: 400 });
      return NextResponse.json({ ok: true });
    }
    return NextResponse.json({ error: 'step must be "begin" or "confirm"' }, { status: 400 });
  } catch (err) {
    if (err instanceof IdentityUnavailableError) {
      return NextResponse.json({ error: err.message }, { status: 503 });
    }
    return NextResponse.json({ error: "enrollment failed" }, { status: 502 });
  }
}
