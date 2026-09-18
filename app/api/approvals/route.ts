import { NextResponse } from "next/server";

import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { getAdminToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";

export const runtime = "nodejs";

// Approving or rejecting a pending command, including an AI proposal
// (roadmap 4.2).
//
// The console does not decide anything here. It forwards the operator's own
// admin token to defendsec-apid, which re-evaluates the policy before signing
// — so an approval granted here is still subject to the rules as they stand
// at the moment of signing, not as they stood when the request was recorded.
export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;

  let body: { pendingId?: string; reject?: boolean };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }
  const pendingId = (body.pendingId ?? "").trim();
  if (!pendingId) {
    return NextResponse.json({ error: "pendingId is required" }, { status: 400 });
  }

  const token = await getAdminToken();
  const response = await fetch(new URL("/v1/policy/approvals", APID_ADMIN_URL), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ pendingId, reject: Boolean(body.reject) }),
    cache: "no-store",
  });

  // The control plane's own answer is relayed verbatim, including a denial.
  // Rewriting it here would give the operator a second, friendlier account of
  // a refusal that the ledger records differently.
  const text = await response.text();
  try {
    return NextResponse.json(JSON.parse(text), { status: response.status });
  } catch {
    return NextResponse.json(
      { error: text || `control plane returned ${response.status}` },
      { status: response.status },
    );
  }
}
