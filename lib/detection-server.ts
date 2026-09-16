import { cookies } from "next/headers";

import { ADMIN_COOKIE } from "./auth-tokens.ts";
import { APID_ADMIN_URL } from "./commands.ts";
import type { DetectionCoverage, ForwardingStatus } from "./detection.ts";

// Server-component client for the detection endpoints (roadmap 3.4 and 3.6).
//
// As elsewhere, the console forwards the operator's own session token and asks
// defendsec-apid rather than deciding anything itself.

export class DetectionUnavailableError extends Error {}

const REQUEST_TIMEOUT_MS = 8000;

async function apid(path: string): Promise<Response> {
  const jar = await cookies();
  const token = jar.get(ADMIN_COOKIE)?.value ?? "";
  const headers = new Headers({ "content-type": "application/json" });
  if (token) headers.set("authorization", `Bearer ${token}`);
  try {
    return await fetch(`${APID_ADMIN_URL}${path}`, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (cause) {
    throw new DetectionUnavailableError(
      "Control plane is not reachable. Start defendsec-apid.",
      { cause },
    );
  }
}

export async function loadDetectionCoverage(): Promise<DetectionCoverage> {
  const res = await apid("/v1/detection/coverage");
  if (!res.ok) {
    throw new DetectionUnavailableError(
      `Control plane returned ${res.status} for detection coverage.`,
    );
  }
  return (await res.json()) as DetectionCoverage;
}

// Forwarding is admin-only on the control plane: destination addresses are
// part of the operator's infrastructure map. A viewer gets null rather than an
// error, because the rest of the page is still theirs to read.
export async function loadForwardingStatus(): Promise<ForwardingStatus | null> {
  try {
    const res = await apid("/v1/detection/forwarding");
    if (!res.ok) return null;
    return (await res.json()) as ForwardingStatus;
  } catch {
    return null;
  }
}
