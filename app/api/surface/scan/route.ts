import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Scan one confirmed asset (assetId) or every confirmed asset (none). The page
// waits for the result so it can show what the scan found.
export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let body: { assetId?: unknown } = {};
  try {
    body = await request.json();
  } catch {
    // an empty body means "all"
  }
  const assetId = typeof body.assetId === "number" ? body.assetId : undefined;
  return forwardToApid(request, "/v1/surface/scan", { method: "POST", body: { assetId, wait: true } });
}
