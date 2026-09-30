import { cookies } from "next/headers";

import { ADMIN_COOKIE } from "./auth-tokens.ts";
import { APID_ADMIN_URL } from "./commands.ts";
import { apiPath, type DeviceListQuery, type DevicePage } from "./device-list.ts";

// The host list, a page at a time, filtered by the control plane (roadmap
// 5.5). The operator's own session token is forwarded, as elsewhere.
export async function loadDevicePage(
  q: DeviceListQuery,
): Promise<{ page: DevicePage } | { error: string }> {
  const token = (await cookies()).get(ADMIN_COOKIE)?.value ?? "";
  const headers = new Headers();
  if (token) headers.set("authorization", `Bearer ${token}`);
  let res: Response;
  try {
    res = await fetch(`${APID_ADMIN_URL}${apiPath(q)}`, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    return { error: "The control plane is not reachable. Start defendsec-apid." };
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return { error: body.error || `The control plane returned ${res.status}.` };
  }
  return { page: (await res.json()) as DevicePage };
}
