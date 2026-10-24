import { NextResponse } from "next/server";
import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken, getApidAuthToken } from "@/lib/auth";
import type { AssetsResponse, SurfaceFindingsResponse } from "@/lib/surface-model";

/**
 * The external surface scanner lives in apid; the console reads and writes it
 * there. Reads return null if the control plane cannot be reached (or is older
 * than the surface API): callers say "unavailable", never an empty list, since
 * an empty list reads as "nothing exposed".
 */
async function get<T>(path: string): Promise<T | null> {
  try {
    const token = await getAdminToken();
    const response = await fetch(new URL(path, APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

export function getAssets(): Promise<AssetsResponse | null> {
  return get<AssetsResponse>("/v1/assets");
}

export function getSurfaceFindings(opts: { resolved?: boolean; limit?: number } = {}): Promise<SurfaceFindingsResponse | null> {
  const q = new URLSearchParams();
  if (opts.resolved) q.set("resolved", "1");
  if (opts.limit) q.set("limit", String(opts.limit));
  const qs = q.toString();
  return get<SurfaceFindingsResponse>(`/v1/surface/findings${qs ? `?${qs}` : ""}`);
}

/**
 * Forward a write to apid with the caller's own session token, so apid records
 * the named person and enforces the admin role itself. The body and status come
 * back unchanged (apid answers plain text for errors; wrap it as JSON for the
 * console).
 */
export async function forwardToApid(request: Request, path: string, init: { method: string; body?: unknown }) {
  try {
    const token = await getApidAuthToken(request);
    const response = await fetch(new URL(path, APID_ADMIN_URL), {
      method: init.method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      cache: "no-store",
    });
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = response.ok ? { ok: true } : { error: text.trim() || `Request failed (${response.status})` };
    }
    return NextResponse.json(parsed, { status: response.status });
  } catch {
    return NextResponse.json({ error: "The control plane could not be reached." }, { status: 502 });
  }
}
