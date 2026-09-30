// Query-string handling for the server-paginated host list (roadmap 5.5).
// Pure, so paging and filter URLs are tested rather than assembled inline.

export type DeviceListQuery = {
  q: string;
  platform: "" | "linux" | "windows" | "darwin";
  status: "" | "online" | "offline" | "isolated";
  cursor: string;
  // Cursors of the pages before this one, so Previous works with a
  // forward-only keyset cursor.
  back: string[];
};

export type DeviceSummary = {
  id: string;
  hostname: string;
  platform: string;
  osName: string;
  osVersion: string;
  arch: string;
  agentVersion: string;
  serial: string;
  hardwareModel: string;
  username: string;
  ipAddresses: string[];
  diskEncryption: boolean | null;
  firewall: boolean | null;
  isolated: boolean;
  lastSeen: string;
  online: boolean;
  softwareCount: number;
  pendingUpdates: number;
};

export type DevicePage = { devices: DeviceSummary[]; next?: string; total: number };

export const PAGE_SIZE = 50;

const PLATFORMS = new Set(["linux", "windows", "darwin"]);
const STATUSES = new Set(["online", "offline", "isolated"]);
const CURSOR_RE = /^[A-Za-z0-9_-]{1,400}$/;

type Params = Record<string, string | string[] | undefined>;

function one(v: string | string[] | undefined): string {
  return (Array.isArray(v) ? v[0] : v) ?? "";
}

// parseDeviceListQuery reads the page's search params, dropping anything
// malformed rather than passing it to the control plane.
export function parseDeviceListQuery(params: Params): DeviceListQuery {
  const platform = one(params.platform);
  const status = one(params.status);
  const cursor = one(params.cursor);
  const back = one(params.back)
    .split(".")
    .filter((c) => c === "0" || CURSOR_RE.test(c))
    .slice(-50);
  return {
    q: one(params.q).trim().slice(0, 200),
    platform: (PLATFORMS.has(platform) ? platform : "") as DeviceListQuery["platform"],
    status: (STATUSES.has(status) ? status : "") as DeviceListQuery["status"],
    cursor: CURSOR_RE.test(cursor) ? cursor : "",
    back: back.filter(Boolean),
  };
}

// apiPath is the control-plane request for a query.
export function apiPath(q: DeviceListQuery): string {
  const p = new URLSearchParams({ limit: String(PAGE_SIZE) });
  if (q.q) p.set("q", q.q);
  if (q.platform) p.set("platform", q.platform);
  if (q.status) p.set("status", q.status);
  if (q.cursor) p.set("cursor", q.cursor);
  return `/v1/devices?${p}`;
}

function pageHref(base: DeviceListQuery, cursor: string, back: string[]): string {
  const p = new URLSearchParams();
  if (base.q) p.set("q", base.q);
  if (base.platform) p.set("platform", base.platform);
  if (base.status) p.set("status", base.status);
  if (cursor) p.set("cursor", cursor);
  if (back.length) p.set("back", back.join("."));
  const s = p.toString();
  return s ? `/devices?${s}` : "/devices";
}

// nextHref and prevHref link the pages. "0" in the back stack stands for the
// first page, which has no cursor.
export function nextHref(q: DeviceListQuery, next: string | undefined): string | null {
  if (!next) return null;
  return pageHref(q, next, [...q.back, q.cursor || "0"]);
}

export function prevHref(q: DeviceListQuery): string | null {
  if (!q.cursor) return null;
  const back = [...q.back];
  const prev = back.pop() ?? "0";
  return pageHref(q, prev === "0" ? "" : prev, back);
}

// pageNumber is 1-based, from the depth of the back stack.
export function pageNumber(q: DeviceListQuery): number {
  return q.cursor ? q.back.length + 1 : 1;
}
