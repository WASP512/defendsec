// External surface scanner (GET /v1/assets, GET /v1/surface/findings).
//
// What the internet sees of the client's declared domains, hostnames and IPs.
// This file holds the wire types and the pure helpers the Assets and Surface
// pages share; it imports nothing from the app, so `node --test` can run it.

export type AssetKind = "domain" | "hostname" | "ip";

export type SurfaceSeverity = "critical" | "high" | "medium" | "low" | "info";

export type SurfaceAsset = {
  id: number;
  kind: AssetKind;
  value: string;
  label: string;
  dkimSelectors: string[];
  sharedHosting: boolean;
  mailHost: boolean;
  /** The "I am authorised to test this asset" confirmation. Nothing is scanned without it. */
  authorised: boolean;
  authorisedBy: string;
  authorisedAt: string | null;
  createdBy: string;
  createdAt: string;
  lastScanAt: string | null;
};

export type SurfaceFinding = {
  id: number;
  assetId: number;
  assetKind: AssetKind;
  assetValue: string;
  /** The check group: spf, dmarc, dkim, tls-cert, ports, ... */
  check: string;
  findingId: string;
  subject: string;
  severity: SurfaceSeverity;
  title: string;
  detail: string;
  fix: string;
  evidence: Record<string, unknown>;
  controls: string[];
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
};

export type SurfaceCheck = {
  check: string;
  assessed: boolean;
  reason: string;
  observed: Record<string, unknown>;
  observedAt: string;
  scanId: number;
};

export type SurfaceAssetState = SurfaceAsset & {
  open: Partial<Record<SurfaceSeverity, number>>;
  checks: SurfaceCheck[];
  /** Checks that could not reach a conclusion: missing evidence, not a pass. */
  notAssessed: SurfaceCheck[];
  scanning: boolean;
};

export type SurfaceFindingsResponse = {
  findings: SurfaceFinding[];
  assets: SurfaceAssetState[];
  total: number;
  truncated: boolean;
  generatedAt: string;
};

export type AssetsResponse = {
  assets: SurfaceAsset[];
  generatedAt: string;
};

export const SEVERITIES: SurfaceSeverity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: SurfaceSeverity | string): number {
  const i = SEVERITIES.indexOf(s as SurfaceSeverity);
  return i < 0 ? 0 : SEVERITIES.length - i;
}

const CHECK_LABELS: Record<string, string> = {
  mx: "Mail servers (MX)",
  spf: "SPF",
  dmarc: "DMARC",
  dkim: "DKIM",
  "mta-sts": "MTA-STS",
  "tls-rpt": "TLS-RPT",
  dnssec: "DNSSEC",
  caa: "CAA",
  cname: "CNAME targets",
  "tls-cert": "TLS certificate",
  "tls-legacy": "Legacy TLS versions",
  ports: "Open ports",
};

export function checkLabel(check: string): string {
  return CHECK_LABELS[check] ?? check;
}

export function kindLabel(kind: AssetKind): string {
  return kind === "ip" ? "IP address" : kind === "hostname" ? "Hostname" : "Domain";
}

/** Findings that need action: info is a note, never counted as one. */
export function actionable(f: Pick<SurfaceFinding, "severity" | "resolvedAt">): boolean {
  return f.resolvedAt === null && f.severity !== "info";
}

export type AssetGroup = {
  asset: SurfaceAssetState;
  /** Open findings, most severe first. */
  findings: SurfaceFinding[];
  /** Closed findings, newest first. */
  resolved: SurfaceFinding[];
  worst: SurfaceSeverity | null;
};

/**
 * Group findings under their assets. Every declared asset gets a group, even
 * with no findings: an asset that is missing from the page reads as "nothing
 * wrong", and it may simply never have been scanned.
 */
export function groupByAsset(assets: SurfaceAssetState[], findings: SurfaceFinding[]): AssetGroup[] {
  const groups = assets.map((asset): AssetGroup => ({ asset, findings: [], resolved: [], worst: null }));
  const byId = new Map(groups.map((g) => [g.asset.id, g]));
  for (const f of findings) {
    const g = byId.get(f.assetId);
    if (!g) continue;
    if (f.resolvedAt) g.resolved.push(f);
    else g.findings.push(f);
  }
  for (const g of groups) {
    g.findings.sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        a.check.localeCompare(b.check) ||
        a.findingId.localeCompare(b.findingId) ||
        a.subject.localeCompare(b.subject),
    );
    g.resolved.sort((a, b) => (b.resolvedAt ?? "").localeCompare(a.resolvedAt ?? ""));
    g.worst = g.findings.length ? g.findings[0].severity : null;
  }
  // Worst first; assets with nothing open after those; then by name.
  return groups.sort((a, b) => {
    const ra = a.worst ? severityRank(a.worst) : 0;
    const rb = b.worst ? severityRank(b.worst) : 0;
    return rb - ra || a.asset.value.localeCompare(b.asset.value);
  });
}

export type AssetStanding =
  | { kind: "unconfirmed"; text: string }
  | { kind: "never_scanned"; text: string }
  | { kind: "findings"; text: string }
  | { kind: "clean_partial"; text: string }
  | { kind: "clean"; text: string };

/**
 * What can honestly be said about an asset. "Nothing found" is only claimed
 * when every check ran; if some could not, the line says so.
 */
export function assetStanding(a: SurfaceAssetState): AssetStanding {
  if (!a.authorised) {
    return { kind: "unconfirmed", text: "Not confirmed as authorised to test, so it is not scanned." };
  }
  if (!a.lastScanAt) {
    return { kind: "never_scanned", text: "Not scanned yet." };
  }
  const open = (Object.entries(a.open) as [SurfaceSeverity, number][]).reduce(
    (n, [sev, count]) => (sev === "info" ? n : n + count),
    0,
  );
  if (open > 0) {
    return { kind: "findings", text: `${open} open finding${open === 1 ? "" : "s"} to act on.` };
  }
  const missing = a.notAssessed.length;
  if (missing > 0) {
    return {
      kind: "clean_partial",
      text: `Nothing found in the checks that ran, but ${missing} check${missing === 1 ? "" : "s"} could not be assessed.`,
    };
  }
  return { kind: "clean", text: "Nothing to act on." };
}

/** Counts per severity for a group, info included, in display order. */
export function severityCounts(findings: SurfaceFinding[]): { severity: SurfaceSeverity; count: number }[] {
  return SEVERITIES.map((severity) => ({ severity, count: findings.filter((f) => f.severity === severity).length })).filter(
    (c) => c.count > 0,
  );
}

/**
 * Validate the Assets form before it is sent. The server validates again; this
 * only saves a round trip and says what is wrong in the operator's words.
 */
export function validateAssetForm(input: { kind: AssetKind; value: string; dkimSelectors: string }): string | null {
  const v = input.value.trim();
  if (!v) return "Enter a domain, hostname or IP address.";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) || /[\s/?#@*]/.test(v)) {
    return "Enter just the name or address: no https://, path, port or wildcard.";
  }
  if (input.kind === "ip") {
    if (!/^[0-9a-f:.]+$/i.test(v) || !(v.includes(".") || v.includes(":"))) return "That is not an IP address.";
  } else {
    if (/^[0-9.]+$/.test(v) || v.includes(":")) return "That looks like an IP address. Choose the IP address type.";
    if (!v.includes(".")) return "Enter a fully qualified name such as example.com.";
  }
  if (input.kind !== "domain" && input.dkimSelectors.trim()) return "DKIM selectors apply to domains only.";
  return null;
}

export function splitSelectors(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}
