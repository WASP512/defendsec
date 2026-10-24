// Vulnerability findings as the control plane computes them (GET /v1/findings).
//
// The console no longer matches software against a catalogue itself: apid
// matches each host's packages against the distro's own advisory ranges and
// stores the result. This file holds the wire types and the pure helpers the
// pages share; it imports nothing from the app, so `node --test` can run it.

import type { FindingStatus, FindingTriage } from "./types.ts";

/** finding: a fix is available. unfixed: affected, no fix published.
 *  informational: the distro will not fix it, or is still investigating. */
export type FindingKind = "finding" | "unfixed" | "informational";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "unknown";

/** What each finding was computed from: advisory, range, snapshot, feed. */
export type VulnFinding = {
  id: number;
  deviceId: string;
  hostname?: string;
  advisoryId: string;
  cve: string;
  family: string;
  /** The key the triage store uses; stable across matcher runs. */
  key: string;
  rangeId: number | null;
  snapshotId: number | null;
  feed: string;
  feedDate: string | null;
  kind: FindingKind;
  basis: "distro" | "upstream";
  package: string;
  sourcePackage: string;
  installed: string;
  fixed: string;
  fixState: string;
  severity: FindingSeverity;
  summary: string;
  kev: boolean;
  epss: number | null;
  cvss: number | null;
  reason: string;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
};

export type Coverage = "covered" | "no_feed" | "no_distro";

export type HostVulnState = {
  deviceId: string;
  distro: string;
  release: string;
  coverage: Coverage;
  packages: number;
  distroMapped: number;
  upstream: number;
  undecidable: number;
  notAffected: number;
  snapshotId: number | null;
  matchedAt: string;
};

export type FindingsResponse = {
  findings: VulnFinding[];
  total: number;
  truncated: boolean;
  state: HostVulnState | null;
  latestSnapshotId: number | null;
  generatedAt: string;
};

export type DeviceFindingsSummary = {
  deviceId: string;
  distro: string;
  release: string;
  coverage: Coverage;
  open: number;
  kev: number;
  unfixed: number;
  informational: number;
  /** Triage keys of open findings that are critical, high or KEV. */
  seriousKeys: string[];
  matchedAt: string;
};

export type FindingsSummaryResponse = {
  devices: DeviceFindingsSummary[];
  latestSnapshotId: number | null;
  generatedAt: string;
};

export type FindingDetail = {
  finding: VulnFinding;
  advisory: {
    id: string;
    cve: string;
    summary: string;
    severity: FindingSeverity;
    source: string;
    cvssVector: string;
    cvssScore: number | null;
    cwe: string[];
    kev: boolean;
    kevAdded: string | null;
    epss: number | null;
    epssDate: string | null;
  } | null;
  range: {
    id: number;
    ecosystem: string;
    distro: string;
    release: string;
    package: string;
    sourcePackage: string;
    introduced: string;
    fixed: string;
    fixState: string;
    snapshotId: number | null;
    feed: string;
  } | null;
  snapshot: {
    id: number;
    createdAt: string;
    feeds: { name: string; url: string; fetchedAt: string; sha256: string; recordCount: number }[];
  } | null;
};

export function findingStatus(key: string, triages: FindingTriage[]): FindingStatus {
  return triages.find((t) => t.key === key)?.status ?? "open";
}

const SEVERITY_ORDER: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

export function severityRank(severity: FindingSeverity): number {
  return SEVERITY_ORDER[severity] ?? 4;
}

/** Open (not acknowledged) serious findings for one host. */
export function seriousOpen(summary: DeviceFindingsSummary | undefined, triages: FindingTriage[]): number {
  if (!summary) return 0;
  const acknowledged = new Set(triages.filter((t) => t.status === "acknowledged").map((t) => t.key));
  return summary.seriousKeys.filter((k) => !acknowledged.has(k)).length;
}

export type CoverageNotice = { tone: "amber"; title: string; detail: string };

/**
 * A host with no findings is only clean if a feed could have spoken for it.
 * Null when it could; otherwise the notice that says it was not assessed.
 */
export function coverageNotice(state: HostVulnState | null): CoverageNotice | null {
  if (!state) {
    return {
      tone: "amber",
      title: "Not assessed yet",
      detail: "This host has not been matched against the advisory feeds. Findings appear after its next inventory report.",
    };
  }
  const os = [state.distro, state.release].filter(Boolean).join(" ");
  if (state.coverage === "no_distro") {
    return {
      tone: "amber",
      title: "Not assessed: operating system unknown",
      detail:
        "This agent did not report its distribution (an older agent, or a platform without os-release), so distro advisory feeds cannot be applied. Update the agent.",
    };
  }
  if (state.coverage === "no_feed") {
    return {
      tone: "amber",
      title: `Not assessed: no advisory feed for ${os || "this release"}`,
      detail:
        "No feed for this distribution and release is loaded, so an empty list does not mean the host is patched. Enable a feed for it in defendsec-feeds, or import a bundle.",
    };
  }
  return null;
}

/** "ubuntu-jammy, fetched 2026-10-20" */
export function feedLabel(f: Pick<VulnFinding, "feed" | "feedDate">): string {
  const date = f.feedDate ? f.feedDate.slice(0, 10) : "date unknown";
  return `${f.feed || "unknown feed"}, fetched ${date}`;
}

/** "fixed in 1:8.9p1-3ubuntu0.10" / "no fix published". */
export function fixLabel(f: Pick<VulnFinding, "fixed" | "kind" | "fixState">): string {
  if (f.fixed) return `fixed in ${f.fixed}`;
  if (f.fixState === "will_not_fix") return "the distro will not fix this";
  if (f.fixState === "under_investigation") return "the distro is investigating";
  return "no fix published";
}
