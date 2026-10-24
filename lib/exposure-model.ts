// The exposure view: the ranked "fix this week" list, its provenance and the
// trend, as the control plane serves them (GET /v1/exposure/*).
//
// apid ranks, pages and counts in the database; this file holds the wire types
// and the pure helpers the pages share. It imports nothing from the app, so
// `node --test` can run it. The ranking rule lives in internal/exposure (Go);
// compareRank below states the same rule so the console can check that a page
// it was handed is in rank order and say why each row sits where it does.

import { upgradeLabel } from "./findings-model.ts";
import type { EolDetail, FindingKind, FindingSeverity, RepoDetail } from "./findings-model.ts";
import { repoCodeLabel, repoFixPhrase } from "./patch-reliability.ts";
import type { FindingTriage } from "./types.ts";

/**
 * What a row of the ranked list is: a vulnerability (one advisory, with the
 * hosts it affects) or, since slice 7b, one external surface finding. An older
 * control plane sends no `source`: that is a vulnerability.
 */
export type ExposureSource = "vulnerability" | "surface" | "identity";

/** The part of an identity row (slice 12) the list needs; the drawer fetches the rest. */
export type IdentityRow = {
  findingId: number;
  /** "m365" or "google". */
  provider: string;
  /** What a person reads: a user principal name, "user · rule name", or the tenant. */
  subject: string;
  /** The check group: mfa, legacy-auth, admin-roles, inbox-rules. */
  check: string;
  /** The condition: mfa.not_registered, inbox_rule.hides_mail, ... */
  id: string;
  /** Tells apart several of one condition (an object id). */
  key: string;
  detail: string;
  fix: string;
  /** When a run last confirmed the finding. */
  lastSeen: string;
  /** The latest run could not assess this finding's check; shown from the last confirmation. */
  unconfirmed: boolean;
};

/** The part of a surface row the list needs; the drawer fetches the rest. */
export type SurfaceRow = {
  findingId: number;
  assetId: number;
  assetKind: "domain" | "hostname" | "ip";
  assetValue: string;
  /** The check group: spf, dmarc, ports, tls-cert, ... */
  check: string;
  /** The condition: dmarc.p_none, ports.open, ... */
  id: string;
  subject: string;
  detail: string;
  fix: string;
  /** When a scan last confirmed the finding. */
  lastSeen: string;
  /** The latest run of this check could not reach a conclusion; shown from the last confirmation. */
  unconfirmed: boolean;
};

/** One advisory with the hosts it affects: a row of the ranked list. */
export type ExposureGroup = {
  advisoryId: string;
  cve: string;
  summary: string;
  severity: FindingSeverity;
  kev: boolean;
  /** YYYY-MM-DD, the day the advisory was added to the KEV catalog. */
  kevAdded: string | null;
  epss: number | null;
  cvss: number | null;
  kinds: FindingKind[];
  hostCount: number;
  /** The first few hosts by name; the drawer lists them all. */
  hosts: { deviceId: string; hostname: string }[];
  findingCount: number;
  packages: string[];
  fixed: string[];
  firstSeen: string;
  resolvedAt: string | null;
  /** YYYY-MM-DD Red Hat shipped the fix an awaiting_vendor finding is waiting for. */
  awaitingSince: string | null;
  /** Set on an end-of-life row (advisory id "EOL:<product>:<cycle>"). */
  eol?: ExposureEol | null;
  /** Set on a repository-health row (advisory id "REPO:<12 hex>"). */
  repo?: ExposureRepo | null;
  source?: ExposureSource;
  /**
   * Set on a surface row. Its advisoryId is the row key ("surface:<12 digits>"),
   * its summary the finding's title; it has no hosts, KEV, EPSS or CVSS.
   */
  surface?: SurfaceRow;
  /**
   * Set on an identity row. Its advisoryId is the row key ("identity:<12 digits>"),
   * its summary the finding's title; it has no hosts, KEV, EPSS or CVSS.
   */
  identity?: IdentityRow;
};

/** The repository a repository-health row is about. */
export type ExposureRepo = {
  label: string;
  manager: string;
  /** The most serious problem found: key_expired, key_missing, no_index, index_stale, ... */
  code: string;
};

/** The release an end-of-life row is about. */
export type ExposureEol = {
  product: string;
  productLabel: string;
  cycle: string;
  /** "eol": security support ended. "eoas": active support ended. */
  stage: "eol" | "eoas";
  /** YYYY-MM-DD the stage began. */
  date: string;
  upgradeTo: string;
  /** The repositories or vendors the packages came from. */
  origins: string[];
};

export type ExposureBucket = "fix" | "watch";
export type ExposureStatus = "open" | "acknowledged" | "resolved";

export type ExposurePageResponse = {
  findings: ExposureGroup[];
  next?: string;
  total: number;
  sort: string;
  bucket: ExposureBucket;
  status: "open" | "resolved";
  latestSnapshotId: number | null;
  generatedAt: string;
};

export type ExposureHostRow = {
  findingId: number;
  key: string;
  deviceId: string;
  hostname: string;
  kind: FindingKind;
  package: string;
  installed: string;
  fixed: string;
  fixState: string;
  reason: string;
  upstreamFixedOn: string;
  feed: string;
  feedDate: string | null;
  snapshotId: number | null;
  rangeId: number | null;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  resolution: "" | "fixed" | "package_removed" | "no_longer_affected";
  resolvedInstalled: string;
  /** End-of-life rows: where the packages came from, the release, the control tags. */
  origin?: string;
  originRepo?: string;
  eol?: EolDetail | null;
  /** Repository-health rows: the repository, every problem, the evidence and the fix. */
  repo?: RepoDetail | null;
  controls?: string[];
};

export type ExposureAdvisoryResponse = {
  advisoryId: string;
  /** Absent from a control plane older than slice 7b; a surface row's drawer answers with another shape. */
  source?: "vulnerability";
  bucket: ExposureBucket;
  status: "open" | "resolved";
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
  hosts: ExposureHostRow[];
  truncated: boolean;
  snapshots: {
    id: number;
    createdAt: string;
    feeds: { name: string; url: string; fetchedAt: string; sha256: string; recordCount: number }[];
  }[];
};

export type ExposureCount = { findings: number; advisories: number };

export type ExposureSummary = {
  hosts: {
    total: number;
    assessed: number;
    notAssessed: number;
    silent: number;
    silentList: { deviceId: string; hostname: string; lastSeen: string }[];
    /** Hosts whose pending-updates list cannot be believed because a repository failed a check. */
    patchUnreliable?: number;
  };
  /**
   * findings, advisories and hosts count patches to install and software to upgrade; eol is the
   * upgrade part (software past end of life from outside the distribution).
   */
  fixable: {
    findings: number;
    advisories: number;
    hosts: number;
    kev: ExposureCount;
    eol?: ExposureCount;
    /** Package repositories with an expired or missing key or a stale index: updates from them have stopped. */
    repoHealth?: ExposureCount;
    /** Open external surface findings that rank (critical, high, medium, low). Absent from an older control plane. */
    surface?: number;
    /** Open identity findings (slice 12). Absent from an older control plane. */
    identity?: number;
    /** advisories + surface + identity: the length of the Fix this week list. */
    total?: number;
  };
  watch: { unfixed: ExposureCount; awaitingVendor: ExposureCount; kev: ExposureCount };
  sca: { total: number; hosts: number; bySeverity: Record<string, number> };
  /** The external surface card. Absent from a control plane older than slice 7b. */
  surface?: SurfaceSummary;
  /** The identity posture card. Absent from a control plane older than slice 12. */
  identity?: IdentitySummary;
  fixThisWeek: ExposureGroup[];
  kevWatch: ExposureGroup[];
  latestSnapshotId: number | null;
  generatedAt: string;
};

export type SurfaceSummary = {
  /** Declared, confirmed as authorised and not removed: the assets that get scanned. */
  assets: number;
  /** Declared but not confirmed, so never scanned. */
  unauthorised: number;
  /** Of `assets`, how many have been scanned at least once. */
  scanned: number;
  /** Open findings that rank: critical, high, medium, low. Info is never counted. */
  findings: number;
  bySeverity: Record<string, number>;
  info: number;
  assetsAffected: number;
  lastScanAt: string | null;
  /** Checks whose latest run could not reach a conclusion. */
  checksNotAssessed: number;
};

export type IdentitySummary = {
  configured: boolean;
  /** The configured provider, or both joined by a comma; "m365" when none. */
  provider: string;
  /** The configured providers ("m365", "google"). Absent from a control plane older than slice 13. */
  providers?: string[];
  /** Open findings; all of them rank. */
  findings: number;
  bySeverity: Record<string, number>;
  lastRunAt: string | null;
  /** ok, partial or not_assessed; "" when no run yet. */
  lastStatus: "" | "ok" | "partial" | "not_assessed";
  lastReason: string;
  /** Check groups the latest run could not assess, of checksTotal. */
  checksNotAssessed: number;
  checksTotal: number;
};

export type TrendPoint = {
  day: string;
  known: boolean;
  open: number;
  kev: number;
  watch: number;
  /** External surface findings open that day (never info); a series of its own. */
  surface?: number;
  /** The critical and high part of `surface`. */
  surfaceHigh?: number;
  /** False before the first surface scan: the zeros mean no data. */
  surfaceKnown?: boolean;
  /** Identity findings open that day (slice 12); a series of its own. */
  identity?: number;
  /** The critical and high part of `identity`. */
  identityHigh?: number;
  /** False before the first identity run: the zeros mean no data. */
  identityKnown?: boolean;
};

export type ExposureTrend = {
  from: string;
  to: string;
  points: TrendPoint[];
  historySince: string | null;
  /** When the first surface scan started; null if none ever ran (or an older control plane). */
  surfaceSince?: string | null;
  /** When the first identity run started; null if none ever ran (or an older control plane). */
  identitySince?: string | null;
  period: { id: string; name: string; closed: boolean } | null;
  caveats: string[];
  generatedAt: string;
};

// ---- ranking ------------------------------------------------------------------

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export type Rankable = Pick<ExposureGroup, "advisoryId" | "severity" | "kev" | "kevAdded" | "epss" | "cvss"> & {
  eol?: ExposureEol | null;
  repo?: ExposureRepo | null;
  source?: ExposureSource;
  /** A surface row's finding; only its condition id is read (the reason text of an upcoming expiry). */
  surface?: Pick<SurfaceRow, "id"> | null;
};

/** True for a row that is a repository-health finding. */
export function isRepoRow(g: Pick<Rankable, "repo">): boolean {
  return Boolean(g.repo);
}

/** True for a row that is an external surface finding. */
export function isSurfaceRow(g: Pick<Rankable, "source">): boolean {
  return g.source === "surface";
}

/** True for a row that is an identity finding (slice 12). */
export function isIdentityRow(g: Pick<Rankable, "source">): boolean {
  return g.source === "identity";
}

// A surface and an identity finding rank by severity alone, under the same rules.
function ranksBySeverity(g: Pick<Rankable, "source">): boolean {
  return isSurfaceRow(g) || isIdentityRow(g);
}

/**
 * The CVSS-equivalent a surface finding ranks by when it is not urgent. It makes
 * the surface and vulnerability orders one order; it is never shown. Mirrors
 * exposure.SurfaceScore.
 */
export const SURFACE_SCORE: Record<string, number> = { critical: 9.5, high: 8.0, medium: 5.0, low: 2.0 };

/**
 * The CVSS-equivalent an end-of-life row ranks by: that of a high vulnerability
 * past end of security support, of a low one past end of active support. Never
 * shown. Mirrors exposure.EOLScore.
 */
export const EOL_SCORE: Record<string, number> = { eol: 8.0, eoas: 2.0 };

/**
 * 0: a KEV vulnerability. 1: a critical or high surface finding, software past
 * end of security support, or a repository with a key problem. 2: everything
 * else. Mirrors exposure.Band.
 */
export function rankBand(g: Rankable): 0 | 1 | 2 {
  if (ranksBySeverity(g) || isRepoRow(g)) return g.severity === "critical" || g.severity === "high" ? 1 : 2;
  if (g.eol && g.eol.stage in EOL_SCORE) return g.eol.stage === "eol" ? 1 : 2;
  return g.kev ? 0 : 2;
}

// A surface or end-of-life row has no exploitation signal, and the CVSS-equivalent of its severity or stage.
function effective(g: Rankable): Rankable {
  // A repository-health row ranks by its severity's CVSS-equivalent, as a surface or identity finding does.
  if (ranksBySeverity(g) || isRepoRow(g)) return { ...g, kev: false, kevAdded: null, epss: null, cvss: SURFACE_SCORE[g.severity] ?? null };
  if (g.eol && g.eol.stage in EOL_SCORE) return { ...g, kev: false, kevAdded: null, epss: null, cvss: EOL_SCORE[g.eol.stage] };
  return g;
}

/**
 * Which kind of row wins a tie on everything the ranking measures: a
 * vulnerability (0), software past end of life (1), a repository (2), an
 * identity finding (3), an external surface finding (4). A stated rule, not the
 * byte order of the ids. Mirrors exposure.TieRank (and k6 in the SQL).
 */
export function tieRank(g: Rankable): number {
  if (isSurfaceRow(g)) return 4;
  if (isIdentityRow(g)) return 3;
  if (isRepoRow(g)) return 2;
  if (g.eol && g.eol.stage in EOL_SCORE) return 1;
  return 0;
}

// Higher first; a missing score goes last (and is not the same as zero).
function byScoreDesc(a: number | null, b: number | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a === b ? 0 : a > b ? -1 : 1;
}

/**
 * The exposure order, most urgent first: on the KEV list before anything else;
 * among KEV, the most recently listed first (an undated entry last); then the
 * critical and high external surface findings (live for anyone on the internet,
 * no foothold or exploit needed); then EPSS high to low; then CVSS high to low;
 * then the vendor's severity label; then the kind of row (tieRank: vulnerability,
 * end-of-life, repository, identity, surface); then the row id, so the order is total. A
 * missing score ranks after any score, including 0. A medium or low surface
 * finding has no EPSS and the CVSS-equivalent of its severity, so it sits with
 * the vulnerabilities that have no EPSS score. Mirrors internal/exposure.Compare.
 *
 * An end-of-life row (slice 10) has no CVE and no score either. Software past
 * end of security support is in the same urgent band as a high surface finding,
 * the CVSS-equivalent of a high vulnerability (8.0): after KEV and before every
 * other vulnerability, whatever its EPSS, because nothing will ever patch it.
 * Past end of active support only, it ranks with the low CVSS-only
 * vulnerabilities (2.0), below every vulnerability that has an EPSS score.
 */
export function compareRank(a0: Rankable, b0: Rankable): number {
  const band = rankBand(a0) - rankBand(b0);
  if (band !== 0) return band;
  const a = effective(a0);
  const b = effective(b0);
  if (a.kev && b.kev) {
    // KEV dates are YYYY-MM-DD, so comparing the strings compares the days.
    const da = a.kevAdded;
    const db = b.kevAdded;
    if (da !== db) {
      if (da === null) return 1;
      if (db === null) return -1;
      return da > db ? -1 : 1;
    }
  }
  const e = byScoreDesc(a.epss, b.epss);
  if (e !== 0) return e;
  const c = byScoreDesc(a.cvss, b.cvss);
  if (c !== 0) return c;
  const s = (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4);
  if (s !== 0) return s;
  const t = tieRank(a0) - tieRank(b0);
  if (t !== 0) return t;
  return a.advisoryId < b.advisoryId ? -1 : a.advisoryId > b.advisoryId ? 1 : 0;
}

/** True if the rows are in rank order: the check that apid and the console agree. */
export function isRanked(rows: Rankable[]): boolean {
  for (let i = 1; i < rows.length; i++) if (compareRank(rows[i - 1], rows[i]) > 0) return false;
  return true;
}

// Two places, but three below 0.01: most findings have a tiny EPSS, and EPSS
// ranks before CVSS, so "0.004" and "0.001" must not both read "<0.01" while one
// outranks the other.
function epssText(v: number): string {
  if (v === 0) return "0.00";
  if (v >= 0.01) return v.toFixed(2);
  return v < 0.001 ? "<0.001" : v.toFixed(3);
}

export type RankReason = {
  /** What put the row here. Never CVSS alone. */
  headline: string;
  /** The other numbers, in the order they break ties. */
  details: string[];
  /** headline and details as one line. */
  text: string;
};

/**
 * Surface findings in the urgent band that are a deadline and not an open door: the
 * condition has not happened yet. Their reason must not say "live". Today that is a
 * certificate that expires within 7 days (internal/surface/tlscheck.go); an expired one
 * (tls.expired) is live and keeps the "live" wording.
 */
export const UPCOMING_SURFACE_IDS: ReadonlySet<string> = new Set(["tls.expires_soon"]);

/**
 * Why a row ranks where it does. The headline is the strongest signal the row
 * has: exploited in the wild, else the exploitation probability, else an honest
 * "no exploitation signal". CVSS is a detail, never the headline, because it
 * says how bad a bug could be and not whether anyone is using it.
 */
export function rankReason(g: Rankable): RankReason {
  let headline: string;
  const details: string[] = [];
  if (g.repo) {
    // No CVE and no score: the repository's state is the signal. A dead repository hides
    // the vulnerabilities it would have fixed, so it ranks with the urgent findings.
    headline =
      g.severity === "high" || g.severity === "critical"
        ? `Updates from this repository have stopped: ${repoCodeLabel(g.repo.code)}`
        : `Repository index out of date: ${repoCodeLabel(g.repo.code)}`;
    details.push("no exploitation score applies");
    details.push(
      rankBand(g) === 1
        ? "ranks after exploited vulnerabilities and before every other vulnerability, because it hides what it would have fixed"
        : "ranks with the medium-scored vulnerabilities that have no EPSS score",
    );
  } else if (g.eol) {
    // No CVE and no score: the release calendar is the signal, and saying so
    // is better than printing "no exploitation signal" as if it were missing.
    const e = g.eol;
    const since = e.date ? ` since ${e.date}` : "";
    headline = e.stage === "eol" ? `Past end of security support${since}` : `Past end of active support${since}`;
    details.push(
      e.stage === "eol"
        ? "no one patches it any more, so every future flaw stays open"
        : "security fixes continue until its end of life",
    );
    details.push("no exploitation score applies");
    if (e.origins.length > 0) details.push(`installed from ${e.origins.join(", ")}, not the distribution`);
    details.push(
      e.stage === "eol"
        ? "ranks after exploited vulnerabilities and before every other vulnerability, as no fix will ever come"
        : "ranks with the low-scored vulnerabilities, below every vulnerability that has an EPSS score",
    );
  } else if (isIdentityRow(g)) {
    // No KEV, EPSS or CVSS exists for an account or a mailbox rule; say what its place does rest on.
    if (rankBand(g) === 1) {
      headline = "In effect now in the client's tenant: a password or a rule is all an intruder needs, no exploit";
      details.push(`${g.severity} severity`, "ranks after exploited vulnerabilities and before every other vulnerability");
    } else {
      headline = "No exploitation signal (identity finding)";
      details.push(`ranked by severity ${g.severity}`, "alongside vulnerabilities with no EPSS score");
    }
  } else if (isSurfaceRow(g)) {
    // No KEV, EPSS or CVSS exists for a DNS or TLS finding; say what its place does rest on.
    if (rankBand(g) === 1 && g.surface && UPCOMING_SURFACE_IDS.has(g.surface.id)) {
      // Not in effect yet: the certificate is still valid today. Saying "live" would be wrong,
      // and the urgency is a deadline, not an open door.
      headline = "Not yet in effect, but with a deadline: every visitor is refused when it lapses, and no attacker is needed";
      details.push(`${g.severity} severity`, "ranks after exploited vulnerabilities and before every other vulnerability, because the lapse is days away");
    } else if (rankBand(g) === 1) {
      headline = "Live for anyone on the internet: no foothold or exploit needed";
      details.push(`${g.severity} severity`, "ranks after exploited vulnerabilities and before every other vulnerability");
    } else {
      headline = "No exploitation signal (external surface finding)";
      details.push(`ranked by severity ${g.severity}`, "alongside vulnerabilities with no EPSS score");
    }
  } else if (g.kev) {
    headline = g.kevAdded
      ? `Exploited in the wild since ${g.kevAdded}`
      : "Exploited in the wild (CISA KEV; listing date not recorded)";
    if (g.epss !== null) details.push(`EPSS ${epssText(g.epss)}`);
    if (g.cvss !== null) details.push(`CVSS ${g.cvss.toFixed(1)}`);
  } else if (g.epss !== null) {
    headline = `EPSS ${epssText(g.epss)}`;
    details.push("not on the CISA KEV list");
    if (g.cvss !== null) details.push(`CVSS ${g.cvss.toFixed(1)}`);
  } else if (g.cvss !== null) {
    headline = "No exploitation signal (not on the CISA KEV list, no EPSS score)";
    details.push(`ranked by CVSS ${g.cvss.toFixed(1)}`);
  } else {
    headline = "No exploitation signal and no CVSS score";
    details.push(g.severity === "unknown" ? "vendor severity unknown" : `vendor severity ${g.severity}`);
  }
  return { headline, details, text: [headline, ...details].join(" · ") };
}

// ---- age, status, resolution ------------------------------------------------------

const DAY_MS = 86_400_000;

/** Whole days between two instants, never negative. */
export function ageDays(from: string, to: string | number = Date.now()): number {
  const end = typeof to === "number" ? to : Date.parse(to);
  return Math.max(0, Math.floor((end - Date.parse(from)) / DAY_MS));
}

/** "open 12 days (first seen 2026-10-11)", or "closed after 3 days (2026-10-11 to 2026-10-14)". */
export function ageLabel(firstSeen: string, resolvedAt: string | null, now: number = Date.now()): string {
  const first = firstSeen.slice(0, 10);
  if (resolvedAt) {
    const n = ageDays(firstSeen, resolvedAt);
    return `closed after ${n} ${n === 1 ? "day" : "days"} (${first} to ${resolvedAt.slice(0, 10)})`;
  }
  const n = ageDays(firstSeen, now);
  if (n === 0) return `open since today (first seen ${first})`;
  return `open ${n} ${n === 1 ? "day" : "days"} (first seen ${first})`;
}

/** Acknowledged is the operator's note in the console; resolved is the control plane's record. */
export function hostStatus(row: Pick<ExposureHostRow, "key" | "resolvedAt">, triages: FindingTriage[]): ExposureStatus {
  if (row.resolvedAt) return "resolved";
  return triages.some((t) => t.key === row.key && t.status === "acknowledged") ? "acknowledged" : "open";
}

/** A group is acknowledged only when every host's finding is. */
export function groupStatus(
  rows: Pick<ExposureHostRow, "key" | "resolvedAt">[],
  triages: FindingTriage[],
): ExposureStatus {
  if (rows.length === 0) return "open";
  const statuses = rows.map((r) => hostStatus(r, triages));
  if (statuses.every((s) => s === "resolved")) return "resolved";
  const live = statuses.filter((s) => s !== "resolved");
  return live.every((s) => s === "acknowledged") ? "acknowledged" : "open";
}

/** How a closed finding closed, in words an operator can check against the host. */
export function resolutionLabel(
  row: Pick<ExposureHostRow, "resolvedAt" | "resolution" | "resolvedInstalled" | "fixed" | "package"> & { kind?: FindingKind },
): string | null {
  if (!row.resolvedAt) return null;
  if (row.kind === "repo_health") {
    // A repository finding closes because the repository passes its checks now, or because the host no longer uses it.
    if (row.resolution === "fixed") return "Fixed: the repository passes its signature and freshness checks now";
    if (row.resolution === "no_longer_affected") return "The repository is no longer enabled on this host";
    return "Closed; the reason was not recorded";
  }
  switch (row.resolution) {
    case "fixed":
      return `Fixed: inventory shows ${row.package} ${row.resolvedInstalled}` + (row.fixed ? ` (fix was ${row.fixed})` : "");
    case "package_removed":
      return `Package ${row.package} is no longer installed`;
    case "no_longer_affected":
      return `${row.package} ${row.resolvedInstalled} is no longer listed as affected (the advisory data changed)`;
    default:
      return "Closed; the reason was not recorded";
  }
}

/** "no fix published" / "fixed by Red Hat on 2026-10-22; awaiting Rocky/Alma" for a watch-bucket row. */
export function watchLabel(g: Pick<ExposureGroup, "kinds" | "awaitingSince">): string {
  const parts: string[] = [];
  if (g.kinds.includes("awaiting_vendor")) {
    parts.push(
      g.awaitingSince
        ? `Fixed by Red Hat on ${g.awaitingSince}; awaiting Rocky/Alma`
        : "Fixed by Red Hat; awaiting Rocky/Alma",
    );
  }
  if (g.kinds.includes("unfixed")) parts.push("No fix published");
  return parts.join(" · ");
}

/**
 * The release an opened end-of-life row is about, read from its host findings:
 * the drawer can be opened on a link, without the list row that carries it.
 * Null when none of the rows is an end-of-life finding.
 */
export function eolOfHosts(hosts: Pick<ExposureHostRow, "eol" | "origin">[]): ExposureEol | null {
  const first = hosts.find((h) => h.eol);
  if (!first?.eol) return null;
  const e = first.eol;
  const origins = [...new Set(hosts.map((h) => h.eol?.origin ?? h.origin ?? "").filter(Boolean))].sort();
  return { product: e.product, productLabel: e.productLabel, cycle: e.cycle, stage: e.stage, date: e.stageFrom, upgradeTo: e.upgradeTo ?? "", origins };
}

/**
 * The repository an opened repository-health row is about, read from its host
 * findings (the drawer can be opened on a link, without the list row).
 */
export function repoOfHosts(hosts: Pick<ExposureHostRow, "repo">[]): ExposureRepo | null {
  const first = hosts.find((h) => h.repo);
  if (!first?.repo) return null;
  const top = first.repo.problems.find((p) => p.severity === "high") ?? first.repo.problems[0];
  return { label: first.repo.label, manager: first.repo.manager, code: top?.code ?? "" };
}

/** "3 hosts: alpha, bravo, charlie" or "12 hosts: alpha, bravo, charlie and 9 more". */
export function hostsLabel(g: Pick<ExposureGroup, "hostCount" | "hosts">): string {
  const n = g.hostCount;
  const names = g.hosts.map((h) => h.hostname || h.deviceId);
  const more = n - names.length;
  return `${n} ${n === 1 ? "host" : "hosts"}: ${names.join(", ")}${more > 0 ? ` and ${more} more` : ""}`;
}

/** What the fixed versions of a group say, one or several. */
export function fixedLabel(g: Pick<ExposureGroup, "fixed"> & { eol?: ExposureEol | null; repo?: ExposureRepo | null }): string {
  if (g.repo) return repoFixPhrase(g.repo.code);
  if (g.eol) return upgradeLabel({ productLabel: g.eol.productLabel, upgradeTo: g.eol.upgradeTo });
  if (g.fixed.length === 0) return "no fix recorded";
  return `fixed in ${g.fixed.join(", ")}`;
}

// ---- watch-bucket red callout --------------------------------------------------------

export type KevCallout = { tone: "red"; title: string; detail: string };

/**
 * Exploited in the wild with nothing to install: no fix is published, or the
 * vendor fixed it and the host's own distribution has not released the rebuild.
 * Not "fix this week", and it must not look safe: it needs a mitigation. Null
 * when there is none.
 */
export function kevWatchNotice(count: number): KevCallout | null {
  if (count <= 0) return null;
  return {
    tone: "red",
    title: `${count} exploited-in-the-wild ${count === 1 ? "vulnerability has" : "vulnerabilities have"} no patch to install`,
    detail:
      "These CVEs are on the CISA KEV list and either have no fix published, or Red Hat has fixed them and Rocky Linux or AlmaLinux has not released the rebuild yet. A patch cannot close them today: apply a mitigation or restrict exposure, and watch for the release.",
  };
}

// ---- the ranked list's URL ----------------------------------------------------------

export type ExposureListQuery = {
  bucket: ExposureBucket;
  status: "open" | "resolved";
  cursor: string;
  /** Cursors of the pages before this one, so Previous works with a forward-only keyset cursor. */
  back: string[];
  /** The advisory whose provenance drawer is open. */
  advisory: string;
};

export const EXPOSURE_PAGE_SIZE = 25;

const CURSOR_RE = /^[A-Za-z0-9_-]{1,600}$/;
type Params = Record<string, string | string[] | undefined>;

function one(v: string | string[] | undefined): string {
  return (Array.isArray(v) ? v[0] : v) ?? "";
}

/** Reads the page's search params, dropping anything malformed rather than passing it on. */
export function parseExposureQuery(params: Params): ExposureListQuery {
  const bucket = one(params.bucket);
  const status = one(params.status);
  const cursor = one(params.cursor);
  return {
    bucket: bucket === "watch" ? "watch" : "fix",
    status: status === "resolved" ? "resolved" : "open",
    cursor: CURSOR_RE.test(cursor) ? cursor : "",
    back: one(params.back)
      .split(".")
      .filter((c) => c === "0" || CURSOR_RE.test(c))
      .slice(-50),
    advisory: one(params.advisory).slice(0, 200),
  };
}

/** The control-plane request for a list query. */
export function exposureApiPath(q: Pick<ExposureListQuery, "bucket" | "status" | "cursor">): string {
  const p = new URLSearchParams({ sort: "rank", status: q.status, bucket: q.bucket, limit: String(EXPOSURE_PAGE_SIZE) });
  if (q.cursor) p.set("cursor", q.cursor);
  return `/v1/exposure/findings?${p}`;
}

function listHref(q: Pick<ExposureListQuery, "bucket" | "status">, cursor: string, back: string[], advisory = ""): string {
  const p = new URLSearchParams();
  if (q.bucket !== "fix") p.set("bucket", q.bucket);
  if (q.status !== "open") p.set("status", q.status);
  if (cursor) p.set("cursor", cursor);
  if (back.length) p.set("back", back.join("."));
  if (advisory) p.set("advisory", advisory);
  const s = p.toString();
  return s ? `/advisories?${s}` : "/advisories";
}

export function nextHref(q: ExposureListQuery, next: string | undefined): string | null {
  if (!next) return null;
  return listHref(q, next, [...q.back, q.cursor || "0"]);
}

export function prevHref(q: ExposureListQuery): string | null {
  if (!q.cursor) return null;
  const back = [...q.back];
  const prev = back.pop() ?? "0";
  return listHref(q, prev === "0" ? "" : prev, back);
}

/** The same page with an advisory's drawer open. */
export function drawerHref(q: ExposureListQuery, advisoryId: string): string {
  return listHref(q, q.cursor, q.back, advisoryId);
}

/** The same page with the drawer closed. */
export function closeDrawerHref(q: ExposureListQuery): string {
  return listHref(q, q.cursor, q.back);
}

/** The list for another bucket or status, from its first page. */
export function filterHref(bucket: ExposureBucket, status: "open" | "resolved"): string {
  return listHref({ bucket, status }, "", []);
}

export function pageNumber(q: ExposureListQuery): number {
  return q.cursor ? q.back.length + 1 : 1;
}

/** The control-plane request for one advisory's provenance. */
export function advisoryApiPath(id: string, bucket: ExposureBucket, status: "open" | "resolved"): string {
  return `/v1/exposure/advisory?${new URLSearchParams({ id, bucket, status })}`;
}

// ---- trend window ----------------------------------------------------------------------

export const TREND_WINDOWS = [30, 90, 180] as const;

export type TrendQuery = { days: number; periodId: string };

/** The window selector's state: a number of days back from now, or an audit period. */
export function parseTrendQuery(params: Params): TrendQuery {
  const days = Number(one(params.window));
  const period = one(params.period);
  return {
    days: (TREND_WINDOWS as readonly number[]).includes(days) ? days : 90,
    periodId: /^[A-Za-z0-9_-]{1,100}$/.test(period) ? period : "",
  };
}

export function trendApiPath(q: TrendQuery, now: Date = new Date()): string {
  if (q.periodId) return `/v1/exposure/trend?${new URLSearchParams({ periodId: q.periodId })}`;
  const from = new Date(now.getTime() - q.days * DAY_MS);
  return `/v1/exposure/trend?${new URLSearchParams({ from: from.toISOString(), to: now.toISOString() })}`;
}

export function trendHref(q: Partial<TrendQuery>): string {
  const p = new URLSearchParams();
  if (q.periodId) p.set("period", q.periodId);
  else if (q.days && q.days !== 90) p.set("window", String(q.days));
  const s = p.toString();
  return s ? `/?${s}` : "/";
}

export type TrendBar = {
  day: string;
  known: boolean;
  x: number;
  width: number;
  /** Heights in the same units as the chart's height. */
  openHeight: number;
  kevHeight: number;
  open: number;
  kev: number;
  watch: number;
};

export type TrendChart = {
  bars: TrendBar[];
  /** SVG points for the watch series, over the known days only; empty if there are none. */
  watchPoints: string;
  max: number;
};

/**
 * Lays the daily series out for an SVG of the given size: one bar per day, its
 * height the open fixable findings, the KEV part marked within it, and the
 * no-fix watch count as a line. The scale is the largest value shown, never a
 * fixed ceiling, so a quiet fleet is not flattened and a bad week is not clipped.
 */
export function trendChart(points: TrendPoint[], width: number, height: number): TrendChart {
  const n = points.length;
  const max = Math.max(1, ...points.map((p) => Math.max(p.open, p.watch)));
  if (n === 0) return { bars: [], watchPoints: "", max };
  const slot = width / n;
  const bars = points.map((p, i): TrendBar => ({
    day: p.day,
    known: p.known,
    x: i * slot,
    width: Math.max(1, slot * 0.8),
    openHeight: (p.open / max) * height,
    kevHeight: (Math.min(p.kev, p.open) / max) * height,
    open: p.open,
    kev: p.kev,
    watch: p.watch,
  }));
  const watchPoints = points
    .map((p, i) => (p.known ? `${(i * slot + slot * 0.4).toFixed(1)},${(height - (p.watch / max) * height).toFixed(1)}` : ""))
    .filter(Boolean)
    .join(" ");
  return { bars, watchPoints, max };
}

export type SurfaceBar = {
  day: string;
  known: boolean;
  x: number;
  width: number;
  height: number;
  /** The critical and high part of the bar. */
  highHeight: number;
  surface: number;
  high: number;
};

export type SurfaceChart = { bars: SurfaceBar[]; max: number };

/**
 * The external surface findings as a series of its own, on its own scale: a few
 * findings would be a flat line under hundreds of vulnerabilities, and the point
 * of the line is that an email-authentication fix visibly pays off. One bar per
 * day, the critical and high part marked within it; a day before the first
 * surface scan is not drawn as zero.
 */
export function surfaceChart(points: TrendPoint[], width: number, height: number): SurfaceChart {
  const n = points.length;
  const max = Math.max(1, ...points.map((p) => (p.surfaceKnown ? (p.surface ?? 0) : 0)));
  if (n === 0) return { bars: [], max };
  const slot = width / n;
  const bars = points.map((p, i): SurfaceBar => {
    const known = p.surfaceKnown === true;
    const surface = known ? (p.surface ?? 0) : 0;
    const high = known ? Math.min(p.surfaceHigh ?? 0, surface) : 0;
    return {
      day: p.day,
      known,
      x: i * slot,
      width: Math.max(1, slot * 0.8),
      height: (surface / max) * height,
      highHeight: (high / max) * height,
      surface,
      high,
    };
  });
  return { bars, max };
}

/** One sentence the chart's reader can check: first and last known day. */
export function trendSummary(points: TrendPoint[]): string {
  const known = points.filter((p) => p.known);
  if (known.length === 0) return "No history yet: no feed snapshot existed in this window.";
  const first = known[0];
  const last = known[known.length - 1];
  const delta = last.open - first.open;
  const trend = delta === 0 ? "unchanged" : delta < 0 ? `down ${-delta}` : `up ${delta}`;
  return `${last.open} open fixable ${last.open === 1 ? "finding" : "findings"} on ${last.day}, ${trend} since ${first.day} (${first.open}).`;
}
