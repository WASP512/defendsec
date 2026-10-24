// External surface findings in the exposure view (slice 7b): the helpers the
// Fleet card, the ranked list and the drawer share. Pure, imports only the
// pure models, so `node --test` can run it.

import { checkLabel, type SurfaceCheck, type SurfaceFinding } from "./surface-model.ts";
import type { ExposureGroup, ExposureSummary, SurfaceSummary, TrendPoint } from "./exposure-model.ts";

function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

// ---- when ----------------------------------------------------------------------------

/** "3 hours ago", "2 days ago"; "never" for no scan. Whole units, rounded down. */
export function agoLabel(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const ms = now - Date.parse(iso);
  if (!Number.isFinite(ms)) return "never";
  const minutes = Math.floor(Math.max(0, ms) / 60_000);
  if (minutes < 60) return minutes < 2 ? "just now" : `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return plural(hours, "hour") + " ago";
  return plural(Math.floor(hours / 24), "day") + " ago";
}

// ---- the Fleet card ---------------------------------------------------------------------

export type SurfaceCardState = "unavailable" | "none" | "unconfirmed" | "unscanned" | "scanned";

export type SurfaceCard = {
  state: SurfaceCardState;
  tone: "neutral" | "good" | "warning" | "critical";
  /** "External surface: 5 findings (1 high) across 3 assets, last scanned 2 hours ago" */
  headline: string;
  /** Anything the headline must not be read without. */
  lines: string[];
};

/** "(1 critical, 2 high)" or "(none high or critical)": the part of the count that needs a person today. */
export function urgentLabel(by: Record<string, number>): string {
  const parts = (["critical", "high"] as const).filter((s) => (by[s] ?? 0) > 0).map((s) => `${by[s]} ${s}`);
  return parts.length === 0 ? "(none high or critical)" : `(${parts.join(", ")})`;
}

/**
 * What the Fleet page says about the outside: N findings (x high) across M
 * assets, last scanned <time>. A surface that was never scanned is not "clean",
 * and checks that could not run are named, so zero findings is never read as
 * more than it is.
 */
export function surfaceCard(s: SurfaceSummary | undefined, now: number = Date.now()): SurfaceCard {
  if (!s) {
    return {
      state: "unavailable",
      tone: "neutral",
      headline: "External surface: unavailable",
      lines: ["The control plane could not be reached, or it is older than the surface exposure API. Nothing here says the outside is clean."],
    };
  }
  if (s.assets === 0 && s.unauthorised === 0) {
    return {
      state: "none",
      tone: "neutral",
      headline: "External surface: no assets declared",
      lines: ["Nothing is checked from the outside yet. Declare your domains and public addresses on the Assets page and confirm you are authorised to test them."],
    };
  }
  if (s.assets === 0) {
    return {
      state: "unconfirmed",
      tone: "warning",
      headline: "External surface: not scanned",
      lines: [`${plural(s.unauthorised, "asset")} declared but not confirmed as authorised to test, so nothing is scanned.`],
    };
  }
  if (s.scanned === 0) {
    return {
      state: "unscanned",
      tone: "neutral",
      headline: "External surface: not scanned yet",
      lines: [
        `${plural(s.assets, "asset")} confirmed; the first scan runs within a day, or start one on the Surface page. No result yet is not a clean result.`,
      ],
    };
  }
  const lines: string[] = [];
  if (s.findings > 0) lines.push(`on ${s.assetsAffected} of ${plural(s.assets, "asset")}`);
  if (s.checksNotAssessed > 0) {
    lines.push(
      `${plural(s.checksNotAssessed, "check")} could not run on the latest pass: missing evidence, not counted as passing.`,
    );
  }
  if (s.scanned < s.assets) lines.push(`${plural(s.assets - s.scanned, "confirmed asset")} not scanned yet.`);
  if (s.unauthorised > 0) lines.push(`${plural(s.unauthorised, "declared asset")} not confirmed as authorised, so not scanned.`);
  if (s.info > 0) lines.push(`${plural(s.info, "informational note")} not counted as findings.`);
  const urgent = (s.bySeverity.critical ?? 0) + (s.bySeverity.high ?? 0);
  return {
    state: "scanned",
    tone: urgent > 0 ? "critical" : s.findings > 0 ? "warning" : s.checksNotAssessed > 0 ? "neutral" : "good",
    headline:
      `External surface: ${plural(s.findings, "finding")} ${urgentLabel(s.bySeverity)} across ${plural(s.assets, "asset")}, ` +
      `last scanned ${agoLabel(s.lastScanAt, now)}`,
    lines,
  };
}

// ---- the Fix this week list ---------------------------------------------------------------

/** How many rows the Fix this week list has in all: vulnerabilities plus surface findings. */
export function fixTotal(f: ExposureSummary["fixable"]): number {
  return f.total ?? f.advisories + (f.surface ?? 0);
}

/** The card's description: what is in the list, in words that keep the two kinds apart. */
export function fixDescription(summary: Pick<ExposureSummary, "fixable">, shown: number): string {
  const { fixable } = summary;
  const surface = fixable.surface ?? 0;
  if (fixable.advisories === 0 && surface === 0) return "Nothing with a fix to install, and no external finding open.";
  const parts: string[] = [];
  if (fixable.advisories > 0) {
    // advisories counts patches to install and, since slice 10, end-of-life releases to upgrade.
    const eolN = fixable.eol?.advisories ?? 0;
    const vulnN = fixable.advisories - eolN;
    const what: string[] = [];
    if (vulnN > 0) what.push(`${plural(vulnN, "vulnerability", "vulnerabilities")} with a fix to install`);
    if (eolN > 0) what.push(`${plural(eolN, "end-of-life release")} to upgrade`);
    parts.push(`${what.join(" and ")}, across ${plural(fixable.hosts, "host")}`);
  }
  if (surface > 0) parts.push(`${plural(surface, "external surface finding")}`);
  return `${parts.join(" and ")}. The top ${shown}, most urgent first:`;
}

/** What an empty Fix this week list may say: good news only where something was actually checked. */
export function fixEmptyText(summary: Pick<ExposureSummary, "hosts" | "surface">): string {
  const { hosts, surface } = summary;
  const hostPart =
    hosts.assessed === 0
      ? "No host has been assessed yet, so this says nothing about the fleet."
      : `Nothing to install on the ${plural(hosts.assessed, "assessed host")}.`;
  const notAssessed = hosts.notAssessed > 0 ? ` ${plural(hosts.notAssessed, "host")} not assessed.` : "";
  let outside = "";
  if (surface === undefined) outside = "";
  else if (surface.scanned === 0) outside = " The external surface has not been scanned, so that says nothing either.";
  else outside = " No external surface finding is open.";
  return hostPart + notAssessed + outside;
}

// ---- rows ------------------------------------------------------------------------------------

type SurfaceGroup = Pick<ExposureGroup, "summary" | "surface">;

/** "client.example.com · DMARC" or "192.0.2.10 · Open ports · 445/tcp". */
export function surfaceWhere(g: SurfaceGroup): string {
  const s = g.surface;
  if (!s) return "";
  const parts = [s.assetValue, checkLabel(s.check)];
  if (s.subject && s.subject !== s.assetValue) parts.push(s.subject);
  return parts.join(" · ");
}

/** Said under a row whose check could not run on its latest pass. Empty when it did. */
export function unconfirmedNote(g: SurfaceGroup): string {
  const s = g.surface;
  if (!s || !s.unconfirmed) return "";
  return `The latest ${checkLabel(s.check)} check could not run: shown from the last confirmation on ${s.lastSeen.slice(0, 10)}.`;
}

// ---- the drawer --------------------------------------------------------------------------------

export type SurfaceInterval = { openedAt: string; closedAt?: string | null };

export type ExposureSurfaceResponse = {
  advisoryId: string;
  source: "surface";
  status: "open" | "resolved";
  detail: {
    key: string;
    finding: SurfaceFinding;
    /** Every span the finding was open, oldest first. */
    intervals: SurfaceInterval[];
    /** The observation of the scan that last confirmed (or, if resolved, settled) the finding. */
    confirmed: SurfaceCheck | null;
    /** The most recent observation of the check. */
    latest: SurfaceCheck | null;
    unconfirmed: boolean;
  };
};

/** The drawer's answer is either a vulnerability's or a surface finding's. */
export function isSurfaceResponse(r: { source?: string } | null | undefined): r is ExposureSurfaceResponse {
  return !!r && r.source === "surface";
}

const DAY_MS = 86_400_000;

function days(from: string, to: number): number {
  return Math.max(0, Math.floor((to - Date.parse(from)) / DAY_MS));
}

/** One line per span: "2026-10-01 to 2026-10-09 (8 days)", "2026-10-20 to now (open 4 days)". */
export function intervalLines(intervals: SurfaceInterval[], now: number = Date.now()): string[] {
  return intervals.map((i) => {
    const from = i.openedAt.slice(0, 10);
    if (i.closedAt) {
      const n = days(i.openedAt, Date.parse(i.closedAt));
      return `${from} to ${i.closedAt.slice(0, 10)} (${plural(n, "day")})`;
    }
    const n = days(i.openedAt, now);
    return n === 0 ? `${from} to now (opened today)` : `${from} to now (open ${plural(n, "day")})`;
  });
}

/** The raw observation as text an operator can compare with dig or openssl; bounded so a huge record cannot flood the drawer. */
export function observationText(observed: Record<string, unknown>, max = 4000): string {
  // Lists of plain values stay on one line: a port list is read across, not down.
  const text = (JSON.stringify(observed, null, 2) ?? "{}").replace(/\[\s*([^[\]{}]*?)\s*\]/g, (_m, inner: string) => `[${inner.replace(/\s*\n\s*/g, " ")}]`);
  return text.length <= max ? text : `${text.slice(0, max)}\n… (${text.length - max} more characters in the evidence export)`;
}

// ---- the trend ------------------------------------------------------------------------------------

/** One sentence the surface line's reader can check, or why there is no line. */
export function surfaceTrendSummary(points: TrendPoint[], since?: string | null): string {
  const known = points.filter((p) => p.surfaceKnown);
  if (known.length === 0) {
    return since ? "No external surface scan in this window." : "No external surface scan has run yet: the surface line starts with the first one.";
  }
  const first = known[0];
  const last = known[known.length - 1];
  const a = first.surface ?? 0;
  const b = last.surface ?? 0;
  const delta = b - a;
  const trend = delta === 0 ? "unchanged" : delta < 0 ? `down ${-delta}` : `up ${delta}`;
  return `${plural(b, "open external surface finding")} on ${last.day}, ${trend} since ${first.day} (${a}).`;
}
