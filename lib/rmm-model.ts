// What the console says about the Datto RMM collector. Pure, so the wording (which
// must never read "clean" for something that was not assessed) is tested rather
// than assembled inline in a component.

import type { OsRelease } from "./os-lifecycle.ts";
import { supportedOs, windowsSupportOf } from "./supported-os.ts";

export type RmmCredentials = {
  configured: boolean;
  apiUrl: string;
  problem?: string;
  warnings: string[];
};

export type RmmSync = {
  id: number;
  siteUid: string;
  triggeredBy: string;
  startedAt: string;
  finishedAt: string;
  status: "ok" | "partial" | "not_assessed";
  reason: string;
  devices: number;
  windows: number;
  skipped: number;
  stale: number;
  unreadable: number;
  merged: number;
  kbsMissing: number;
  kbsUnmapped: number;
  findingsOpen: number;
  requests: number;
  errors: string[];
};

export type RmmSettings = {
  configured: boolean;
  siteUid: string;
  siteName: string;
  staleAfterDays: number;
  selectedBy?: string;
  selectedAt?: string;
};

export type RmmSummary = {
  settings: RmmSettings;
  devices: number;
  merged: number;
  covered: number;
  stale: number;
  noData: number;
  noFeed: number;
  unmatched: number;
  patchesApprovedPending: number;
  patchesNotApproved: number;
  devicesMissingPatches: number;
  missingKbs: number;
  missingKbsMapped: number;
  findingsOpen: number;
  findingsKev: number;
  advisoriesOpen: number;
  devicesWithFindings: number;
  oldestAuditAt: string | null;
  feedLoaded: boolean;
  lastSync: RmmSync | null;
};

export type RmmStatus = {
  summary: RmmSummary;
  credentials: RmmCredentials;
  running: boolean;
  intervalHours: number;
  scheduled: boolean;
  notAssessed: { what: string; why: string }[];
  generatedAt: string;
  readOnlyNote: string;
};

export type RmmSite = { uid: string; name: string; devices: number };

export type RmmDeviceRow = {
  id: string;
  hostname: string;
  osCaption: string;
  osVersion: string;
  osDisplay: string;
  deviceType: string;
  online: boolean;
  lastSeen: string | null;
  lastAuditAt: string | null;
  patchStatus: string;
  patchesApprovedPending: number;
  patchesNotApproved: number;
  softwareCount: number;
  coverage: string;
  reason: string;
  mergedInto: string;
  dedupeBasis: string;
  findingsOpen: number;
  kevOpen: number;
};

export type RmmPatchRow = {
  uid: string;
  kb: string;
  title: string;
  severity: string;
  type: string;
  status: string;
  releaseDate: string | null;
  rebootRequired: boolean;
  cves: number;
  kev: number;
  mapped: boolean;
};

export type RmmDeviceDetail = RmmDeviceRow & {
  siteUid: string;
  rmmUid: string;
  serial: string;
  osBuild: string;
  osInstallType: string;
  rebootRequired: boolean;
  lastReboot: string | null;
  patchesInstalled: number;
  antivirus: string;
  collectError: string;
  collectedAt: string;
  agentDeviceId: string;
  evidenceAt: string | null;
  kbsMissing: number;
  kbsMapped: number;
  patches: RmmPatchRow[];
  software: { name: string; version: string }[];
};

const DEVICE_ID = /^rmm-[A-Za-z0-9_-]{4,64}$/;

/** True for the id of a device read from an RMM (as opposed to an enrolled agent). */
export function isRmmDeviceId(id: string): boolean {
  return DEVICE_ID.test(id);
}

export function plural(n: number, one: string, many = one + "s"): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "3 days ago", "5 hours ago", "just now"; "never" for no time. */
export function ago(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "unknown";
  const s = Math.max(0, Math.round((now.getTime() - t) / 1000));
  if (s < 90) return "just now";
  const m = Math.round(s / 60);
  if (m < 90) return `${m} minutes ago`;
  const h = Math.round(m / 60);
  if (h < 36) return `${h} hours ago`;
  const d = Math.round(h / 24);
  return `${d} days ago`;
}

export type Tone = "good" | "warning" | "critical" | "neutral";

/** How a device's coverage reads. "covered" is the only state that may be called assessed. */
export function coverageText(coverage: string): { label: string; tone: Tone; detail: string } {
  switch (coverage) {
    case "covered":
      return { label: "Assessed", tone: "good", detail: "Fresh RMM evidence, matched against Microsoft's update feed." };
    case "stale":
      return {
        label: "Evidence too old",
        tone: "warning",
        detail: "The last RMM audit is older than the threshold. Software and patch evidence is missing, which is not the same as clean.",
      };
    case "no_data":
      return {
        label: "Not assessed",
        tone: "warning",
        detail: "RMM has no audit for this device, or its patches could not be read.",
      };
    case "no_feed":
      return {
        label: "No update feed",
        tone: "warning",
        detail: "No Microsoft update feed is loaded, so missing updates cannot be mapped to vulnerabilities.",
      };
    default:
      return { label: "Not matched yet", tone: "neutral", detail: "This device has not been matched since it was read." };
  }
}

export type RmmCard = {
  state: "unavailable" | "not-configured" | "no-site" | "never-read" | "not-assessed" | "partial" | "ok";
  tone: Tone;
  headline: string;
  lines: string[];
};

/**
 * The Fleet card. Numbers come from the control plane. A site that was never
 * read, or a read that failed, says so: an empty count must not read as a clean
 * fleet.
 */
export function rmmCard(status: RmmStatus | null, now: Date = new Date()): RmmCard {
  if (!status) {
    return {
      state: "unavailable",
      tone: "warning",
      headline: "Datto RMM status unavailable",
      lines: ["The control plane could not be reached, or it is older than the RMM API. Nothing here says the Windows devices are clean."],
    };
  }
  const s = status.summary;
  if (!status.credentials.configured && !s.settings.configured) {
    return {
      state: "not-configured",
      tone: "neutral",
      headline: "Windows devices are not read from Datto RMM",
      lines: [
        status.credentials.problem ?? "Datto RMM is not configured.",
        "Connecting it gives Windows coverage (OS, installed software, missing updates) with nothing installed on the PCs.",
      ],
    };
  }
  if (!s.settings.configured) {
    return {
      state: "no-site",
      tone: "neutral",
      headline: "Datto RMM is connected, but no site is selected",
      lines: ["Pick the one RMM site this instance reads."],
    };
  }
  const site = s.settings.siteName || "the selected site";
  const last = s.lastSync;
  if (!last) {
    return {
      state: "never-read",
      tone: "neutral",
      headline: `Datto RMM: ${site} has not been read yet`,
      lines: ["Nothing is known about its Windows devices until the first read."],
    };
  }
  if (last.status === "not_assessed" && s.devices === 0) {
    return {
      state: "not-assessed",
      tone: "warning",
      headline: `Datto RMM: ${site} could not be read`,
      lines: [last.reason || "The read did not complete.", `Last attempt ${ago(last.finishedAt, now)}. Nothing here says the Windows devices are clean.`],
    };
  }
  const notAssessed = s.stale + s.noData + s.noFeed + s.unmatched;
  const lines: string[] = [];
  if (s.devicesMissingPatches > 0) {
    const kev = s.findingsKev > 0 ? `, ${plural(s.findingsKev, "finding")} exploited in the wild` : "";
    lines.push(
      `${plural(s.devicesMissingPatches, "device")} missing updates that fix ${plural(s.advisoriesOpen, "vulnerability", "vulnerabilities")}${kev}.`,
    );
  } else if (s.covered > 0) {
    lines.push(`No missing updates on the ${plural(s.covered, "device")} assessed.`);
  }
  if (notAssessed > 0) {
    const parts: string[] = [];
    if (s.stale) parts.push(`${s.stale} with an audit older than ${s.settings.staleAfterDays} days`);
    if (s.noData) parts.push(`${s.noData} with no usable data`);
    if (s.noFeed) parts.push(`${s.noFeed} with no update feed to map against`);
    if (s.unmatched) parts.push(`${s.unmatched} not matched yet`);
    lines.push(`${plural(notAssessed, "device")} not assessed: ${parts.join(", ")}. That is missing evidence, not a clean result.`);
  }
  if (!s.feedLoaded) {
    lines.push("The Microsoft update feed is not loaded, so missing updates cannot be mapped to vulnerabilities (enable the msrc feed).");
  } else if (s.missingKbs > s.missingKbsMapped) {
    lines.push(`${s.missingKbs - s.missingKbsMapped} missing update${s.missingKbs - s.missingKbsMapped === 1 ? " is" : "s are"} not in the Microsoft feed (not security updates, or older than its window).`);
  }
  lines.push("Third-party application vulnerabilities are not assessed from RMM data.");
  lines.push(`Last read ${ago(last.finishedAt, now)}${last.status === "ok" ? "" : `: ${last.reason}`}.`);
  const partial = last.status !== "ok";
  return {
    state: partial ? "partial" : "ok",
    tone: s.findingsKev > 0 ? "critical" : partial || notAssessed > 0 ? "warning" : "good",
    headline: `Datto RMM: ${plural(s.devices - s.merged, "Windows device")} in ${site}`,
    lines,
  };
}

/**
 * Windows devices from RMM whose OS is past end of support, for the Fleet "also check" list.
 * The verdict is main's edition-aware calendar judgement (os-lifecycle.ts); RMM gives the
 * caption, not the EditionID, so the edition is read from the caption.
 */
export function unsupportedRmm(
  rows: RmmDeviceRow[],
  now: Date = new Date(),
  calendar?: OsRelease[] | null,
): { id: string; hostname: string; os: string }[] {
  return rows
    .filter((d) => supportedOs({ platform: "windows", osName: d.osCaption, osVersion: d.osVersion }, undefined, calendar, now) === false)
    .map((d) => ({ id: d.id, hostname: d.hostname, os: `${d.osCaption} ${d.osVersion}`.trim() }))
    .sort((a, b) => a.hostname.localeCompare(b.hostname));
}

/** One line about a device's OS support: the verdict and the calendar cycle it rests on. */
export function osSupportLine(
  d: { osCaption: string; osVersion: string },
  now: Date = new Date(),
  calendar?: OsRelease[] | null,
): string {
  const s = windowsSupportOf({ platform: "windows", osName: d.osCaption, osVersion: d.osVersion }, undefined, calendar, now);
  if (s.state === false) return `Past end of support. ${s.reason}.`;
  if (s.state === true) return `Supported. ${s.reason}.`;
  return `Support status unknown. ${s.reason}.`;
}
