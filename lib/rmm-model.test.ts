import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { ago, coverageText, isRmmDeviceId, osSupportLine, rmmCard, unsupportedRmm, type RmmStatus, type RmmDeviceRow } from "./rmm-model.ts";

import type { OsRelease } from "./os-lifecycle.ts";

const NOW = new Date("2026-10-24T12:00:00Z");
// The one Windows end-of-support source: the endoflife.date calendar slice 10 loads (a real fetch, 2026-10-24).
const calendar = (JSON.parse(readFileSync(new URL("./testdata/os-calendar.json", import.meta.url), "utf8")) as { releases: OsRelease[] }).releases;

function status(over: Partial<RmmStatus["summary"]> = {}, creds: Partial<RmmStatus["credentials"]> = {}): RmmStatus {
  return {
    summary: {
      settings: { configured: true, siteUid: "s1", siteName: "Demo Client One", staleAfterDays: 7 },
      devices: 12, merged: 2, covered: 8, stale: 1, noData: 1, noFeed: 0, unmatched: 0,
      patchesApprovedPending: 9, patchesNotApproved: 4, devicesMissingPatches: 5, missingKbs: 6, missingKbsMapped: 6,
      findingsOpen: 40, findingsKev: 0, advisoriesOpen: 31, devicesWithFindings: 5, oldestAuditAt: "2026-10-10T00:00:00Z", feedLoaded: true,
      lastSync: {
        id: 1, siteUid: "s1", triggeredBy: "schedule", startedAt: "2026-10-24T08:00:00Z", finishedAt: "2026-10-24T08:05:00Z", status: "ok", reason: "",
        devices: 14, windows: 12, skipped: 2, stale: 1, unreadable: 0, merged: 2, kbsMissing: 6, kbsUnmapped: 0, findingsOpen: 40, requests: 80, errors: [],
      },
      ...over,
    },
    credentials: { configured: true, apiUrl: "https://pinotage-api.centrastage.net", warnings: [], ...creds },
    running: false, intervalHours: 6, scheduled: true, notAssessed: [], generatedAt: "2026-10-24T12:00:00Z", readOnlyNote: "",
  };
}

test("an unreachable control plane is unavailable, never an empty fleet", () => {
  const c = rmmCard(null, NOW);
  assert.equal(c.state, "unavailable");
  assert.match(c.lines.join(" "), /Nothing here says the Windows devices are clean/);
});

test("not configured says how, and does not read as zero devices", () => {
  const c = rmmCard(status({ settings: { configured: false, siteUid: "", siteName: "", staleAfterDays: 7 } }, { configured: false, problem: "Datto RMM is not configured: set DEFENDSEC_RMM_API_URL" }), NOW);
  assert.equal(c.state, "not-configured");
  assert.match(c.headline, /not read from Datto RMM/);
  assert.match(c.lines[0], /DEFENDSEC_RMM_API_URL/);
});

test("credentials present but no site", () => {
  const c = rmmCard(status({ settings: { configured: false, siteUid: "", siteName: "", staleAfterDays: 7 } }), NOW);
  assert.equal(c.state, "no-site");
});

test("a site never read, and a read that failed, say so", () => {
  assert.equal(rmmCard(status({ lastSync: null, devices: 0 }), NOW).state, "never-read");
  const failed = rmmCard(
    status({
      devices: 0,
      lastSync: {
        id: 2, siteUid: "s1", triggeredBy: "schedule", startedAt: "2026-10-24T08:00:00Z", finishedAt: "2026-10-24T08:00:02Z", status: "not_assessed",
        reason: "Datto RMM refused the API key and secret (HTTP 400): check them, or generate new keys", devices: 0, windows: 0, skipped: 0, stale: 0,
        unreadable: 0, merged: 0, kbsMissing: 0, kbsUnmapped: 0, findingsOpen: 0, requests: 1, errors: [],
      },
    }),
    NOW,
  );
  assert.equal(failed.state, "not-assessed");
  assert.match(failed.lines.join(" "), /refused the API key and secret/);
  assert.match(failed.lines.join(" "), /Nothing here says the Windows devices are clean/);
});

test("the happy card counts machines once, names what was not assessed and what is not covered", () => {
  const c = rmmCard(status(), NOW);
  assert.equal(c.state, "ok");
  assert.equal(c.headline, "Datto RMM: 10 Windows devices in Demo Client One"); // 12 read, 2 are also agents
  const text = c.lines.join("\n");
  assert.match(text, /5 devices missing updates that fix 31 vulnerabilities\./);
  assert.match(text, /2 devices not assessed: 1 with an audit older than 7 days, 1 with no usable data\. That is missing evidence, not a clean result\./);
  assert.match(text, /Third-party application vulnerabilities are not assessed from RMM data\./);
  assert.match(text, /Last read 4 hours ago\./);
  assert.equal(c.tone, "warning"); // devices were not assessed
});

test("KEV makes the card critical", () => {
  const c = rmmCard(status({ findingsKev: 2 }), NOW);
  assert.equal(c.tone, "critical");
  assert.match(c.lines[0], /2 findings exploited in the wild/);
});

test("everything assessed and nothing missing is good, and still lists what is out of scope", () => {
  const c = rmmCard(status({ stale: 0, noData: 0, devicesMissingPatches: 0, advisoriesOpen: 0, findingsOpen: 0 }), NOW);
  assert.equal(c.tone, "good");
  assert.match(c.lines[0], /No missing updates on the 8 devices assessed\./);
  assert.match(c.lines.join(" "), /Third-party application/);
});

test("no feed loaded and unmapped KBs are said, not hidden", () => {
  assert.match(rmmCard(status({ feedLoaded: false }), NOW).lines.join(" "), /Microsoft update feed is not loaded/);
  assert.match(rmmCard(status({ missingKbs: 9, missingKbsMapped: 6 }), NOW).lines.join(" "), /3 missing updates are not in the Microsoft feed/);
  assert.match(rmmCard(status({ missingKbs: 7, missingKbsMapped: 6 }), NOW).lines.join(" "), /1 missing update is not in the Microsoft feed/);
});

test("a partial read is a warning with its reason", () => {
  const s = status();
  s.summary.lastSync = { ...s.summary.lastSync!, status: "partial", reason: "Datto RMM is rate limiting this account (HTTP 429); the read stopped rather than keep asking" };
  const c = rmmCard(s, NOW);
  assert.equal(c.state, "partial");
  assert.match(c.lines.join(" "), /rate limiting/);
});

test("only a covered device reads as assessed", () => {
  assert.equal(coverageText("covered").label, "Assessed");
  for (const c of ["stale", "no_data", "no_feed", "", "whatever"]) {
    assert.notEqual(coverageText(c).label, "Assessed", c);
    assert.notEqual(coverageText(c).tone, "good", c);
  }
  assert.match(coverageText("stale").detail, /not the same as clean/);
});

test("ago", () => {
  assert.equal(ago(null, NOW), "never");
  assert.equal(ago("2026-10-24T11:59:30Z", NOW), "just now");
  assert.equal(ago("2026-10-24T11:00:00Z", NOW), "60 minutes ago");
  assert.equal(ago("2026-10-24T04:00:00Z", NOW), "8 hours ago");
  assert.equal(ago("2026-10-14T12:00:00Z", NOW), "10 days ago");
  assert.equal(ago("not a date", NOW), "unknown");
});

test("device ids", () => {
  assert.equal(isRmmDeviceId("rmm-dddddddd-0000-4000-8000-000000000001"), true);
  for (const bad of ["dddd", "rmm-", "rmm-a", "rmm-../etc", "rmm-a b c d", "agent-1", "rmm-" + "a".repeat(65)]) assert.equal(isRmmDeviceId(bad), false, bad);
});

const row = (hostname: string, osCaption: string, osVersion: string): RmmDeviceRow => ({
  id: "rmm-" + hostname, hostname, osCaption, osVersion, osDisplay: "", deviceType: "", online: true, lastSeen: null, lastAuditAt: null, patchStatus: "",
  patchesApprovedPending: 0, patchesNotApproved: 0, softwareCount: 0, coverage: "covered", reason: "", mergedInto: "", dedupeBasis: "", findingsOpen: 0, kevOpen: 0,
});

test("Windows 10 Pro 22H2 and old servers are unsupported; LTSC and Server 2019 are not (main's calendar, by edition)", () => {
  const list = unsupportedRmm(
    [
      row("PC-10", "Microsoft Windows 10 Pro", "10.0.19045"),
      row("PC-LTSC", "Microsoft Windows 10 Enterprise LTSC 2021", "10.0.19044"),
      row("SRV-2019", "Microsoft Windows Server 2019 Standard", "10.0.17763"),
      row("SRV-2012", "Microsoft Windows Server 2012 R2 Standard", "6.3.9600"),
      row("PC-ODD", "Microsoft Windows 10 Pro", ""),
      row("PC-11", "Microsoft Windows 11 Pro", "10.0.26200"),
    ],
    NOW,
    calendar,
  );
  assert.deepEqual(list.map((x) => x.hostname), ["PC-10", "SRV-2012"]);
});

test("without the release calendar a Windows device is unknown, never unsupported", () => {
  const list = unsupportedRmm([row("PC-10", "Microsoft Windows 10 Pro", "10.0.19045")], NOW, []);
  assert.deepEqual(list, []);
  assert.match(osSupportLine({ osCaption: "Microsoft Windows 10 Pro", osVersion: "10.0.19045" }, NOW, []), /^Support status unknown\./);
});

test("OS support line states the verdict and the calendar cycle it rests on", () => {
  const line = (osCaption: string, osVersion: string) => osSupportLine({ osCaption, osVersion }, NOW, calendar);
  assert.match(line("Microsoft Windows 10 Pro", "10.0.19045"), /^Past end of support\. .*2025-10-14/);
  assert.match(line("Microsoft Windows 10 Enterprise LTSC 2021", "10.0.19044"), /^Supported\. .*2027-01-12/);
  assert.match(line("Microsoft Windows Server 2019 Standard", "10.0.17763"), /^Supported\. .*2029-01-09/);
  assert.match(line("Microsoft Windows 10 Pro", ""), /^Support status unknown\. The Windows build number was not reported/);
});
