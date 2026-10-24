import assert from "node:assert/strict";
import { test } from "node:test";

import {
  agoLabel,
  fixDescription,
  fixEmptyText,
  fixTotal,
  intervalLines,
  isSurfaceResponse,
  observationText,
  surfaceCard,
  surfaceTrendSummary,
  surfaceWhere,
  unconfirmedNote,
  urgentLabel,
} from "./surface-exposure.ts";
import type { ExposureGroup, SurfaceSummary } from "./exposure-model.ts";

const NOW = Date.parse("2026-10-24T12:00:00Z");

function summary(over: Partial<SurfaceSummary> = {}): SurfaceSummary {
  return {
    assets: 3,
    unauthorised: 0,
    scanned: 3,
    findings: 5,
    bySeverity: { critical: 0, high: 1, medium: 3, low: 1 },
    info: 0,
    assetsAffected: 2,
    lastScanAt: "2026-10-24T10:00:00Z",
    checksNotAssessed: 0,
    ...over,
  };
}

// ---- the Fleet card --------------------------------------------------------------------------------

test("the card reads: N findings (x high) across M assets, last scanned <time>", () => {
  const c = surfaceCard(summary(), NOW);
  assert.equal(c.headline, "External surface: 5 findings (1 high) across 3 assets, last scanned 2 hours ago");
  assert.equal(c.state, "scanned");
  assert.equal(c.tone, "critical");
  assert.deepEqual(c.lines, ["on 2 of 3 assets"]);
});

test("critical and high are counted apart, a singular is singular, and none says none", () => {
  assert.match(
    surfaceCard(summary({ findings: 1, assets: 1, scanned: 1, bySeverity: { critical: 1 } }), NOW).headline,
    /^External surface: 1 finding \(1 critical\) across 1 asset, last scanned 2 hours ago$/,
  );
  assert.equal(urgentLabel({ critical: 2, high: 3 }), "(2 critical, 3 high)");
  const calm = surfaceCard(summary({ findings: 2, bySeverity: { medium: 1, low: 1 } }), NOW);
  assert.match(calm.headline, /\(none high or critical\)/);
  assert.equal(calm.tone, "warning");
});

test("zero findings is good news only if every check ran and every asset was scanned", () => {
  const clean = surfaceCard(summary({ findings: 0, bySeverity: {}, assetsAffected: 0 }), NOW);
  assert.equal(clean.tone, "good");
  assert.match(clean.headline, /^External surface: 0 findings \(none high or critical\) across 3 assets/);
  const blind = surfaceCard(summary({ findings: 0, bySeverity: {}, assetsAffected: 0, checksNotAssessed: 2 }), NOW);
  assert.equal(blind.tone, "neutral", "checks that could not run are not a pass");
  assert.ok(blind.lines.some((l) => /2 checks could not run .* not counted as passing/.test(l)));
  const partial = surfaceCard(summary({ findings: 0, bySeverity: {}, assetsAffected: 0, scanned: 2 }), NOW);
  assert.ok(partial.lines.some((l) => /1 confirmed asset not scanned yet/.test(l)));
});

test("an unscanned or undeclared surface is never presented as clean", () => {
  assert.equal(surfaceCard(undefined, NOW).state, "unavailable");
  assert.match(surfaceCard(undefined, NOW).lines[0], /Nothing here says the outside is clean/);
  const none = surfaceCard(summary({ assets: 0, unauthorised: 0, scanned: 0, findings: 0 }), NOW);
  assert.equal(none.state, "none");
  assert.equal(none.headline, "External surface: no assets declared");
  const unconfirmed = surfaceCard(summary({ assets: 0, unauthorised: 2, scanned: 0, findings: 0 }), NOW);
  assert.equal(unconfirmed.state, "unconfirmed");
  assert.match(unconfirmed.lines[0], /2 assets declared but not confirmed as authorised/);
  const unscanned = surfaceCard(summary({ scanned: 0, findings: 0, lastScanAt: null }), NOW);
  assert.equal(unscanned.state, "unscanned");
  assert.equal(unscanned.headline, "External surface: not scanned yet");
  assert.doesNotMatch(unscanned.headline, /0 findings/);
});

test("informational notes and unconfirmed assets are named, never counted as findings", () => {
  const c = surfaceCard(summary({ info: 3, unauthorised: 1 }), NOW);
  assert.ok(c.lines.some((l) => l === "3 informational notes not counted as findings."));
  assert.ok(c.lines.some((l) => /1 declared asset not confirmed as authorised/.test(l)));
});

test("agoLabel rounds down and says never for no scan", () => {
  assert.equal(agoLabel(null, NOW), "never");
  assert.equal(agoLabel("2026-10-24T11:59:30Z", NOW), "just now");
  assert.equal(agoLabel("2026-10-24T11:15:00Z", NOW), "45 minutes ago");
  assert.equal(agoLabel("2026-10-24T11:00:00Z", NOW), "1 hour ago");
  assert.equal(agoLabel("2026-10-23T13:00:00Z", NOW), "23 hours ago");
  assert.equal(agoLabel("2026-10-20T11:00:00Z", NOW), "4 days ago");
  assert.equal(agoLabel("not a date", NOW), "never");
});

// ---- the Fix this week card ----------------------------------------------------------------------------

const fixable = (advisories: number, surface?: number) => ({
  findings: advisories,
  advisories,
  hosts: 2,
  kev: { findings: 0, advisories: 0 },
  surface,
});

test("the list's length is vulnerabilities plus surface findings, and an older control plane still works", () => {
  assert.equal(fixTotal({ ...fixable(4, 5), total: 9 }), 9);
  assert.equal(fixTotal(fixable(4, 5)), 9);
  assert.equal(fixTotal(fixable(4)), 4);
});

test("the description keeps vulnerabilities and external findings apart", () => {
  assert.equal(
    fixDescription({ fixable: fixable(4, 5) }, 5),
    "4 vulnerabilities with a fix to install, across 2 hosts and 5 external surface findings. The top 5, most urgent first:",
  );
  assert.equal(fixDescription({ fixable: fixable(0, 1) }, 1), "1 external surface finding. The top 1, most urgent first:");
  assert.equal(fixDescription({ fixable: fixable(0, 0) }, 0), "Nothing with a fix to install, and no external finding open.");
});

test("the description names end-of-life releases to upgrade apart from patches to install", () => {
  const eol = (n: number) => ({ findings: n, advisories: n });
  assert.equal(
    fixDescription({ fixable: { ...fixable(5, 1), eol: eol(2) } }, 5),
    "3 vulnerabilities with a fix to install and 2 end-of-life releases to upgrade, across 2 hosts and 1 external surface finding. The top 5, most urgent first:",
  );
  assert.equal(
    fixDescription({ fixable: { ...fixable(1), eol: eol(1) } }, 1),
    "1 end-of-life release to upgrade, across 2 hosts. The top 1, most urgent first:",
  );
});

test("an empty list claims no more than was checked", () => {
  const hosts = { total: 3, assessed: 3, notAssessed: 0, silent: 0, silentList: [] };
  assert.equal(
    fixEmptyText({ hosts, surface: summary({ findings: 0 }) }),
    "Nothing to install on the 3 assessed hosts. No external surface finding is open.",
  );
  assert.match(fixEmptyText({ hosts, surface: summary({ scanned: 0, findings: 0 }) }), /The external surface has not been scanned, so that says nothing either\.$/);
  assert.match(fixEmptyText({ hosts: { ...hosts, assessed: 0, notAssessed: 3 }, surface: undefined }), /^No host has been assessed yet.* 3 hosts not assessed\.$/);
});

// ---- rows and the drawer ---------------------------------------------------------------------------------

function group(over: Partial<NonNullable<ExposureGroup["surface"]>> = {}): Pick<ExposureGroup, "summary" | "surface"> {
  return {
    summary: "Port 445/tcp (SMB) is reachable",
    surface: {
      findingId: 7, assetId: 1, assetKind: "ip", assetValue: "192.0.2.10", check: "ports", id: "ports.open", subject: "445/tcp",
      detail: "", fix: "", lastSeen: "2026-10-22T06:00:00Z", unconfirmed: false, ...over,
    },
  };
}

test("surfaceWhere names the asset, the check and the subject once", () => {
  assert.equal(surfaceWhere(group()), "192.0.2.10 · Open ports · 445/tcp");
  assert.equal(
    surfaceWhere(group({ assetValue: "example.com", assetKind: "domain", check: "dmarc", id: "dmarc.p_none", subject: "example.com" })),
    "example.com · DMARC",
  );
  assert.equal(surfaceWhere({ summary: "x" }), "");
});

test("a finding whose check could not run says so, with the date it was last confirmed", () => {
  assert.equal(unconfirmedNote(group()), "");
  assert.equal(
    unconfirmedNote(group({ unconfirmed: true, check: "dmarc" })),
    "The latest DMARC check could not run: shown from the last confirmation on 2026-10-22.",
  );
});

test("intervals read as open on A, closed on B", () => {
  assert.deepEqual(
    intervalLines(
      [
        { openedAt: "2026-10-01T06:00:00Z", closedAt: "2026-10-09T06:00:00Z" },
        { openedAt: "2026-10-20T06:00:00Z", closedAt: null },
        { openedAt: "2026-10-24T09:00:00Z" },
      ],
      NOW,
    ),
    ["2026-10-01 to 2026-10-09 (8 days)", "2026-10-20 to now (open 4 days)", "2026-10-24 to now (opened today)"],
  );
});

test("the drawer tells a surface finding from a vulnerability", () => {
  assert.equal(isSurfaceResponse({ source: "surface" }), true);
  assert.equal(isSurfaceResponse({ source: "vulnerability" }), false);
  assert.equal(isSurfaceResponse({}), false, "an older control plane sends no source: a vulnerability");
  assert.equal(isSurfaceResponse(null), false);
});

test("the raw observation is shown whole up to a bound, then cut with a pointer to the export", () => {
  assert.equal(observationText({ record: "v=spf1 -all" }), '{\n  "record": "v=spf1 -all"\n}');
  // A list of plain values reads across; a list of objects keeps its shape.
  assert.equal(observationText({ open: [22, 445, 3389], none: [] }), '{\n  "open": [22, 445, 3389],\n  "none": []\n}');
  assert.match(observationText({ certs: [{ cn: "a" }] }), /"certs": \[\n    \{\n      "cn": "a"/);
  const long = observationText({ record: "x".repeat(5000) }, 100);
  assert.ok(long.length < 200);
  assert.match(long, /more characters in the evidence export\)$/);
});

// ---- the trend --------------------------------------------------------------------------------------------

test("the surface trend sentence names the first and last known day, or says why there is no line", () => {
  const p = (day: string, surface: number, known: boolean) => ({ day, known: true, open: 0, kev: 0, watch: 0, surface, surfaceKnown: known });
  assert.equal(
    surfaceTrendSummary([p("2026-10-01", 0, false), p("2026-10-02", 5, true), p("2026-10-09", 2, true)]),
    "2 open external surface findings on 2026-10-09, down 3 since 2026-10-02 (5).",
  );
  assert.equal(surfaceTrendSummary([p("2026-10-02", 1, true), p("2026-10-03", 1, true)]), "1 open external surface finding on 2026-10-03, unchanged since 2026-10-02 (1).");
  assert.match(surfaceTrendSummary([p("2026-10-01", 0, false)], null), /No external surface scan has run yet/);
  assert.equal(surfaceTrendSummary([p("2026-10-01", 0, false)], "2026-11-01T00:00:00Z"), "No external surface scan in this window.");
});
