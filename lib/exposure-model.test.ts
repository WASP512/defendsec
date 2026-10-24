import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ageDays,
  ageLabel,
  closeDrawerHref,
  compareRank,
  drawerHref,
  exposureApiPath,
  filterHref,
  fixedLabel,
  groupStatus,
  hostStatus,
  hostsLabel,
  isRanked,
  kevWatchNotice,
  nextHref,
  parseExposureQuery,
  parseTrendQuery,
  prevHref,
  rankReason,
  resolutionLabel,
  trendApiPath,
  trendChart,
  trendHref,
  trendSummary,
  watchLabel,
  type ExposureGroup,
  type Rankable,
} from "./exposure-model.ts";

function row(id: string, over: Partial<Rankable> = {}): Rankable {
  return { advisoryId: id, severity: "medium", kev: false, kevAdded: null, epss: null, cvss: null, ...over };
}

function sorted(rows: Rankable[]): string[] {
  return [...rows].sort(compareRank).map((r) => r.advisoryId);
}

// ---- the ranking function ---------------------------------------------------------------

test("KEV ranks before everything else, whatever the scores", () => {
  const kev = row("z-kev", { kev: true, kevAdded: "2020-01-01", epss: 0.001, cvss: 1 });
  const scary = row("a-scary", { epss: 0.999, cvss: 10, severity: "critical" });
  assert.deepEqual(sorted([scary, kev]), ["z-kev", "a-scary"]);
});

test("among KEV the newest listing is first, an undated one last", () => {
  const rows = [
    row("old", { kev: true, kevAdded: "2021-11-03", epss: 0.97, cvss: 10 }),
    row("undated", { kev: true, kevAdded: null, epss: 0.99, cvss: 10 }),
    row("new", { kev: true, kevAdded: "2026-09-14", epss: 0.02, cvss: 3 }),
  ];
  assert.deepEqual(sorted(rows), ["new", "old", "undated"]);
});

test("the same KEV day falls through to EPSS, then CVSS", () => {
  const rows = [
    row("low-epss-high-cvss", { kev: true, kevAdded: "2026-09-14", epss: 0.02, cvss: 9.8 }),
    row("high-epss", { kev: true, kevAdded: "2026-09-14", epss: 0.71, cvss: 5 }),
    row("same-epss-lower-cvss", { kev: true, kevAdded: "2026-09-14", epss: 0.02, cvss: 4 }),
  ];
  assert.deepEqual(sorted(rows), ["high-epss", "low-epss-high-cvss", "same-epss-lower-cvss"]);
});

test("without KEV: EPSS high to low, then CVSS, then severity, then id", () => {
  const rows = [
    row("d-nothing-low", { severity: "low" }),
    row("c-cvss-6", { cvss: 6 }),
    row("b-epss-mid-cvss-critical", { epss: 0.3, cvss: 9.9, severity: "critical" }),
    row("a-epss-high-cvss-3", { epss: 0.6, cvss: 3 }),
    row("e-nothing-critical", { severity: "critical" }),
    row("f-cvss-9", { cvss: 9 }),
    row("a-epss-high-cvss-3-twin", { epss: 0.6, cvss: 3 }),
  ];
  assert.deepEqual(sorted(rows), [
    "a-epss-high-cvss-3",
    "a-epss-high-cvss-3-twin",
    "b-epss-mid-cvss-critical",
    "f-cvss-9",
    "c-cvss-6",
    "e-nothing-critical",
    "d-nothing-low",
  ]);
});

test("a missing score ranks after a real zero", () => {
  assert.deepEqual(sorted([row("none"), row("zero", { epss: 0 })]), ["zero", "none"]);
  assert.deepEqual(sorted([row("none"), row("zero", { cvss: 0 })]), ["zero", "none"]);
});

test("compareRank is antisymmetric and total", () => {
  const rows = [
    row("a", { kev: true, kevAdded: "2026-01-01", epss: 0.5, cvss: 5 }),
    row("b", { kev: true, kevAdded: "2026-01-01", epss: 0.5, cvss: 5 }),
    row("c", { epss: 0.5, cvss: 5 }),
    row("d"),
  ];
  for (const x of rows) {
    assert.equal(compareRank(x, x), 0);
    for (const y of rows) {
      assert.equal(Math.sign(compareRank(x, y)) + 0, -Math.sign(compareRank(y, x)) + 0);
      if (x !== y) assert.notEqual(compareRank(x, y), 0);
    }
  }
});

test("isRanked accepts rank order and rejects anything else", () => {
  const ordered = [row("a", { kev: true, kevAdded: "2026-09-14" }), row("b", { epss: 0.5 }), row("c")];
  assert.equal(isRanked(ordered), true);
  assert.equal(isRanked([...ordered].reverse()), false);
  assert.equal(isRanked([]), true);
  assert.equal(isRanked([ordered[0]]), true);
});

// ---- "why it ranks here" ----------------------------------------------------------------------

test("a KEV row says since when it has been exploited, with EPSS and CVSS as detail", () => {
  const r = rankReason(row("x", { kev: true, kevAdded: "2026-09-14", epss: 0.71, cvss: 9.8 }));
  assert.equal(r.headline, "Exploited in the wild since 2026-09-14");
  assert.deepEqual(r.details, ["EPSS 0.71", "CVSS 9.8"]);
  assert.equal(r.text, "Exploited in the wild since 2026-09-14 · EPSS 0.71 · CVSS 9.8");
});

test("an undated KEV row does not invent a date", () => {
  const r = rankReason(row("x", { kev: true }));
  assert.match(r.headline, /Exploited in the wild/);
  assert.match(r.headline, /listing date not recorded/);
  assert.doesNotMatch(r.text, /since/);
});

test("a non-KEV row leads with EPSS and says it is not on KEV", () => {
  const r = rankReason(row("x", { epss: 0.71, cvss: 9.8 }));
  assert.equal(r.headline, "EPSS 0.71");
  assert.deepEqual(r.details, ["not on the CISA KEV list", "CVSS 9.8"]);
});

test("CVSS is never the headline", () => {
  for (const g of [
    row("cvss-only", { cvss: 9.8 }),
    row("nothing", {}),
    row("kev", { kev: true, cvss: 9.8 }),
    row("epss", { epss: 0.1, cvss: 9.8 }),
  ]) {
    const r = rankReason(g);
    assert.doesNotMatch(r.headline, /CVSS \d/, `${g.advisoryId}: ${r.headline}`);
  }
  const cvssOnly = rankReason(row("cvss-only", { cvss: 9.8 }));
  assert.match(cvssOnly.headline, /No exploitation signal/);
  assert.deepEqual(cvssOnly.details, ["ranked by CVSS 9.8"]);
});

test("a row with no scores says so and falls back to the vendor's label", () => {
  assert.equal(rankReason(row("x", { severity: "high" })).text, "No exploitation signal and no CVSS score · vendor severity high");
  assert.match(rankReason(row("x", { severity: "unknown" })).text, /vendor severity unknown/);
});

test("EPSS is shown to two places, three below 0.01 so ranked neighbours differ, with a floor for tiny values", () => {
  assert.equal(rankReason(row("x", { epss: 0 })).headline, "EPSS 0.00");
  assert.equal(rankReason(row("x", { epss: 0.004 })).headline, "EPSS 0.004");
  assert.equal(rankReason(row("x", { epss: 0.0004 })).headline, "EPSS <0.001");
  assert.equal(rankReason(row("x", { epss: 0.01 })).headline, "EPSS 0.01");
  assert.equal(rankReason(row("x", { epss: 0.9723 })).headline, "EPSS 0.97");
  assert.equal(rankReason(row("x", { kev: true, kevAdded: "2026-01-01", cvss: 10 })).details[0], "CVSS 10.0");
});

// ---- age, status, resolution ---------------------------------------------------------------

test("age counts whole days and never goes negative", () => {
  const now = Date.parse("2026-10-24T12:00:00Z");
  assert.equal(ageDays("2026-10-11T12:00:00Z", now), 13);
  assert.equal(ageDays("2026-10-24T11:00:00Z", now), 0);
  assert.equal(ageDays("2026-11-01T00:00:00Z", now), 0);
});

test("the age label reads open and closed intervals", () => {
  const now = Date.parse("2026-10-24T12:00:00Z");
  assert.equal(ageLabel("2026-10-11T08:00:00Z", null, now), "open 13 days (first seen 2026-10-11)");
  assert.equal(ageLabel("2026-10-23T08:00:00Z", null, now), "open 1 day (first seen 2026-10-23)");
  assert.equal(ageLabel("2026-10-24T08:00:00Z", null, now), "open since today (first seen 2026-10-24)");
  assert.equal(
    ageLabel("2026-10-11T08:00:00Z", "2026-10-14T09:00:00Z", now),
    "closed after 3 days (2026-10-11 to 2026-10-14)",
  );
});

test("status: resolved comes from the control plane, acknowledged from the operator", () => {
  const triages = [{ key: "d1:A:pkg", status: "acknowledged" as const, updatedAt: "" }];
  assert.equal(hostStatus({ key: "d1:A:pkg", resolvedAt: null }, triages), "acknowledged");
  assert.equal(hostStatus({ key: "d2:A:pkg", resolvedAt: null }, triages), "open");
  assert.equal(hostStatus({ key: "d1:A:pkg", resolvedAt: "2026-10-14T00:00:00Z" }, triages), "resolved");
});

test("a group is acknowledged only when every open host is, and resolved when none is open", () => {
  const triages = [
    { key: "d1:A:p", status: "acknowledged" as const, updatedAt: "" },
    { key: "d2:A:p", status: "acknowledged" as const, updatedAt: "" },
  ];
  const open = (key: string) => ({ key, resolvedAt: null });
  const closed = (key: string) => ({ key, resolvedAt: "2026-10-14T00:00:00Z" });
  assert.equal(groupStatus([open("d1:A:p"), open("d2:A:p")], triages), "acknowledged");
  assert.equal(groupStatus([open("d1:A:p"), open("d3:A:p")], triages), "open");
  assert.equal(groupStatus([open("d1:A:p"), closed("d3:A:p")], triages), "acknowledged");
  assert.equal(groupStatus([closed("d1:A:p"), closed("d3:A:p")], triages), "resolved");
  assert.equal(groupStatus([], triages), "open");
});

test("resolution wording says what the inventory showed", () => {
  const base = { resolvedAt: "2026-10-14T00:00:00Z", fixed: "3.0.2-15", package: "openssl", resolvedInstalled: "3.0.2-15" };
  assert.equal(resolutionLabel({ ...base, resolvedAt: null, resolution: "" }), null);
  assert.equal(
    resolutionLabel({ ...base, resolution: "fixed" }),
    "Fixed: inventory shows openssl 3.0.2-15 (fix was 3.0.2-15)",
  );
  assert.match(resolutionLabel({ ...base, resolution: "package_removed" }) ?? "", /no longer installed/);
  assert.match(resolutionLabel({ ...base, resolution: "no_longer_affected" }) ?? "", /advisory data changed/);
  assert.match(resolutionLabel({ ...base, resolution: "" }) ?? "", /reason was not recorded/);
});

test("watch labels keep the CEO's wording for awaiting_vendor and say when there is no fix", () => {
  assert.equal(
    watchLabel({ kinds: ["awaiting_vendor"], awaitingSince: "2026-10-22" }),
    "Fixed by Red Hat on 2026-10-22; awaiting Rocky/Alma",
  );
  assert.equal(watchLabel({ kinds: ["awaiting_vendor"], awaitingSince: null }), "Fixed by Red Hat; awaiting Rocky/Alma");
  assert.equal(watchLabel({ kinds: ["unfixed"], awaitingSince: null }), "No fix published");
  assert.equal(
    watchLabel({ kinds: ["awaiting_vendor", "unfixed"], awaitingSince: "2026-10-22" }),
    "Fixed by Red Hat on 2026-10-22; awaiting Rocky/Alma · No fix published",
  );
});

test("host and fix labels", () => {
  const hosts = [{ deviceId: "1", hostname: "alpha" }, { deviceId: "2", hostname: "bravo" }];
  assert.equal(hostsLabel({ hostCount: 2, hosts }), "2 hosts: alpha, bravo");
  assert.equal(hostsLabel({ hostCount: 12, hosts }), "12 hosts: alpha, bravo and 10 more");
  assert.equal(hostsLabel({ hostCount: 1, hosts: [hosts[0]] }), "1 host: alpha");
  assert.equal(fixedLabel({ fixed: [] }), "no fix recorded");
  assert.equal(fixedLabel({ fixed: ["1.2", "1.3"] }), "fixed in 1.2, 1.3");
});

test("the KEV callout appears only when something exploited has nothing to install", () => {
  assert.equal(kevWatchNotice(0), null);
  const notice = kevWatchNotice(1);
  if (!notice) throw new Error("expected a notice for one exploited advisory");
  assert.equal(notice.tone, "red");
  assert.match(notice.title, /^1 exploited-in-the-wild vulnerability has no patch/);
  assert.match(kevWatchNotice(3)?.title ?? "", /^3 exploited-in-the-wild vulnerabilities have/);
  assert.match(notice.detail, /mitigation/);
});

// ---- the list's URLs -------------------------------------------------------------------------------

test("list query parsing drops anything malformed", () => {
  assert.deepEqual(parseExposureQuery({}), { bucket: "fix", status: "open", cursor: "", back: [], advisory: "" });
  const q = parseExposureQuery({ bucket: "watch", status: "resolved", cursor: "abc_-1", back: "0.xyz", advisory: "CVE-1" });
  assert.deepEqual(q, { bucket: "watch", status: "resolved", cursor: "abc_-1", back: ["0", "xyz"], advisory: "CVE-1" });
  const bad = parseExposureQuery({ bucket: "all", status: "acknowledged", cursor: "a b;c", back: "../x.ok" });
  assert.deepEqual(bad, { bucket: "fix", status: "open", cursor: "", back: ["ok"], advisory: "" });
});

test("the API path asks for rank order, a bounded page and the cursor", () => {
  const path = exposureApiPath({ bucket: "fix", status: "open", cursor: "" });
  assert.equal(path, "/v1/exposure/findings?sort=rank&status=open&bucket=fix&limit=25");
  assert.match(exposureApiPath({ bucket: "watch", status: "resolved", cursor: "abc" }), /bucket=watch.*cursor=abc$/);
});

test("paging links work with a forward-only cursor", () => {
  const first = parseExposureQuery({});
  assert.equal(prevHref(first), null);
  assert.equal(nextHref(first, undefined), null);
  const toSecond = nextHref(first, "c2");
  assert.equal(toSecond, "/advisories?cursor=c2&back=0");
  const second = parseExposureQuery({ cursor: "c2", back: "0" });
  assert.equal(prevHref(second), "/advisories");
  const toThird = nextHref(second, "c3");
  assert.equal(toThird, "/advisories?cursor=c3&back=0.c2");
  const third = parseExposureQuery({ cursor: "c3", back: "0.c2" });
  assert.equal(prevHref(third), "/advisories?cursor=c2&back=0");
});

test("opening and closing the drawer keeps the page and the filters", () => {
  const q = parseExposureQuery({ bucket: "watch", cursor: "c2", back: "0" });
  const open = drawerHref(q, "RHSA-2026:1234");
  assert.equal(open, "/advisories?bucket=watch&cursor=c2&back=0&advisory=RHSA-2026%3A1234");
  assert.equal(closeDrawerHref(parseExposureQuery({ bucket: "watch", cursor: "c2", back: "0", advisory: "X" })), "/advisories?bucket=watch&cursor=c2&back=0");
  assert.equal(filterHref("watch", "open"), "/advisories?bucket=watch");
  assert.equal(filterHref("fix", "resolved"), "/advisories?status=resolved");
  assert.equal(filterHref("fix", "open"), "/advisories");
});

// ---- the trend ---------------------------------------------------------------------------------------

test("the trend window defaults to 90 days and accepts only the offered ones or an audit period", () => {
  assert.deepEqual(parseTrendQuery({}), { days: 90, periodId: "" });
  assert.deepEqual(parseTrendQuery({ window: "30" }), { days: 30, periodId: "" });
  assert.deepEqual(parseTrendQuery({ window: "7" }), { days: 90, periodId: "" });
  assert.deepEqual(parseTrendQuery({ period: "q3-2026" }), { days: 90, periodId: "q3-2026" });
  assert.deepEqual(parseTrendQuery({ period: "../x" }), { days: 90, periodId: "" });
});

test("the trend API path is a from/to window, or the audit period by id", () => {
  const now = new Date("2026-10-24T00:00:00Z");
  assert.equal(
    trendApiPath({ days: 30, periodId: "" }, now),
    "/v1/exposure/trend?from=2026-09-24T00%3A00%3A00.000Z&to=2026-10-24T00%3A00%3A00.000Z",
  );
  assert.equal(trendApiPath({ days: 30, periodId: "q3" }, now), "/v1/exposure/trend?periodId=q3");
  assert.equal(trendHref({ days: 90 }), "/");
  assert.equal(trendHref({ days: 180 }), "/?window=180");
  assert.equal(trendHref({ periodId: "q3" }), "/?period=q3");
});

test("the chart scales to the largest value shown and keeps unknown days apart", () => {
  const points = [
    { day: "2026-10-01", known: false, open: 0, kev: 0, watch: 0 },
    { day: "2026-10-02", known: true, open: 4, kev: 1, watch: 2 },
    { day: "2026-10-03", known: true, open: 8, kev: 2, watch: 10 },
  ];
  const c = trendChart(points, 300, 100);
  assert.equal(c.max, 10);
  assert.equal(c.bars.length, 3);
  assert.equal(c.bars[1].openHeight, 40);
  assert.equal(c.bars[1].kevHeight, 10);
  assert.equal(c.bars[2].openHeight, 80);
  assert.equal(c.bars[0].known, false);
  // The watch line starts at the first known day, not at an unknown one.
  assert.equal(c.watchPoints.split(" ").length, 2);
  assert.equal(c.watchPoints, "140.0,80.0 240.0,0.0");
  assert.deepEqual(trendChart([], 300, 100), { bars: [], watchPoints: "", max: 1 });
  assert.equal(trendChart([{ day: "d", known: true, open: 0, kev: 0, watch: 0 }], 100, 50).max, 1);
});

test("the chart summary is a sentence anyone can check against the bars", () => {
  assert.match(trendSummary([]), /No history yet/);
  assert.match(trendSummary([{ day: "d", known: false, open: 0, kev: 0, watch: 0 }]), /No history yet/);
  const p = (day: string, open: number) => ({ day, known: true, open, kev: 0, watch: 0 });
  assert.equal(trendSummary([p("2026-10-01", 9), p("2026-10-24", 4)]), "4 open fixable findings on 2026-10-24, down 5 since 2026-10-01 (9).");
  assert.equal(trendSummary([p("2026-10-01", 1), p("2026-10-24", 1)]), "1 open fixable finding on 2026-10-24, unchanged since 2026-10-01 (1).");
  assert.match(trendSummary([p("2026-10-01", 1), p("2026-10-24", 3)]), /up 2 since/);
});

test("ExposureGroup rows from the wire satisfy Rankable", () => {
  // A compile-time check as much as a runtime one: the wire type is rankable as is.
  const g: ExposureGroup = {
    advisoryId: "A", cve: "CVE-1", summary: "", severity: "high", kev: false, kevAdded: null, epss: 0.1, cvss: 7,
    kinds: ["finding"], hostCount: 1, hosts: [{ deviceId: "d", hostname: "h" }], findingCount: 1, packages: ["p"],
    fixed: ["2"], firstSeen: "2026-10-01T00:00:00Z", resolvedAt: null, awaitingSince: null,
  };
  assert.equal(isRanked([g]), true);
});
