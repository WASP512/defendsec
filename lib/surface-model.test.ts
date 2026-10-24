import assert from "node:assert/strict";
import test from "node:test";
import {
  actionable,
  assetStanding,
  checkLabel,
  groupByAsset,
  severityCounts,
  severityRank,
  splitSelectors,
  validateAssetForm,
  type SurfaceAssetState,
  type SurfaceCheck,
  type SurfaceFinding,
} from "./surface-model.ts";

const asset = (over: Partial<SurfaceAssetState> = {}): SurfaceAssetState => ({
  id: 1,
  kind: "domain",
  value: "example.com",
  label: "",
  dkimSelectors: [],
  sharedHosting: false,
  mailHost: false,
  authorised: true,
  authorisedBy: "mason",
  authorisedAt: "2026-10-24T06:00:00Z",
  createdBy: "mason",
  createdAt: "2026-10-24T06:00:00Z",
  lastScanAt: "2026-10-24T06:01:00Z",
  open: {},
  checks: [],
  notAssessed: [],
  scanning: false,
  ...over,
});

const finding = (over: Partial<SurfaceFinding> = {}): SurfaceFinding => ({
  id: 1,
  assetId: 1,
  assetKind: "domain",
  assetValue: "example.com",
  check: "dmarc",
  findingId: "dmarc.p_none",
  subject: "example.com",
  severity: "medium",
  title: "DMARC is monitoring only",
  detail: "",
  fix: "",
  evidence: {},
  controls: [],
  firstSeen: "2026-10-24T06:00:00Z",
  lastSeen: "2026-10-24T06:00:00Z",
  resolvedAt: null,
  ...over,
});

const missing = (check: string): SurfaceCheck => ({
  check,
  assessed: false,
  reason: "no DKIM selector found",
  observed: {},
  observedAt: "2026-10-24T06:01:00Z",
  scanId: 1,
});

test("severity order is critical, high, medium, low, info", () => {
  const order = ["info", "low", "medium", "high", "critical"].map(severityRank);
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
  assert.equal(severityRank("critical") > severityRank("high"), true);
  assert.equal(severityRank("nonsense"), 0);
});

test("findings are grouped under their asset, worst first, with closed ones kept apart", () => {
  const assets = [asset({ id: 1, value: "b.example.com" }), asset({ id: 2, value: "a.example.com" }), asset({ id: 3, value: "c.example.com" })];
  const findings = [
    finding({ id: 1, assetId: 1, severity: "low", findingId: "spf.softfail" }),
    finding({ id: 2, assetId: 2, severity: "critical", findingId: "spf.plus_all" }),
    finding({ id: 3, assetId: 2, severity: "medium", findingId: "dmarc.p_none" }),
    finding({ id: 4, assetId: 1, severity: "high", findingId: "dmarc.missing", resolvedAt: "2026-10-25T00:00:00Z" }),
    finding({ id: 5, assetId: 99, severity: "critical" }), // asset no longer declared: ignored
  ];
  const groups = groupByAsset(assets, findings);
  assert.deepEqual(
    groups.map((g) => g.asset.id),
    [2, 1, 3],
    "critical asset first, then low, then the one with nothing open",
  );
  assert.deepEqual(groups[0].findings.map((f) => f.id), [2, 3]);
  assert.equal(groups[0].worst, "critical");
  assert.deepEqual(groups[1].findings.map((f) => f.id), [1]);
  assert.deepEqual(groups[1].resolved.map((f) => f.id), [4]);
  assert.equal(groups[2].worst, null);
  assert.equal(groups.length, 3, "an asset with no findings still gets a group");
});

test("info is a note and does not count as something to act on", () => {
  assert.equal(actionable({ severity: "info", resolvedAt: null }), false);
  assert.equal(actionable({ severity: "low", resolvedAt: null }), true);
  assert.equal(actionable({ severity: "critical", resolvedAt: "2026-10-25T00:00:00Z" }), false);
});

test("an asset is never called clean when checks could not run", () => {
  assert.equal(assetStanding(asset({ authorised: false })).kind, "unconfirmed");
  assert.equal(assetStanding(asset({ lastScanAt: null })).kind, "never_scanned");
  assert.equal(assetStanding(asset({ open: { medium: 2, info: 1 } })).text, "2 open findings to act on.");
  assert.equal(assetStanding(asset({ open: { high: 1 } })).text, "1 open finding to act on.");
  const partial = assetStanding(asset({ notAssessed: [missing("dkim"), missing("tls-cert")] }));
  assert.equal(partial.kind, "clean_partial");
  assert.match(partial.text, /2 checks could not be assessed/);
  assert.equal(assetStanding(asset()).kind, "clean");
  // info alone is not "to act on"
  assert.equal(assetStanding(asset({ open: { info: 3 } })).kind, "clean");
});

test("severityCounts lists only what is present, most severe first", () => {
  const counts = severityCounts([finding({ severity: "low" }), finding({ severity: "critical" }), finding({ severity: "low" })]);
  assert.deepEqual(counts, [
    { severity: "critical", count: 1 },
    { severity: "low", count: 2 },
  ]);
});

test("asset form validation says what is wrong", () => {
  const ok = { kind: "domain" as const, value: "example.com", dkimSelectors: "" };
  assert.equal(validateAssetForm(ok), null);
  assert.equal(validateAssetForm({ ...ok, value: "  " }), "Enter a domain, hostname or IP address.");
  assert.match(validateAssetForm({ ...ok, value: "https://example.com" }) ?? "", /no https/);
  assert.match(validateAssetForm({ ...ok, value: "example.com/x" }) ?? "", /no https/);
  assert.match(validateAssetForm({ ...ok, value: "*.example.com" }) ?? "", /no https/);
  assert.match(validateAssetForm({ ...ok, value: "192.0.2.1" }) ?? "", /IP address/);
  assert.match(validateAssetForm({ ...ok, value: "localhost" }) ?? "", /fully qualified/);
  assert.equal(validateAssetForm({ kind: "ip", value: "192.0.2.1", dkimSelectors: "" }), null);
  assert.equal(validateAssetForm({ kind: "ip", value: "2001:db8::1", dkimSelectors: "" }), null);
  assert.match(validateAssetForm({ kind: "ip", value: "example.com", dkimSelectors: "" }) ?? "", /not an IP/);
  assert.match(validateAssetForm({ kind: "hostname", value: "www.example.com", dkimSelectors: "s1" }) ?? "", /domains only/);
});

test("selectors are split on commas and whitespace and lower-cased", () => {
  assert.deepEqual(splitSelectors(" Google, s1  k1\nmail "), ["google", "s1", "k1", "mail"]);
  assert.deepEqual(splitSelectors(""), []);
});

test("check labels fall back to the raw name", () => {
  assert.equal(checkLabel("mta-sts"), "MTA-STS");
  assert.equal(checkLabel("something-new"), "something-new");
});
