import assert from "node:assert/strict";
import test from "node:test";
import {
  coverageNotice,
  feedLabel,
  findingStatus,
  fixLabel,
  seriousOpen,
  severityRank,
  type DeviceFindingsSummary,
  type HostVulnState,
} from "./findings-model.ts";

const summary = (over: Partial<DeviceFindingsSummary> = {}): DeviceFindingsSummary => ({
  deviceId: "d1",
  distro: "ubuntu",
  release: "22.04",
  coverage: "covered",
  open: 2,
  kev: 1,
  unfixed: 0,
  informational: 0,
  seriousKeys: ["d1:CVE-1:openssh", "d1:CVE-2:curl"],
  matchedAt: "2026-10-23T12:00:00Z",
  ...over,
});

const state = (over: Partial<HostVulnState> = {}): HostVulnState => ({
  deviceId: "d1",
  distro: "ubuntu",
  release: "22.04",
  coverage: "covered",
  packages: 600,
  distroMapped: 400,
  upstream: 0,
  undecidable: 0,
  notAffected: 0,
  snapshotId: 3,
  matchedAt: "2026-10-23T12:00:00Z",
  ...over,
});

test("acknowledged findings do not count as open serious ones", () => {
  const triages = [{ key: "d1:CVE-1:openssh", status: "acknowledged" as const, updatedAt: "" }];
  assert.equal(seriousOpen(summary(), []), 2);
  assert.equal(seriousOpen(summary(), triages), 1);
  assert.equal(seriousOpen(undefined, triages), 0);
  assert.equal(findingStatus("d1:CVE-1:openssh", triages), "acknowledged");
  assert.equal(findingStatus("d1:CVE-9:x", triages), "open");
});

test("a host no feed could speak for is reported as not assessed, not clean", () => {
  assert.equal(coverageNotice(state()), null);
  const noFeed = coverageNotice(state({ coverage: "no_feed", distro: "fedora", release: "40" }));
  assert.ok(noFeed);
  assert.match(noFeed.title, /no advisory feed for fedora 40/);
  const noDistro = coverageNotice(state({ coverage: "no_distro", distro: "", release: "" }));
  assert.ok(noDistro);
  assert.match(noDistro.title, /operating system unknown/);
  const never = coverageNotice(null);
  assert.ok(never);
  assert.match(never.title, /Not assessed yet/);
});

test("labels name the fix and the feed the finding came from", () => {
  assert.equal(fixLabel({ fixed: "1:8.9p1-3ubuntu0.10", kind: "finding", fixState: "fixed" }), "fixed in 1:8.9p1-3ubuntu0.10");
  assert.equal(fixLabel({ fixed: "", kind: "unfixed", fixState: "affected" }), "no fix published");
  assert.equal(fixLabel({ fixed: "", kind: "informational", fixState: "will_not_fix" }), "the distro will not fix this");
  assert.equal(feedLabel({ feed: "ubuntu-jammy", feedDate: "2026-10-20T03:00:00Z" }), "ubuntu-jammy, fetched 2026-10-20");
  assert.equal(feedLabel({ feed: "", feedDate: null }), "unknown feed, fetched date unknown");
});

test("severity ranks put critical first and unknown last", () => {
  const order = (["low", "unknown", "critical", "medium", "high"] as const).slice().sort((a, b) => severityRank(a) - severityRank(b));
  assert.deepEqual(order, ["critical", "high", "medium", "low", "unknown"]);
});
