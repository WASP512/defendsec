import assert from "node:assert/strict";
import { test } from "node:test";

import { compareRank, fixedLabel, rankBand, rankReason, repoOfHosts, resolutionLabel, type Rankable } from "./exposure-model.ts";
import { fixDescription, fixEmptyText } from "./surface-exposure.ts";
import type { ExposureSummary } from "./exposure-model.ts";
import type { RepoDetail } from "./findings-model.ts";
import { fixLabel } from "./findings-model.ts";
import {
  isUnreliable,
  patchReliabilityOf,
  pendingCountLabel,
  repoCodeLabel,
  repoFixPhrase,
  unreliableHostsNote,
  unreliablePatchPolicy,
  type RepoHealthReport,
} from "./patch-reliability.ts";
import type { Device } from "./types.ts";

function row(id: string, over: Partial<Rankable> = {}): Rankable {
  return { advisoryId: id, severity: "medium", kev: false, kevAdded: null, epss: null, cvss: null, ...over };
}

function repoRow(id: string, severity: Rankable["severity"], code = "key_expired"): Rankable {
  return row(id, { severity, repo: { label: "http://repo.example.invalid/apt stable", manager: "apt", code } });
}

// ---- ranking: the same rows as TestRepoHealthRanksWithEverythingElse in internal/storepg ------------------

test("repository rows rank with the urgent findings: high next to EOL and surface, medium with the CVSS-only CVEs", () => {
  const rows: Rankable[] = [
    row("F-cvss-only-3", { severity: "low", cvss: 3 }),
    repoRow("REPO:aaaaaaaaaaaa", "medium", "index_stale"),
    row("E-cvss-only-5", { cvss: 5 }),
    row("B-scored", { epss: 0.0002, cvss: 4 }),
    row("surface:000000000001", { severity: "high", source: "surface" }),
    repoRow("REPO:bbbbbbbbbbbb", "high"),
    row("EOL:php:8.0", {
      severity: "high",
      eol: { product: "php", productLabel: "PHP", cycle: "8.0", stage: "eol", date: "2023-11-26", upgradeTo: "8.4", origins: [] },
    }),
    row("A-kev", { kev: true, kevAdded: "2026-10-01", epss: 0.5, cvss: 8, severity: "high" }),
  ];
  const got = [...rows].sort(compareRank).map((r) => r.advisoryId);
  // At equal score and severity the id decides, bytewise: "EOL:" < "REPO:" < "surface:".
  assert.deepEqual(got, [
    "A-kev",
    "EOL:php:8.0",
    "REPO:bbbbbbbbbbbb",
    "surface:000000000001",
    "B-scored",
    "E-cvss-only-5",
    "REPO:aaaaaaaaaaaa",
    "F-cvss-only-3",
  ]);
});

test("a high repository row is in the urgent band after KEV; a medium one is in the rest band; scores it was handed are ignored", () => {
  assert.equal(rankBand(repoRow("REPO:x", "high")), 1);
  assert.equal(rankBand(repoRow("REPO:x", "medium")), 2);
  const withScores = { ...repoRow("REPO:x", "high"), epss: 0.99, cvss: 10, kev: false };
  assert.ok(compareRank(withScores, row("cve", { epss: 0.999, cvss: 10 })) < 0, "above a non-KEV CVE, whatever its EPSS");
  assert.ok(compareRank(row("z", { kev: true, kevAdded: "2019-01-01" }), withScores) < 0, "KEV beats a dead repository");
});

test("rankReason says the repository's state is the signal, not a missing score", () => {
  const high = rankReason(repoRow("REPO:x", "high"));
  assert.match(high.headline, /Updates from this repository have stopped: signing key expired/);
  assert.ok(high.details.some((d) => /hides what it would have fixed/.test(d)));
  assert.ok(!/no exploitation signal/i.test(high.text));
  const medium = rankReason(repoRow("REPO:x", "medium", "index_stale"));
  assert.match(medium.headline, /index out of date: index stale/i);
});

test("a repository row's fix is a keyring, not a package version", () => {
  assert.match(fixedLabel({ fixed: [], repo: { label: "r", manager: "apt", code: "key_expired" } }), /signing key \(signed-by keyring\)/);
  assert.match(fixedLabel({ fixed: [], repo: { label: "r", manager: "apt", code: "index_stale" } }), /refresh the index/);
  assert.match(fixLabel({ kind: "repo_health", fixed: "", fixState: "key_missing" }), /signing key/);
});

test("a closed repository finding says how it closed, in repository terms", () => {
  const base = { resolvedAt: "2026-10-24T00:00:00Z", resolvedInstalled: "", fixed: "", package: "r", kind: "repo_health" as const };
  assert.match(resolutionLabel({ ...base, resolution: "fixed" }) ?? "", /passes its signature and freshness checks/);
  assert.match(resolutionLabel({ ...base, resolution: "no_longer_affected" }) ?? "", /no longer enabled on this host/);
  assert.match(resolutionLabel({ ...base, resolution: "" }) ?? "", /reason was not recorded/);
});

test("repoOfHosts reads the repository and its worst problem from the host findings", () => {
  const detail: RepoDetail = {
    repoId: "r", label: "http://repo.example.invalid/apt stable", manager: "apt", signature: "expired_key", staleAfterDays: 7, fix: "x",
    problems: [
      { code: "index_stale", severity: "medium", title: "t", detail: "d" },
      { code: "key_expired", severity: "high", title: "t", detail: "d" },
    ],
  };
  assert.deepEqual(repoOfHosts([{ repo: null }, { repo: detail }]), { label: detail.label, manager: "apt", code: "key_expired" });
  assert.equal(repoOfHosts([{ repo: null }]), null);
});

// ---- the Fix this week text -------------------------------------------------------------------------------

function summary(over: Partial<ExposureSummary["fixable"]> = {}, hosts: Partial<ExposureSummary["hosts"]> = {}): ExposureSummary {
  return {
    hosts: { total: 5, assessed: 5, notAssessed: 0, silent: 0, silentList: [], ...hosts },
    fixable: { findings: 0, advisories: 0, hosts: 0, kev: { findings: 0, advisories: 0 }, ...over },
    watch: { unfixed: { findings: 0, advisories: 0 }, awaitingVendor: { findings: 0, advisories: 0 }, kev: { findings: 0, advisories: 0 } },
    sca: { total: 0, hosts: 0, bySeverity: {} },
    fixThisWeek: [],
    kevWatch: [],
    latestSnapshotId: null,
    generatedAt: "2026-10-24T00:00:00Z",
  };
}

test("the Fix this week description names repositories apart from vulnerabilities", () => {
  const text = fixDescription(
    summary({ advisories: 4, hosts: 2, eol: { findings: 1, advisories: 1 }, repoHealth: { findings: 2, advisories: 1 } }),
    4,
  );
  assert.match(text, /2 vulnerabilities with a fix to install/);
  assert.match(text, /1 end-of-life release to upgrade/);
  assert.match(text, /1 package repository whose updates have stopped/);
});

test("an empty Fix this week list does not call hosts with an unreliable patch list clean", () => {
  const text = fixEmptyText({ hosts: summary({}, { patchUnreliable: 2 }).hosts, surface: undefined });
  assert.match(text, /Nothing to install on the 5 assessed hosts/);
  assert.match(text, /2 hosts' pending updates cannot be trusted/);
  assert.ok(!/cannot be trusted/.test(fixEmptyText({ hosts: summary().hosts, surface: undefined })));
});

// ---- pending updates are never a clean zero beside a failed check ------------------------------------------

const brokenReport: RepoHealthReport = {
  manager: "apt",
  repos: [{ id: "r", label: "http://repo.example.invalid/apt stable", signature: "expired_key", keyId: "13EDAB264F59ECF5" }],
  assessment: {
    reliability: "unreliable",
    reasons: ["http://repo.example.invalid/apt stable: signing key 13EDAB264F59ECF5 has expired"],
    problems: [],
    checked: 1,
  },
};

function device(over: Partial<Device> = {}): Device {
  return {
    id: "d1", hostname: "alpha", platform: "linux", osName: "Ubuntu", osVersion: "22.04", arch: "amd64", serial: "", hardwareModel: "", cpu: "",
    memoryMb: 0, diskEncryption: null, firewall: null, ipAddresses: [], username: "", uptimeSeconds: 0, software: [], pendingUpdates: [],
    patchInventory: "ok", fim: [], fimBaseline: [], sample: false, enrolledAt: "", lastSeen: new Date().toISOString(), nodeKey: "",
    ...over,
  };
}

test("patchReliabilityOf reads the server's verdict, says unassessed for a Linux host that reports none, and n/a elsewhere", () => {
  assert.equal(patchReliabilityOf(device({ repoHealth: brokenReport })).state, "unreliable");
  assert.equal(patchReliabilityOf(device({ repoHealth: { ...brokenReport, assessment: { ...brokenReport.assessment!, reliability: "reliable", reasons: [] } } })).state, "reliable");
  assert.equal(patchReliabilityOf(device()).state, "unassessed");
  assert.equal(patchReliabilityOf(device({ platform: "windows" })).state, "n/a");
  assert.equal(patchReliabilityOf(device({ sample: true })).state, "n/a");
});

test("an unreliable host's count is never printed as a clean zero", () => {
  const r = patchReliabilityOf(device({ repoHealth: brokenReport }));
  assert.ok(isUnreliable(r));
  assert.match(pendingCountLabel(0, r), /0 pending — unreliable, not zero/);
  assert.match(pendingCountLabel(3, r), /list may be incomplete/);
  assert.equal(pendingCountLabel(0, { state: "reliable", reasons: [] }), "No pending updates");
});

test("the 'No pending patches' policy is unknown, not pass, for a host whose repository check failed", () => {
  const unreliable = unreliablePatchPolicy(0, patchReliabilityOf(device({ repoHealth: brokenReport })));
  assert.equal(unreliable?.status, "unknown");
  assert.match(unreliable?.detail ?? "", /unreliable, not zero/);
  assert.match(unreliable?.detail ?? "", /has expired/);
  // A reliable or unassessed host is judged by its count, as before.
  assert.equal(unreliablePatchPolicy(0, patchReliabilityOf(device())), null);
  assert.equal(unreliablePatchPolicy(0, { state: "reliable", reasons: [] }), null);
});

test("wording helpers", () => {
  assert.equal(repoCodeLabel("key_expired"), "signing key expired");
  assert.equal(repoCodeLabel("something_new"), "something new");
  assert.match(repoFixPhrase("no_index"), /signed-by/);
  assert.equal(unreliableHostsNote(0), "");
  assert.match(unreliableHostsNote(1), /^1 host's pending updates/);
});
