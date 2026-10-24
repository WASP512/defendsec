import assert from "node:assert/strict";
import { test } from "node:test";

import {
  isExact,
  missingChoices,
  opKindLabel,
  opStatusLabel,
  parseCompanyId,
  pickLabel,
  runResultLabel,
  runSummary,
  settingsPayload,
  withLabel,
  stateLabel,
  subIssuesFor,
  urgencyLabel,
  type PickItem,
} from "./autotask-model.ts";

const subs: PickItem[] = [
  { value: "200", label: "Vulnerability remediation", isDefault: false, parent: "20" },
  { value: "201", label: "Email security", isDefault: false, parent: "20" },
  { value: "210", label: "Printer", isDefault: false, parent: "21" },
];

test("sub-issue types are only those of the chosen issue type", () => {
  assert.deepEqual(
    subIssuesFor(subs, "20").map((s) => s.value),
    ["200", "201"],
  );
  assert.deepEqual(subIssuesFor(subs, "21").map((s) => s.value), ["210"]);
  assert.deepEqual(subIssuesFor(subs, ""), [], "no issue type chosen, nothing to offer");
  assert.deepEqual(subIssuesFor(subs, "99"), []);
});

test("a saved value that Autotask no longer lists is said so, never shown as a label it does not have", () => {
  const items: PickItem[] = [{ value: "101", label: "Security Test Queue", isDefault: false }];
  assert.equal(pickLabel(items, "101"), "Security Test Queue");
  assert.equal(pickLabel(items, "777"), "777 (not in Autotask's current list)");
  assert.equal(pickLabel(items, ""), "not set");
  assert.equal(pickLabel(undefined, "5"), "5 (not in Autotask's current list)");
});

test("the form names what is still to be chosen, and nothing is assumed", () => {
  const empty = { apiUser: "", companyId: 0, queueId: "", status: "", priorityCritical: "", priorityHigh: "", priorityMedium: "", noteType: "", notePublish: "" };
  assert.deepEqual(missingChoices(empty), [
    "the API user's name",
    "the Autotask company",
    "the queue",
    "the status of a new ticket",
    "a priority for each of critical, high and medium",
    "the note type and who may see a note",
  ]);
  const full = { ...empty, apiUser: "u@example.com", companyId: 3001, queueId: "101", status: "1", priorityCritical: "1", priorityHigh: "2", priorityMedium: "3", noteType: "1", notePublish: "2" };
  assert.deepEqual(missingChoices(full), []);
  assert.deepEqual(missingChoices({ ...full, priorityMedium: "" }), ["a priority for each of critical, high and medium"]);
  assert.deepEqual(missingChoices({ ...full, apiUser: "  " }), ["the API user's name"]);
});

test("company ids are plain positive integers", () => {
  assert.equal(parseCompanyId("29683805"), 29683805);
  assert.equal(parseCompanyId(" 3001 "), 3001);
  for (const bad of ["", "0", "-5", "12a", "1e3", "3001.5", "99999999999999999999"]) {
    assert.equal(parseCompanyId(bad), null, bad);
  }
});

test("a run is worded as what would happen in a dry run and what happened in a live one", () => {
  const base = { created: 2, noted: 1, completed: 0, failed: 0, deferred: 0, flagged: 0, groups: 5, belowThreshold: 2 };
  assert.equal(runSummary({ ...base, mode: "dry_run" }), "2 would be opened, 1 note would be added (5 actions in Fix this week, 2 below the threshold)");
  assert.equal(runSummary({ ...base, mode: "live" }), "2 opened, 1 note added (5 actions in Fix this week, 2 below the threshold)");
  assert.equal(
    runSummary({ mode: "live", created: 0, noted: 0, completed: 1, failed: 1, deferred: 3, flagged: 2, groups: 1, belowThreshold: 0 }),
    "1 completed, 1 failed, 3 waiting for the next run, 2 tickets need a look (1 action in Fix this week)",
  );
  assert.equal(runSummary({ mode: "live", created: 0, noted: 0, completed: 0, failed: 0, deferred: 0, flagged: 0, groups: 0, belowThreshold: 0 }), "nothing to do (0 actions in Fix this week)");
});

test("labels", () => {
  assert.equal(opKindLabel("create"), "New ticket");
  assert.equal(opKindLabel("adopt"), "Existing ticket (adopted)");
  assert.equal(opKindLabel("flag"), "Needs a look");
  assert.equal(opKindLabel("zzz"), "zzz");
  assert.equal(opStatusLabel("planned", "dry_run"), "would happen");
  assert.equal(opStatusLabel("planned", "live"), "planned");
  assert.equal(opStatusLabel("skipped", "live"), "not attempted");
  assert.equal(runResultLabel("partial"), "partly done");
  assert.equal(runResultLabel("not_run"), "not run");
  assert.equal(stateLabel("closed_in_psa"), "closed in Autotask");
  assert.equal(stateLabel("resolved"), "resolved in DefendSec");
  assert.equal(urgencyLabel("critical"), "Critical");
});

test("a settings save sends what apid accepts and not who saved it", () => {
  const saved = {
    mode: "dry_run",
    apiUser: "u@example.com",
    zoneUrl: "",
    companyId: 3001,
    queueId: "101",
    status: "1",
    source: "",
    issueType: "20",
    subIssueType: "200",
    priorityCritical: "1",
    priorityHigh: "2",
    priorityMedium: "3",
    noteType: "1",
    notePublish: "2",
    autoComplete: false,
    completeStatus: "",
    minUrgency: "high",
    dueDaysCritical: 2,
    dueDaysHigh: 7,
    dueDaysMedium: 14,
    consoleUrl: "",
    maxCreates: 10,
    updatedBy: "mason",
    updatedAt: "2026-10-24T10:00:00Z",
  } as const;
  const body = settingsPayload({ ...saved }, 3002, "live") as Record<string, unknown>;
  assert.equal("updatedBy" in body, false, "apid refuses unknown fields; a save that echoes updatedBy fails");
  assert.equal("updatedAt" in body, false);
  assert.equal(body.companyId, 3002);
  assert.equal(body.mode, "live");
  assert.equal(body.queueId, "101");
  assert.equal(Object.keys(body).length, Object.keys(saved).length - 2);
  assert.equal(JSON.stringify(settingsPayload({ ...saved, autoComplete: true }, 3001, "dry_run")).includes('"autoComplete":true'), true);
});

test("a picklist value is shown with Autotask's name for it when the run read the list", () => {
  assert.equal(withLabel({ queue: "Security Test Queue" }, "queue", 101, "category default"), "Security Test Queue (101)");
  assert.equal(withLabel(undefined, "queue", 101, "category default"), "101");
  assert.equal(withLabel({}, "priority", 1, "none"), "1");
  assert.equal(withLabel({ queue: "x" }, "queue", undefined, "category default"), "category default");
});

test("only a run that read Autotask is exact", () => {
  assert.equal(isExact({ verified: true }), true);
  assert.equal(isExact({ verified: false }), false);
});
