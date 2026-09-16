import assert from "node:assert/strict";
import test from "node:test";

import {
  categoryRows,
  orderedLevels,
  type DetectionCoverage,
} from "./detection.ts";

function coverage(over: Partial<DetectionCoverage> = {}): DetectionCoverage {
  return {
    rules: 0,
    byLevel: {},
    byCategory: {},
    techniques: [],
    tactics: [],
    observedKinds: [],
    unobservedKinds: [],
    caveats: [],
    ...over,
  };
}

test("rules that cannot fire are listed before anything else", () => {
  const rows = categoryRows(
    coverage({
      byCategory: { process: 4, network: 2, file: 1 },
      observedKinds: ["process", "file"],
      unobservedKinds: ["network", "registry"],
    }),
  );
  // network has rules and no sensor reporting it: that is the cell an
  // operator has to see first, because those rules are not running.
  assert.equal(rows[0].category, "network");
  assert.equal(rows[0].rules, 2);
  assert.equal(rows[0].observed, false);
});

test("an observed kind with no rules ranks above one that is merely absent", () => {
  const rows = categoryRows(
    coverage({
      byCategory: {},
      observedKinds: ["dns"],
      unobservedKinds: ["registry"],
    }),
  );
  assert.deepEqual(
    rows.map((r) => r.category),
    ["dns", "registry"],
  );
});

test("working categories come last", () => {
  const rows = categoryRows(
    coverage({
      byCategory: { process: 3, network: 1 },
      observedKinds: ["process"],
      unobservedKinds: ["network"],
    }),
  );
  assert.equal(rows[rows.length - 1].category, "process");
});

test("a category is listed even when it has rules and was never observed at all", () => {
  // byCategory can name a kind that appears in neither observed nor
  // unobserved list; dropping it would hide rules that are not running.
  const rows = categoryRows(coverage({ byCategory: { esoteric: 1 } }));
  assert.deepEqual(rows, [
    { category: "esoteric", rules: 1, observed: false },
  ]);
});

test("levels are ordered worst first, with unknown levels kept rather than dropped", () => {
  const ordered = orderedLevels({
    low: 4,
    critical: 1,
    medium: 2,
    unheard: 7,
    high: 3,
  });
  assert.deepEqual(ordered, [
    { level: "critical", count: 1 },
    { level: "high", count: 3 },
    { level: "medium", count: 2 },
    { level: "low", count: 4 },
    { level: "unheard", count: 7 },
  ]);
});

test("levels with no rules are not invented", () => {
  assert.deepEqual(orderedLevels({ high: 2 }), [{ level: "high", count: 2 }]);
  assert.deepEqual(orderedLevels({}), []);
});
