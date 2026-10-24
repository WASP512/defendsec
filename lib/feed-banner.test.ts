import assert from "node:assert/strict";
import test from "node:test";
import { describeAge, feedBanner, type FeedStatus, type FeedsResponse } from "./feed-banner.ts";

const DAY = 86400;

function feed(name: string, ageSeconds: number | null, extra: Partial<FeedStatus> = {}): FeedStatus {
  return {
    name,
    kind: "test",
    url: `https://example.invalid/${name}`,
    lastSuccess: ageSeconds === null ? null : "2026-10-23T12:00:00Z",
    lastAttempt: "2026-10-23T12:00:00Z",
    ageSeconds,
    stale: ageSeconds === null || ageSeconds > 7 * DAY,
    recordCount: 10,
    snapshotId: 1,
    sha256: "a".repeat(64),
    lastError: "",
    ...extra,
  };
}

function resp(feeds: FeedStatus[]): FeedsResponse {
  const ages = feeds.map((f) => f.ageSeconds).filter((a): a is number => a !== null);
  return {
    feeds,
    generatedAt: "2026-10-23T12:00:00Z",
    staleAfterSeconds: 7 * DAY,
    anyStale: feeds.some((f) => f.stale),
    oldestAgeSeconds: ages.length ? Math.max(...ages) : null,
    latestSnapshotId: 1,
  };
}

test("describeAge picks the largest whole unit", () => {
  assert.equal(describeAge(0), "under a minute");
  assert.equal(describeAge(59), "under a minute");
  assert.equal(describeAge(60), "1 minute");
  assert.equal(describeAge(3 * 3600 + 5), "3 hours");
  assert.equal(describeAge(DAY), "1 day");
  assert.equal(describeAge(8 * DAY + 3600), "8 days");
  assert.equal(describeAge(-5), "under a minute");
});

test("red when any feed is older than seven days", () => {
  const b = feedBanner(resp([feed("kev", 3600), feed("epss", 8 * DAY), feed("debian", 2 * DAY)]));
  assert.equal(b.tone, "red");
  assert.match(b.title, /1 of 3 vulnerability feeds are older than 7 days/);
  assert.match(b.detail, /epss \(8 days old\)/);
  assert.doesNotMatch(b.detail, /kev \(/);
});

test("exactly seven days is not yet stale; the server's flag decides", () => {
  assert.equal(feedBanner(resp([feed("kev", 7 * DAY)])).tone, "ok");
  assert.equal(feedBanner(resp([feed("kev", 7 * DAY + 1)])).tone, "red");
});

test("a feed that never succeeded is red and named", () => {
  const b = feedBanner(resp([feed("kev", 60), feed("debian", null, { lastError: "dial tcp: lookup failed" })]));
  assert.equal(b.tone, "red");
  assert.match(b.detail, /never synced: debian/);
  assert.match(b.detail, /Last error: debian: dial tcp: lookup failed/);
});

test("green when everything is recent", () => {
  const b = feedBanner(resp([feed("kev", 3 * 3600), feed("epss", 3 * 3600), feed("debian", 26 * 3600)]));
  assert.equal(b.tone, "ok");
  assert.match(b.detail, /3 feeds current, oldest confirmed 1 day ago/);
  assert.equal(feedBanner(resp([feed("kev", 120)])).detail, "1 feed current, oldest confirmed 2 minutes ago.");
});

test("amber, not green, when recent data came with a failed last attempt", () => {
  const b = feedBanner(resp([feed("kev", 3600), feed("epss", 3600, { lastError: "HTTP 503" })]));
  assert.equal(b.tone, "amber");
  assert.match(b.detail, /Failed on the last attempt: epss/);
});

test("amber when feeds never synced or status cannot be read", () => {
  const empty = feedBanner(resp([]));
  assert.equal(empty.tone, "amber");
  assert.match(empty.title, /never synced/);
  const unavailable = feedBanner(null);
  assert.equal(unavailable.tone, "amber");
  assert.match(unavailable.title, /unavailable/);
});

test("the stale list is trimmed when long", () => {
  const many = Array.from({ length: 9 }, (_, i) => feed(`feed-${i}`, null));
  const b = feedBanner(resp(many));
  assert.equal(b.tone, "red");
  assert.match(b.detail, /feed-0, feed-1, feed-2, feed-3, feed-4, feed-5 and 3 more/);
});
