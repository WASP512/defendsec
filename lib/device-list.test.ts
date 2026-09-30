import assert from "node:assert/strict";
import test from "node:test";

import { apiPath, nextHref, pageNumber, parseDeviceListQuery, prevHref } from "./device-list.ts";

test("malformed params are dropped, not forwarded", () => {
  const q = parseDeviceListQuery({ platform: "plan9", status: "sideways", cursor: "a b;drop", q: "  web  " });
  assert.deepEqual(q, { q: "web", platform: "", status: "", cursor: "", back: [] });
});

test("the API request carries filters and cursor", () => {
  const q = parseDeviceListQuery({ q: "db", platform: "windows", status: "offline", cursor: "abc" });
  assert.equal(apiPath(q), "/v1/devices?limit=50&q=db&platform=windows&status=offline&cursor=abc");
});

test("next then previous returns to the same page", () => {
  const first = parseDeviceListQuery({ q: "db" });
  const toSecond = nextHref(first, "c2")!;
  const second = parseDeviceListQuery(Object.fromEntries(new URL(toSecond, "http://x").searchParams));
  assert.equal(second.cursor, "c2");
  assert.equal(pageNumber(second), 2);
  const toThird = nextHref(second, "c3")!;
  const third = parseDeviceListQuery(Object.fromEntries(new URL(toThird, "http://x").searchParams));
  assert.equal(pageNumber(third), 3);
  const back = parseDeviceListQuery(Object.fromEntries(new URL(prevHref(third)!, "http://x").searchParams));
  assert.equal(back.cursor, "c2");
  assert.equal(back.q, "db");
  const home = prevHref(back)!;
  assert.equal(home, "/devices?q=db");
  assert.equal(prevHref(first), null);
  assert.equal(nextHref(first, undefined), null);
});
