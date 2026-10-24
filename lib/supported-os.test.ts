import assert from "node:assert/strict";
import test from "node:test";

import { readFileSync } from "node:fs";

import type { OsRelease } from "./os-lifecycle.ts";
import { distroOf, floorsFrom, supportedOs, windowsSupportOf } from "./supported-os.ts";

const linux = (osName: string, osVersion: string) => supportedOs({ platform: "linux", osName, osVersion });

test("each supported distro, current and too old", () => {
  assert.equal(linux("Ubuntu", "24.04"), true);
  assert.equal(linux("Ubuntu", "22.04"), true);
  assert.equal(linux("Ubuntu", "20.04"), false);
  assert.equal(linux("Debian GNU/Linux", "12"), true);
  assert.equal(linux("Debian GNU/Linux", "11"), false);
  assert.equal(linux("Fedora Linux", "44"), true);
  assert.equal(linux("Fedora Linux", "40"), false);
  assert.equal(linux("Red Hat Enterprise Linux", "9.4"), true);
  assert.equal(linux("Red Hat Enterprise Linux", "7.9"), false);
  assert.equal(linux("Rocky Linux", "8.10"), true);
  assert.equal(linux("openSUSE Leap", "16.0"), true);
  assert.equal(linux("openSUSE Leap", "15.6"), false);
  assert.equal(linux("openSUSE Tumbleweed", "20260915"), true);
});

test("unknown is not a failure", () => {
  assert.equal(linux("Arch Linux", ""), null);
  assert.equal(linux("Ubuntu", ""), null);
  assert.equal(supportedOs({ platform: "darwin", osName: "macOS", osVersion: "15.1" }), null);
});

// A real feed fetch (see os-lifecycle.test.ts); the Windows judgement needs the calendar.
const calendar = (JSON.parse(readFileSync(new URL("./testdata/os-calendar.json", import.meta.url), "utf8")) as { releases: OsRelease[] }).releases;
const TODAY = new Date("2026-10-24T12:00:00Z");

test("Windows by edition and build, from the calendar", () => {
  const win = (osName: string, v: string, osEdition = "") =>
    supportedOs({ platform: "windows", osName, osVersion: v, osEdition }, floorsFrom(undefined), calendar, TODAY);
  assert.equal(win("Microsoft Windows Server 2016 Standard", "10.0.14393", "ServerStandard"), true); // the old build floor said false
  assert.equal(win("Microsoft Windows Server 2019 Standard", "10.0.17763", "ServerStandard"), true); // and this
  assert.equal(win("Microsoft Windows Server 2022 Standard", "10.0.20348", "ServerStandard"), true);
  assert.equal(win("Microsoft Windows 11 Enterprise", "10.0.22631", "Enterprise"), true);
  assert.equal(win("Microsoft Windows 10 Pro", "10.0.19045", "Professional"), false);
  assert.equal(win("Microsoft Windows 10 Enterprise 2016 LTSB", "10.0.14393", "EnterpriseS"), false);
  assert.equal(win("Microsoft Windows", "10.0.17763"), null); // edition unknown, build shared
  assert.equal(win("Microsoft Windows 11 Pro", ""), null);
});

test("Windows is unknown, not unsupported, until the calendar is loaded", () => {
  const d = { platform: "windows", osName: "Microsoft Windows Server 2016 Standard", osVersion: "10.0.14393", osEdition: "ServerStandard" };
  assert.equal(supportedOs(d, floorsFrom(undefined), null, TODAY), null);
  assert.equal(supportedOs(d, floorsFrom(undefined), [], TODAY), null);
});

test("DEFENDSEC_SUPPORTED_OS windows=<build> still forces a build floor over the calendar", () => {
  const floors = floorsFrom("windows=20348");
  const s2016 = { platform: "windows", osName: "Microsoft Windows Server 2016 Standard", osVersion: "10.0.14393", osEdition: "ServerStandard" };
  assert.equal(supportedOs(s2016, floors, calendar, TODAY), false); // the operator asked for it
  assert.equal(supportedOs({ ...s2016, osVersion: "10.0.20348" }, floors, calendar, TODAY), true);
  assert.equal(supportedOs({ ...s2016, osVersion: "" }, floors, calendar, TODAY), null);
  assert.match(windowsSupportOf(s2016, floors, calendar, TODAY).reason, /configured minimum 20348/);
});

test("distro names", () => {
  assert.equal(distroOf("AlmaLinux"), "rhel");
  assert.equal(distroOf("SUSE Linux Enterprise Server"), "opensuse");
});

test("minimums can be raised by configuration", () => {
  const floors = floorsFrom("fedora=44, rhel=9, windows=26100, bogus=1, debian=x");
  const f = (p: string, osName: string, osVersion: string) => supportedOs({ platform: p, osName, osVersion }, floors);
  assert.equal(f("linux", "Fedora Linux", "43"), false);
  assert.equal(f("linux", "Red Hat Enterprise Linux", "8.10"), false);
  assert.equal(f("linux", "Debian GNU/Linux", "12"), true); // malformed override ignored
  assert.equal(f("windows", "Windows Server 2022", "10.0.20348"), false);
  assert.equal(f("windows", "Windows 11", "10.0.26100"), true);
});
