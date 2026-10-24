import assert from "node:assert/strict";
import test from "node:test";

import { distroOf, floorsFrom, supportedOs, windowsEndOfSupport } from "./supported-os.ts";

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

// "Today" for the Windows tests: the dates below are the vendor's, so the answer depends on the day.
const TODAY = new Date("2026-10-24T12:00:00Z");
const winAt = (osName: string, v: string, now = TODAY) => supportedOs({ platform: "windows", osName, osVersion: v }, floorsFrom(""), now);

test("Windows by end-of-support date", () => {
  assert.equal(winAt("Microsoft Windows 10 Pro", "10.0.19045"), false); // 22H2 ended 2025-10-14
  assert.equal(winAt("Microsoft Windows 10 Pro", "10.0.19045", new Date("2025-10-14T08:00:00Z")), true); // on the day, still supported
  assert.equal(winAt("Microsoft Windows 10 Pro", "10.0.19045", new Date("2025-10-15T08:00:00Z")), false);
  assert.equal(winAt("Microsoft Windows 11 Pro", "10.0.26100"), false); // 24H2 Home/Pro ended 2026-10-13
  assert.equal(winAt("Microsoft Windows 11 Enterprise", "10.0.26100"), true); // Enterprise to 2027-10-12
  assert.equal(winAt("Microsoft Windows 11 Pro", "10.0.26200"), true); // 25H2
  assert.equal(winAt("Microsoft Windows 11 Pro", "10.0.22631"), false); // 23H2 Home/Pro ended 2025-11-11
  assert.equal(winAt("Microsoft Windows 11 Pro", "10.0.22000"), false);
  assert.equal(winAt("Windows 11", "10.0.22000"), false); // both editions ended: no need to know which
  assert.equal(winAt("Windows 11", "10.0.26200"), true); // neither ended
  assert.equal(winAt("", "10.0.19045"), false);
  assert.equal(winAt("Microsoft Windows 10 Pro", ""), null);
  assert.equal(winAt("Microsoft Windows 10 Pro", "10.0.12345"), null); // a build not in the table is unknown, not unsupported
});

test("Windows 11 23H2 with no edition in the caption is unknown while the two dates straddle today", () => {
  // Home/Pro ended 2025-11-11, Enterprise ends 2026-11-10; today is between them.
  assert.equal(winAt("Windows 11", "10.0.22631"), null);
  assert.equal(winAt("Windows 11 Enterprise", "10.0.22631"), true);
  assert.equal(winAt("Windows 11 Education", "10.0.22631"), true);
  assert.equal(winAt("Windows 11 Pro Education", "10.0.22631"), true);
  assert.equal(winAt("Windows 11", "10.0.22631", new Date("2026-11-11T00:00:00Z")), false);
});

test("Windows Server is judged as a server, not by its client twin's build", () => {
  // 17763 is Windows 10 1809 (ended 2020/2021) and Server 2019 (supported to 2029-01-09).
  assert.equal(winAt("Microsoft Windows Server 2019 Standard", "10.0.17763"), true);
  assert.equal(winAt("Microsoft Windows 10 Pro", "10.0.17763"), false);
  assert.equal(winAt("Microsoft Windows 10 Enterprise LTSC", "10.0.17763"), true); // LTSC 2019: 2029-01-09
  assert.equal(winAt("Microsoft Windows Server 2016 Standard", "10.0.14393"), true); // to 2027-01-12
  assert.equal(winAt("Microsoft Windows Server 2016 Standard", "10.0.14393", new Date("2027-01-13T00:00:00Z")), false);
  assert.equal(winAt("Microsoft Windows Server 2022 Standard", "10.0.20348"), true);
  assert.equal(winAt("Microsoft Windows Server 2025 Standard", "10.0.26100"), true);
  assert.equal(winAt("Microsoft Windows Server 2012 R2 Standard", "6.3.9600"), false); // ended 2023-10-10
  assert.equal(winAt("Microsoft Windows Server 2012 Standard", "6.2.9200"), false);
  assert.equal(winAt("Microsoft Windows Server 2008 R2 Standard", "6.1.7601"), false);
  assert.equal(winAt("Microsoft Windows 7 Professional", "6.1.7601"), false);
});

test("end of support names its date and what it applies to", () => {
  assert.deepEqual(windowsEndOfSupport("Microsoft Windows 10 Pro", "10.0.19045"), { date: "2025-10-14", range: null, basis: "all editions" });
  assert.deepEqual(windowsEndOfSupport("Microsoft Windows Server 2019 Standard", "10.0.17763"), { date: "2029-01-09", range: null, basis: "Server" });
  assert.deepEqual(windowsEndOfSupport("Windows 11", "10.0.22631"), { date: null, range: ["2025-11-11", "2026-11-10"], basis: "edition not named" });
  assert.equal(windowsEndOfSupport("Windows 10", "garbage"), null);
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
  // An operator's windows=<build> floor replaces the dates: Server 2022 is below 26100.
  assert.equal(f("windows", "Windows Server 2022", "10.0.20348"), false);
  assert.equal(f("windows", "Windows 11", "10.0.26100"), true);
  assert.equal(f("windows", "Windows 10", "10.0.19045"), false);
});
