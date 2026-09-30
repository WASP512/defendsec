import assert from "node:assert/strict";
import test from "node:test";

import { distroOf, supportedOs } from "./supported-os.ts";

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

test("Windows by build number", () => {
  const win = (v: string) => supportedOs({ platform: "windows", osName: "Microsoft Windows 11 Pro", osVersion: v });
  assert.equal(win("10.0.22631"), true); // Windows 11 23H2 — the old check reported this unsupported
  assert.equal(win("10.0.26100"), true); // Server 2025 / Windows 11 24H2
  assert.equal(win("10.0.20348"), true); // Server 2022
  assert.equal(win("10.0.19045"), false); // Windows 10 22H2
  assert.equal(win(""), null);
});

test("distro names", () => {
  assert.equal(distroOf("AlmaLinux"), "rhel");
  assert.equal(distroOf("SUSE Linux Enterprise Server"), "opensuse");
});
