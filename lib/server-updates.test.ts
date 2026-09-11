import assert from "node:assert/strict";
import test from "node:test";

import { compareVersions, normalizeVersion, parseChecksums, parseRelease } from "./server-release.ts";

test("normalizes v-prefixed release tags", () => {
  assert.equal(normalizeVersion("v1.2.3"), "1.2.3");
  assert.equal(normalizeVersion("release-1"), "release-1");
});

test("compares stable and prerelease semantic versions", () => {
  assert.equal(compareVersions("1.2.2", "1.2.3"), -1);
  assert.equal(compareVersions("v1.2.3", "1.2.3"), 0);
  assert.equal(compareVersions("1.2.3-rc.1", "1.2.3"), -1);
  assert.equal(compareVersions("2.0.0", "1.9.9"), 1);
  assert.equal(compareVersions("dev", "1.0.0"), null);
});

test("parses checksums with GNU binary markers", () => {
  const digest = "a".repeat(64);
  const checksums = parseChecksums(`${digest}  *defendsec-agentd-linux-amd64\ninvalid\n`);
  assert.equal(checksums.get("defendsec-agentd-linux-amd64"), digest);
});

test("reports missing required release assets", () => {
  const release = parseRelease({
    tag_name: "v1.0.0",
    name: "DefendSec 1.0",
    assets: [
      {
        name: "SHA256SUMS",
        browser_download_url: "https://github.com/WASP512/defendsec/releases/download/v1.0.0/SHA256SUMS",
      },
    ],
  });
  assert.equal(release.version, "1.0.0");
  assert.ok(release.missingAssets.includes("defendsec-console.tar.gz"));
});

test("rejects prereleases from the stable channel", () => {
  assert.throws(
    () => parseRelease({ tag_name: "v1.0.0-rc.1", prerelease: true }),
    /No stable release/,
  );
});

