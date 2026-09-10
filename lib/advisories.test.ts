import assert from "node:assert/strict";
import test from "node:test";
import { canonicalPackage, packageMatches, versionOlderThan } from "./advisories.ts";

test("strips Debian epochs before comparing", () => {
  assert.equal(versionOlderThan("1:8.9p1-3ubuntu0.11", "9.8p1"), true);
  assert.equal(versionOlderThan("1:9.8p1-1", "9.8p1"), false);
  assert.equal(versionOlderThan("3.0.2-0ubuntu1.18", "3.0.14"), true);
  assert.equal(versionOlderThan("3.0.14", "3.0.14"), false);
});

test("matches packages by canonical name, not substring", () => {
  assert.equal(packageMatches("git", "git"), true);
  assert.equal(packageMatches("git", "git-lfs"), false);
  assert.equal(packageMatches("git", "python3-git"), false);
  assert.equal(packageMatches("docker", "docker.io"), true);
  assert.equal(packageMatches("docker", "docker-compose"), false);
  assert.equal(packageMatches("google chrome", "Google Chrome"), true);
  assert.equal(canonicalPackage("docker-ce"), "docker");
});
