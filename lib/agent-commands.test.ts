import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_DOWNLOADS,
  agentPlatform,
  downloadBaseFor,
  installCommand,
  msiCommand,
  uninstallCommand,
} from "./agent-commands.ts";

const opts = { host: "ds.example", downloadBase: "https://ds.example:47261/downloads", secret: "s3cr3t" };

test("device platforms map to command families", () => {
  assert.equal(agentPlatform("linux"), "linux");
  assert.equal(agentPlatform("windows"), "windows");
  assert.equal(agentPlatform("darwin"), "macos");
  assert.equal(agentPlatform("plan9"), null);
  assert.equal(agentPlatform(undefined), null);
});

test("every command downloads only files the console serves", () => {
  const served = new Set<string>(AGENT_DOWNLOADS);
  const commands = [
    ...(["linux", "windows", "macos"] as const).flatMap((p) => [
      installCommand(p, opts),
      uninstallCommand(p, opts.downloadBase, false),
    ]),
  ];
  for (const cmd of commands) {
    for (const m of cmd.matchAll(/\/downloads\/([A-Za-z0-9._-]+)/g)) {
      assert.ok(served.has(m[1]!), `${m[1]} is not served`);
    }
  }
});

test("https downloads are verified, never skipped", () => {
  for (const p of ["linux", "macos"] as const) {
    const cmd = installCommand(p, opts);
    assert.match(cmd, /--cacert \/tmp\/defendsec-console.crt/);
    assert.match(cmd, /--download-ca/);
    assert.doesNotMatch(cmd, /--insecure|-k /);
  }
  const win = installCommand("windows", opts);
  assert.match(win, /Thumbprint/);
  assert.match(win, /-DownloadCa/);
  assert.doesNotMatch(win, /SkipCertificateCheck/);
});

test("PowerShell values are single-quoted with quotes doubled", () => {
  const cmd = installCommand("windows", { ...opts, secret: "a'b" });
  assert.match(cmd, /-EnrollSecret 'a''b'/);
});

test("purge is passed through per platform", () => {
  assert.match(uninstallCommand("linux", opts.downloadBase, true), /--purge-data/);
  assert.match(uninstallCommand("macos", opts.downloadBase, true), /--purge-data/);
  assert.match(uninstallCommand("windows", opts.downloadBase, true), /-PurgeData/);
  assert.doesNotMatch(uninstallCommand("windows", opts.downloadBase, false), /-PurgeData/);
});

test("MSI command carries the enrollment properties", () => {
  const cmd = msiCommand(opts);
  assert.match(cmd, /ENROLL_SECRET=s3cr3t/);
  assert.match(cmd, /\/qn/);
});

test("download base is derived from the console URL", () => {
  assert.deepEqual(downloadBaseFor("https://ds.example:47261/"), {
    host: "ds.example",
    downloadBase: "https://ds.example:47261/downloads",
  });
});
