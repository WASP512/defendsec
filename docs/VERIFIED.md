# VERIFIED

What has actually been run, where, and what happened. Nothing on this page is claimed
unless a command and its output are quoted. "Not run" means not run.

## Slice 0 baseline — commit `04a793fc52582a671ff45ebdec52d114535c1477` (main)

- Date: 2026-10-24 UTC, run finished 01:35 UTC (2026-10-23 evening MDT)
- Host: `hermesagent` — Debian 13 (trixie) container, kernel 7.0.14-20-pve, **2 vCPU, 4 GiB RAM**, no Postgres, no Docker, no sudo, no `pwsh`, no root/CAP_BPF
- Toolchain: go1.26.8 linux/amd64, node v22.23.3, npm 10.9.9
- `TEST_DATABASE_URL`: **unset**
- Cold caches: the Go module cache and build cache were empty, so `go build` includes module download time. Node `node_modules` was empty too.
- Branch `scout/0-baseline`, clone made over HTTPS (the SSH deploy key is not yet authorised on GitHub: `git clone git@github-defendsec:...` returned `Permission denied (publickey)`).

### Commands

| # | Command | Exit | Wall time | Result |
| --- | --- | ---: | ---: | --- |
| 1 | `go build ./...` | 0 | 50.0 s (cold, incl. module download) | green |
| 2 | `go vet ./...` | 0 | 8.0 s | green, no output |
| 3 | `GOOS=windows go vet ./...` | 0 | 44.8 s | green, no output |
| 4 | `go test ./...` | **1** | 29.4 s (first run, test binaries compiled) | 1 package red, see below |
| 4b | `TMPDIR=/tmp go test -count=1 ./internal/agentcmd/` | 0 | 0.5 s | `ok  defendsec/internal/agentcmd 0.088s` — confirms the red in #4 is environmental |
| 5 | `go test -count=1 -v ./...` (counting run) | 1 | 15.2 s (warm) | same single failure |
| 6 | `npm ci` | 0 | 15.9 s | green (only the "new major npm available" notice) |
| 7 | `npm test` | 0 | 1.7 s | `# tests 71 / # pass 71 / # fail 0 / # skipped 0` |
| 8 | `npm run lint` (`eslint`) | 0 | 11.4 s | green, no output (no warnings, no errors) |
| 9 | `npm run build` (`next build`, Next.js 16.3.6 Turbopack) | 0 | 28.1 s | green: compiled 15.4 s, TypeScript 8.7 s, 24/24 static pages |

### Counts

Go packages (46 with `go test ./...`): **35 pass, 1 fail, 10 "no test files"**.
Go tests (from `go test -json`, counted per test and subtest): **679 pass, 1 fail, 110 skip**.
Node tests: **71 pass, 0 fail, 0 skip**.

Overall for the 8 baseline commands (rows 1–4 and 6–9): **7 green, 1 red (`go test`), 0 skipped as commands**. Inside `go test`: 110 individual tests skipped.

### Red: `go test ./...` — environmental, not a product defect

Exact failure text:

```
--- FAIL: TestQuarantinePathMovesFile (0.00s)
    quarantine_test.go:44: move to quarantine: rename /tmp/defendsec-quarantine/test-002.src /home/hermes/.hermes/profiles/scout/cache/scratch/TestQuarantinePathMovesFile2204583601/001/quarantine/test-002.src.20261024T013220Z: invalid cross-device link
FAIL
FAIL	defendsec/internal/agentcmd	0.094s
```

Cause (read from source): `internal/agentcmd/quarantine.go:17` hard-codes the staging dir `/tmp/defendsec-quarantine`, and the test renames from there into `t.TempDir()`. On this host `TMPDIR` points at `~/.hermes/profiles/scout/cache/scratch` (a different filesystem from `/tmp`, which is tmpfs), so `rename(2)` returns EXDEV. With `TMPDIR=/tmp` the package passes (row 4b). This is EDR code on the slice-6 drop list (quarantine); no fix was made (slice 0 is read-only).

So: **broken = 0 defects found; environment-sensitive = 1 test.**

### Skipped (110 tests) — needs Postgres vs. other

**Needs Postgres (`TEST_DATABASE_URL is not set`): 105 tests**

| Package | Skipped tests |
| --- | ---: |
| `internal/storepg` | 55 |
| `internal/control` | 49 |
| `db/migrations` | 1 (`TestApplyCreatesSchema`) |

`internal/storepg` reports `pass` with 0 tests run and 55 skipped. **Everything in the Postgres store, the migrations, and 49 control-plane tests are unverified on this box.** CI has a `postgres-integration` job (`.github/workflows/ci.yml`, postgres:16) that runs `go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/...`; I have not looked at its run results.

**Skipped for other reasons: 5 tests**

| Package | Count | Reason (as printed) |
| --- | ---: | --- |
| `internal/sensor` | 3 | `loading a BPF program needs root or CAP_BPF` |
| `internal/agentcmd` | 1 | `pwsh not installed` (`TestWindowsQueryScriptsParse`) |
| `internal/agentcmd` | 1 | `run by scripts/test-isolation-netns.sh` |

### Packages with no test files (10)

`cmd/defendsec-loadtest`, `cmd/defendsec-verify`, `internal/agentfim`, `internal/db`, `internal/gen/v1`, `internal/proclist`, `internal/savedqueries`, `internal/secret`, `internal/sso/ssotest`, `packs`.

Notably `cmd/defendsec-verify` — the offline verifier binary that the product's headline claim rests on — has no tests of its own (its libraries `internal/evidence`, `internal/auditchain`, `internal/anchor` do).

### Disk and build cost on this box

- Root fs 20 GB: 7.7 GB used / 13 GB free before the run, 8.6 GB used / 12 GB free after.
- After the run: `.next` 110 MB, `node_modules` 346 MB, Go module cache 66 MB, Go build cache 171 MB.
- Time from empty to everything green: about 3 min of command time (rows 1–4 and 6–9 sum to 189 s; rows 4b and 5 are extra diagnostics, ≈ 16 s). `next build` is 28 s here, much less than feared.

## LOC before slice-6 deletion (tracked files at `04a793f`)

Lines counted with `wc -l` equivalent (every line, comments and blanks included) over `git ls-files`. `internal/gen` is generated protobuf. Windows-tagged files are counted inside their package.

### Go — 36,582 src + 18,986 test = 55,568 lines, 253 files

| package | src LOC | test LOC | files |
| --- | ---: | ---: | ---: |
| `cmd/defendsec-agentd` | 1302 | 73 | 12 |
| `cmd/defendsec-apid` | 894 | 35 | 3 |
| `cmd/defendsec-loadtest` ★ | 456 | 0 | 1 |
| `cmd/defendsec-verify` | 180 | 0 | 1 |
| `cmd/defendsec-web` | 273 | 216 | 2 |
| `db` | 46 | 121 | 2 |
| `internal/agentcmd` | 1838 | 780 | 27 |
| `internal/agentfim` | 70 | 0 | 1 |
| `internal/alertmeta` | 67 | 38 | 2 |
| `internal/anchor` | 708 | 435 | 4 |
| `internal/auditchain` | 223 | 242 | 2 |
| `internal/auditlayer` | 318 | 334 | 2 |
| `internal/cmdlog` | 248 | 178 | 2 |
| `internal/control` | 7570 | 3625 | 45 |
| `internal/controls` | 1182 | 328 | 6 |
| `internal/db` | 61 | 0 | 1 |
| `internal/etw` ★ | 420 | 86 | 3 |
| `internal/events` ★ | 731 | 443 | 6 |
| `internal/evidence` | 550 | 586 | 3 |
| `internal/forward` ★ | 1144 | 572 | 7 |
| `internal/gen` (generated) | 1802 | 0 | 2 |
| `internal/hostinv` | 784 | 100 | 2 |
| `internal/identity` | 626 | 655 | 6 |
| `internal/mcp` ★ | 797 | 648 | 5 |
| `internal/metrics` | 305 | 48 | 2 |
| `internal/pki` | 286 | 62 | 2 |
| `internal/playbook` ★ | 390 | 470 | 4 |
| `internal/policy` ★ | 785 | 1910 | 8 |
| `internal/posture` | 515 | 139 | 5 |
| `internal/presence` | 786 | 125 | 2 |
| `internal/proclist` ★ | 115 | 0 | 3 |
| `internal/savedqueries` | 104 | 0 | 1 |
| `internal/sca` | 1715 | 983 | 12 |
| `internal/secret` | 56 | 0 | 2 |
| `internal/sensor` ★ | 1183 | 641 | 9 |
| `internal/sigma` ★ | 1333 | 846 | 6 |
| `internal/sign` | 305 | 202 | 4 |
| `internal/sso` | 413 | 206 | 3 |
| `internal/storepg` | 3690 | 2372 | 23 |
| `internal/supplychain` | 173 | 249 | 2 |
| `internal/telemetry` | 494 | 151 | 3 |
| `internal/triage` ★ | 672 | 411 | 5 |
| `internal/vuln` | 542 | 370 | 7 |
| `internal/webtls` | 419 | 306 | 2 |
| `packs` | 11 | 0 | 1 |
| **total** | **36582** | **18986** | **253** |

★ = on the slice-6 drop list (whole package). Subtotal of the 11 starred packages: **8,026 src + 6,027 test = 14,053 lines** (about 25% of all Go). That is a floor: it excludes EDR code living inside kept packages (`internal/agentcmd` isolate/kill/run_script, `internal/control` handlers and `internal/storepg` tables for alerts/playbooks/proposals, Windows service/ETW files in `cmd/defendsec-agentd` and `internal/agentcmd`, `internal/posture`). `internal/policy`, `internal/sign`, `internal/mcp` are to be archived on `archive/action-governance` first (slice 6).

### TypeScript / TSX — 14,110 src + 654 test = 14,764 lines, 145 files

| package | src LOC | test LOC | files |
| --- | ---: | ---: | ---: |
| `(root)` (`instrumentation.ts`, `next.config.ts`) | 47 | 0 | 2 |
| `app` (layout) | 36 | 0 | 1 |
| `app/(console)` | 1702 | 0 | 20 |
| `app/api` | 1308 | 0 | 25 |
| `app/downloads` | 55 | 0 | 1 |
| `app/login` | 98 | 0 | 1 |
| `components` | 6973 | 0 | 46 |
| `hooks` | 19 | 0 | 1 |
| `lib` | 3872 | 654 | 48 |
| **total** | **14110** | **654** | **145** |

Console has no component or page tests; only `lib/*.test.ts` runs (71 tests). The route list from `next build` includes the pages slice 6 will drop: `/detection`, `/response`, `/proposals` (also `/alerts`, `/policies`, `/scope` still to be triaged).

### Other tracked source

Python 719 lines (`agent/`, `scripts/`), SQL migrations 770 lines (18 files), SCA pack YAML 646 lines.

## Feature × platform × evidence matrix

Empty on purpose. As of this baseline there is **no** row with a "real host" run or a looked-up CI result. Later slices add rows only with a run behind them.

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Go build/vet | linux/amd64 | build+vet green (rows 1–2) | not checked | n/a |
| Go vet | windows (cross) | vet green (row 3) | not checked | none |
| Console build/lint/lib tests | node 22 | green (rows 6–9) | not checked | none |
| Postgres store / migrations / control plane | linux | **skipped, 105 tests** (no `TEST_DATABASE_URL`) | not checked | none |

## Not verified in slice 0

- Anything touching Postgres (see above) — needs a Postgres reachable from this box, or trust CI.
- Any CI result: I did not query GitHub Actions.
- `go test -race`, Windows tests (only cross-vet), eBPF tests (need root), pwsh script parsing.
- Whether any binary runs: nothing was started. `go build ./...` proves compilation only.
- The console at 10.10.10.214 was not touched or inspected.
