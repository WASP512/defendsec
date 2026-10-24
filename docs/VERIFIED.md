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

## Slice 1 — direction, README, LICENSE (docs only)

- Branch `scout/1-direction`, from `main` at `04a793f` plus the slice 0 commit above.
- Changed: `README.md`, `docs/DIRECTION.md` (new), `docs/ROADMAP.md` (banner only), `docs/NEXT-PHASES.md` (deleted), `LICENSE` (new, AGPL-3.0 text from `https://www.gnu.org/licenses/agpl-3.0.txt`, SHA-256 `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`), `package.json` (`"license": "AGPL-3.0-only"`), this file.
- No Go or console source changed.

| Command | Exit | Result |
| --- | ---: | --- |
| `grep -in 'edr\|sigma\|isolat\|playbook' README.md` | 0 | 2 matching lines (80, 81), both inside "What it is not"; none elsewhere |
| `npm run lint` | 0 | green, no output |
| `npm test` | 0 | `# tests 71 / # pass 71 / # fail 0` |

Not run in this slice: `npm run build`, any Go command (no Go file changed). Not verified: the README's feature claims were carried over from the previous README, not re-tested; dependency licence compatibility with AGPL-3.0 has not been audited.

## Slice 2 — advisory schema (migration 019)

- Branch `scout/2-advisory-schema`, stacked on `scout/1-direction` (slice 1 is not merged and not pushed).
- Changed: `db/migrations/019_advisory_ranges.sql` (new), `internal/storepg/advisories.go` (new: types, `RecordFeedSnapshot`, `GetFeedSnapshot`, `UpsertAdvisoryWithRanges`, `ListAdvisoryRanges`, `GetAdvisory`), `internal/storepg/store.go` (`ListAdvisories` now `WHERE package <> ''`, nothing else), tests, this file.
- Not changed: matching behaviour, `lib/advisories.ts`, `scripts/ingest-osv.py`, the admin API.

### Postgres used

A real PostgreSQL **16.15** (same major as CI's `postgres:16`), run in user space on this box: the `io.zonky.test.postgres:embedded-postgres-binaries-linux-amd64:16.15.0` jar from Maven Central (jar SHA-1 `f2f03e89deb63c0dbac75450bb713ca37c1e82b1`, matches the `.sha1` Maven publishes), `initdb --auth=trust`, listening on `127.0.0.1:54329` only. This is a test database with no data of value; it is not the console's database and does not substitute for a real install.

### Commands

| Command | Exit | Result |
| --- | ---: | --- |
| `gofmt -l db internal cmd` | 0 | no output |
| `go build ./...` | 0 | green |
| `go vet ./...` | 0 | green |
| `GOOS=windows go vet ./...` | 0 | green |
| `go test ./...` (no `TEST_DATABASE_URL`) | 1 | everything `ok` except the known slice-0 environmental failure `TestQuarantinePathMovesFile` (EXDEV, `TMPDIR` not on `/tmp`'s filesystem); new DB tests report SKIP |
| `TMPDIR=/tmp go test -count=1 ./internal/agentcmd` | 0 | `ok` (as in slice 0) |
| `TEST_DATABASE_URL=postgres://…@127.0.0.1:54329/postgres go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/...` (the CI `postgres-integration` command) | 0 | per test+subtest: storepg 87 pass / 0 fail / 0 skip; db/migrations 5 pass / 0 fail / 0 skip; control 145 pass / 0 fail / 0 skip |
| `TEST_DATABASE_URL=… go test ./...` | 1 | same single `TestQuarantinePathMovesFile` failure; every other package `ok` |

### What the migration was shown to do (against real Postgres 16.15)

- **Fresh database**: `TestAdvisoryRangesFreshDatabase` applies all 19 migrations twice into an empty throwaway database; the three `advisory_ranges` indexes exist, 0 ranges, 0 snapshots.
- **Existing install**: `TestAdvisoryRangesUpgradeKeepsExistingAdvisories` applies 001–018, inserts three legacy rows the old way (two with a floor, one with an empty floor), then applies the full set three times. All three advisories survive; exactly two ranges exist (the empty-floor row has nothing to mirror) and neither is duplicated by the re-runs; each is `ecosystem='legacy'`, `distro/release/introduced` NULL, `fixed` = the old `below`, `fix_state='fixed'`. A legacy-style `INSERT … ON CONFLICT DO UPDATE` (the `ingest-osv.py` shape) moves the mirrored range; deleting an advisory cascades.
- **Constraints**: `TestAdvisoryRangesConstraints` — unknown `fix_state`, `fixed` without a version, EPSS 1.5, CVSS 10.5, a non-array `feeds`, a duplicate range, a same-bounds range with a different state, and a range for a missing advisory are all rejected.
- **Store**: round trip of every new advisory column, snapshot feeds (including instant-preserving `fetched_at`), full replace of the range set, rollback leaves old state intact on a failed upsert, lookup by binary and source package and by distro/release (a NULL release matches every release; distro-agnostic ranges only when asked), and the legacy `UpsertAdvisory`/`ListAdvisories` path unchanged.

### Not verified

- **No real install was upgraded.** No console database, no production-sized `advisories` table: timing of the trigger/backfill on 100k+ rows is unmeasured. The migration runs inside `Apply`'s single transaction on every start; the backfill is a no-op after the first run, but that was shown only on a three-row table.
- Migration was run on PostgreSQL 16.15 only. Not on 14/15/17 (identity columns need ≥ 10; the test helper's forced database drop needs ≥ 13).
- No CI result: the branch is not on GitHub.
- Nothing populates the new columns yet (feed sync is slice 3); `ListAdvisoryRanges` has no caller in product code (matcher is slice 4). Query plans for the lookup were not inspected (`EXPLAIN` not run); the indexes exist and the semantics are tested, performance is not.
- The `legacy` mirror trigger and the `package`/`below` columns are transitional and should be dropped when slice 4 moves the matcher and `ingest-osv.py` is replaced.

## Feature × platform × evidence matrix — additions from slice 2

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Migration 019 (advisory ranges, snapshots) fresh + upgrade | linux, Postgres 16.15 (user-space) | 3 new migration tests + 2 existing, green against real PG | not checked | none |
| Advisory store (`UpsertAdvisoryWithRanges`, `ListAdvisoryRanges`, snapshots) | linux, Postgres 16.15 (user-space) | green (unit validation + integration) | not checked | none |

## Slice 3 — feed sync service (`defendsec-feeds`)

- Branch `scout/3-feeds`, stacked on `scout/2-advisory-schema` (slices 1–2 are unmerged and not pushed).
- Added: `cmd/defendsec-feeds`, `internal/feeds/{kev,epss,oval,ubuntu,rhel,suse,debian,osv,fetch,bundle,runner}`, `internal/storepg/feeds.go`, migration `020_feed_status.sql`, `sign.Load`/`SignBlob`/`VerifyBlob`, `GET /v1/feeds` (`internal/control/feeds.go`), `lib/feed-banner.ts` + `components/feed-age-banner.tsx`, `packaging/systemd/defendsec-feeds.{service,timer}`, `feeds.env.example`, `docs/FEEDS.md`.
- Removed: `scripts/ingest-osv.py`, `scripts/ingest-osv.timer.md`, `packaging/systemd/defendsec-ingest-osv.{service,timer}`, and the console's "last OSV ingest" line.
- Changed besides that: `lib/advisories-db.ts` now selects `WHERE package <> ''` (same filter as `storepg.ListAdvisories`) so feed-written advisories, which carry versions only in `advisory_ranges`, cannot reach the legacy console matcher; `.github/workflows/ci.yml` runs `./internal/feeds/runner/...` in `postgres-integration` (`TestEveryIntegrationPackageRunsInCI` demands it); the release scripts build `defendsec-feeds`.
- **The matcher does not use any of this yet.** Findings still come from the legacy catalog. That is slice 4.

### Postgres used

The same user-space PostgreSQL 16.15 as slice 2 (port 54329, scratch databases). Not the console's database, not the host at 10.10.10.214.

### Commands

| Command | Exit | Result |
| --- | ---: | --- |
| `gofmt -l cmd db internal` | 0 | no output |
| `go build ./...`, `go vet ./...`, `GOOS=windows go vet ./...` | 0 | green |
| `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/defendsec-feeds` | 0 | green (no cgo) |
| `TEST_DATABASE_URL=… go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/... ./internal/feeds/... ./internal/sign/... ./internal/supplychain/...` | 0 | per test+subtest, 0 fail, 0 skip: migrations 5, control 147, storepg 95, feeds/runner 20, bundle 22, debian 10, epss 8, fetch 11, kev 8, oval 5, ubuntu 4, rhel 3, suse 3, osv 3, feeds 4, sign 16, supplychain 16 |
| same, without `TEST_DATABASE_URL` | 0 | DB tests skip (runner 15 pass / 5 skip; control 95 / 50; storepg 20 / 68); parser, fetch, bundle, sign tests all run |
| `go test ./...` with and without DB | 1 | only the known slice-0 environmental failure `TestQuarantinePathMovesFile` (EXDEV) |
| `npm run lint` / `npm test` / `npm run build` | 0 / 0 / 0 | lint clean; `# tests 79 / # pass 79 / # fail 0` (8 new in `lib/feed-banner.test.ts`); build green |

Every parser has a committed fixture cut from the real upstream file (Ubuntu jammy, RHEL 9, SUSE Leap, Debian tracker, KEV, EPSS, four OSV records) and tests against it.

### Real runs against the live upstream feeds (this box, 2 vCPU, scratch database `feedsdemo`)

`defendsec-feeds sync`, first run, all nine default feeds, 2m22s wall:

| Feed | Status | Records | Advisories | Download | Seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| ubuntu-jammy | loaded | 51,376 | 5,133 | 1.4 MiB | 7.7 |
| ubuntu-noble | loaded | 34,263 | 3,193 | 1.2 MiB | 6.1 |
| debian | loaded | 134,089 | 62,299 | 82.1 MiB | 12.9 |
| rhel-8 | loaded | 128,069 | 6,791 | 1.9 MiB | 12.4 |
| rhel-9 | loaded | 279,367 | 7,861 | 1.3 MiB | 20.6 |
| suse-leap-16.0 | loaded | 334,606 | 19,955 | 7.3 MiB | 42.9 |
| suse-tumbleweed | loaded | 265,937 | 30,003 | 7.0 MiB | 33.3 |
| kev | loaded | 1,756 | – | 1.7 MiB | 0.5 |
| epss | loaded | 394,803 | – | 2.6 MiB | 5.0 |

Skipped and counted, not guessed: Ubuntu jammy 114 definitions without a CVE + 1,763 kernel running-version tests; noble 68 + 787; Debian 792 non-CVE identifiers; RHEL 8 16,563 and RHEL 9 2,212 module-stream ranges; SUSE Leap 16.0 2,388 CVEs without package ranges.

- **Peak RSS** (VmHWM polled every 0.2 s during `sync --dry-run`, one feed at a time): suse-leap-16.0 281 MiB, debian 239, epss 145, rhel-9 138.
- **Second run**: all nine `unchanged` (HTTP 304 / identical SHA-256), 4.0 s wall, nothing loaded.
- **Kill and resume**: `kill -9` during a first sync into `feedsdemo2` (after ubuntu-jammy and noble had loaded, snapshot 1 created); the next sync loaded the remaining seven and made snapshot 2. Final state: all nine feeds loaded, snapshot 2.
- **OSV** (off by default): `DEFENDSEC_FEEDS_ENABLED=osv-pypi DEFENDSEC_FEEDS_OSV_ECOSYSTEMS=PyPI sync --dry-run` parsed 19,400 records / 12,604 advisories from a 35.3 MiB `all.zip` in 2.9 s; skipped last_affected 1,551, GIT ranges 1,535, withdrawn 622. Dry run only: PyPI was not loaded into a database.
- **Export → import**: `export` wrote a 111,789,056-byte tar of the nine cached feeds. `import --trust-key <exporter pub>` into the separate database `feedsairgap` with a different control key verified and accepted it (nine feeds, digests identical to the exporter's). Earlier on the same data: import with no trust key was refused; a tampered bundle was refused before anything was written; ranges and advisories tables compared by md5 between the two databases were identical (that comparison was done on the first bundle; the second bundle above was not re-compared by md5).
- **`GET /v1/feeds`** on a real `defendsec-apid` (built binary, pointed at `feedsdemo`): 200 with all nine feeds with age, record count and snapshot id (e.g. kev: 1,756 records, snapshot 1, ageSeconds 1094); no token 401; POST 405.

### Not verified

- **No browser look at the banner.** `lib/feed-banner.ts` (the decision logic) is unit-tested and the page builds; the rendered red/amber/plain states were not seen in a browser.
- **`sync` has never run on the console host (10.10.10.214)** and the systemd units were never started: `systemd-analyze verify` only complained that `/usr/local/bin/defendsec-feeds` does not exist here. The timer is untested; the environment-file layering with `apid.env` is untested.
- **Postgres 16.15 only**, scratch databases, no CI run (branch not on GitHub). The CI step addition is only checked by `TestEveryIntegrationPackageRunsInCI`.
- **Whether the data is right is not verified against a real host.** Parsers are checked against fixtures cut from the real feeds and counted in the run above; no installed-package list has been matched against them (slice 4). RHEL module-stream errata, Ubuntu kernel definitions and RHEL "unpatched" classes are skipped by design.
- **Alma/Rocky**: no feed of their own; the plan is that the matcher maps them to `rhel`. Not exercised.
- **RHEL 10** has no v2 OVAL feed (HTTP 404 at the time of the probe) and is not in the defaults.
- **Large `advisory_ranges` performance**: the nine feeds parsed to about 1.23 million records in total; no query plans inspected and no timing of reads against that table.
- Mirrors: `DEFENDSEC_FEEDS_URL_*` overrides are unit-tested against an httptest server, not a real mirror.

## Feature × platform × evidence matrix — additions from slice 3

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Feed parsers (KEV, EPSS, Ubuntu/RHEL/SUSE OVAL, Debian, OSV) | linux | fixture tests from real files, green | not checked | parsed full live feeds on hermesagent (counts above) |
| `defendsec-feeds sync` (resumable, conditional, shrink guard) | linux, Postgres 16.15 | runner e2e tests, green | not checked | real sync of 9 feeds into a scratch DB; kill -9 + resume |
| `export` / `import` signed bundles | linux, Postgres 16.15 | bundle + runner tests (tamper, wrong key, rollback) | not checked | round trip between two scratch DBs with different keys |
| `GET /v1/feeds` | linux, Postgres 16.15 | green | not checked | called on a real apid |
| Feed-age banner | any | logic unit-tested | not checked | none (not seen in a browser) |
| systemd service + timer | linux | none | none | none |

## Slice 4 — distro-aware matcher (migration 021)

Branch `scout/4-matcher`, stacked on `scout/3-feeds`. **The exit measurement (zero findings on a
fully patched Ubuntu 22.04 and a fully patched Rocky 9 host) is PENDING.** There are no such hosts on
this box. The CEO was asked (via `bot-dm`, delivery reported "ambiguous") to have grumpy provide two VMs
on titan, or to run `defendsec-agentd -print-inventory` on existing ones and drop the JSON in
`workspace/measure/{ubuntu-2204,rocky-9}.json`. Until those files exist this slice is not closed. What was
run instead is below, and each item says what it does and does not show.

### Toolchain

`protoc` 3.21.12 (Maven Central `com.google.protobuf:protoc`, SHA-1 matched the `.sha1` beside it),
`protoc-gen-go` v1.35.2, `protoc-gen-go-grpc` v1.5.1: the versions in the generated headers. `make proto`
on the unchanged proto left `git status` clean (byte-identical output); after the field additions only
`agent.pb.go` changed.

### Commands (this box, Postgres 16.15 user-space, `go test -p 1`)

| Command | Result |
| --- | --- |
| `go build ./...`, `go vet ./...`, `GOOS=windows go vet ./...`, `gofmt -l` | green |
| `CGO_ENABLED=0 GOARCH=arm64 go build ./cmd/defendsec-agentd ./cmd/defendsec-feeds` | green |
| `go test -p 1 ./...` with `TEST_DATABASE_URL` | only the known `TestQuarantinePathMovesFile` EXDEV failure (`/tmp` vs scratch on different devices; same as slice 0) |
| `go test -v` per package, with the DB | vuln 24 pass, hostinv 9, storepg 75, control 120; 0 fail, 0 skip |
| `npm run lint` / `npm test` / `npx tsc --noEmit` / `npm run build` | 0 problems / 81 pass / clean / built |

Mutation check: changing `>=` to `>` in the "reached the fix" comparison fails four matcher tests
(Debian, RHEL family, several fixed ranges, source version).

### Test vector

`{"1:8.9p1-3ubuntu0.11", "9.8p1", true}` no longer exists in the Go suite (changed to "not vulnerable"/
"unknown" in Phase 0.1, `internal/vuln/vuln_test.go`, `compare_test.go`). The last place that still asserted
"vulnerable" was `lib/advisories.test.ts`, deleted with the catalogue. Backport regression cases added in
`internal/vuln/match_test.go`: Ubuntu 22.04 openssh (patched / one update behind), Debian 12 openssh and
glibc binNMU, RHEL 9 with Rocky and Alma 9.4 mapped to `rhel`, epoch handling, openSUSE Leap 15.6,
not_affected / will_not_fix / affected / introduced, Ubuntu Pro-only fixes, no source field (old agent),
coverage states, upstream fallback only for unmapped software.

### Real runs

**1. This host (hermesagent, Debian 13 trixie), real feeds.** Nine feeds synced from the live upstreams
into scratch database `slice4` (2m29s; snapshot 1). `defendsec-agentd -print-inventory` reported 615
packages (the old collector would have stopped at 80). `defendsec-feeds match`:
`coverage covered; 407 packages distro-mapped, 0 upstream, 26,556 advisories considered, 4,803
marked not_affected; 5 findings with a fix (bind9-dnsutils ×4, libbrotli1 ×1), 1,143 unfixed, 307
informational`. Exit 2. These five are **not independently confirmed**: `apt-cache` shows installed ==
candidate, but the apt lists on this box date from 2026-10-18 and cannot be refreshed without root, so the
feed may simply be newer than apt's view. (The first run before the `unfixed` kind existed printed 1,148
"findings", because Debian's tracker lists open CVEs with no fix; that is why the kind exists.)

**2. Synthetic "everything patched" inventories from the real ranges.** Each package set to the highest
fixed version any loaded range names, then matched. Ubuntu 22.04: 51,376 ranges → 3,984 packages → **0
findings**; same without Pro-only ranges (3,169 packages) → **0 findings**, 289 unfixed (fixes that exist
only in Ubuntu Pro); RHEL 9 (as Rocky 9.4): 279,367 ranges → 2,924 packages → **0 findings**. This is
true by construction. It shows the comparators and the distro/epoch/source handling cope with 330,000 real
fixed-version strings, and says **nothing** about what a real host's package list looks like.

**3. Whole pipeline, real binaries.** `defendsec-apid` (scratch database `slice4`) + `defendsec-agentd`
enrolled over mTLS from this box, inventory reported (`software=615`) → matcher → `vuln_findings` →
`GET /v1/findings`, `/v1/findings/{id}`, `/v1/findings/summary` returned the five findings with advisory
id, range id, snapshot id, feed name and feed date (e.g. `feed debian`, fetched 2026-10-23T20:55 -06:00),
the detail returned the advisory, the matched range and the nine feeds with SHA-256 digests. The built
console (`next start`, cookie from the admin token) rendered `/advisories` (5 rows), `/devices/{id}`
(5 finding rows, one "no fix to install" block, policy "4 high, critical or KEV findings with a fix
available: Failing", "Matched 615 packages against debian 13 advisories; 407 are covered") and
`/findings/{id}` (evidence table). Acknowledging the four serious findings through `POST /api/findings`
(existing triage keys) flipped the policy to Passing and back on reopen. With apid stopped, the console
showed "Findings unavailable" on both pages, not an empty list. HTML was fetched with `curl`; **no browser
was used**.

### Not verified

- **The exit measurement** (see top). No real Ubuntu 22.04 or Rocky 9 host has been matched.
- **`rpm` collection never ran on an rpm host** (no `rpm` here). `ParseRPMQuery` / `ParseSourceRPM` are tested
  on hand-written text in the shape of `rpm -qa --queryformat` output; whether rpm renders
  `%|EPOCH?{%{EPOCH}:}|` as expected on Rocky 9 is unchecked. If it does not, openssl-libs & co. would be
  mis-compared (the epoch test documents why this matters).
- `-print-inventory` and the new collector ran only on Debian/dpkg. Windows agent path compiled
  (`GOOS=windows go vet`), not run; Windows hosts report no distro and are shown as not assessed.
- Ubuntu Pro detection is a heuristic (any `+esm`/`~esm` package). Not tried on a Pro host.
- Re-matching on a new feed snapshot: `refreshFindings` is covered by an integration test (host re-matched
  after a new snapshot with unchanged packages; left alone when nothing changed). The 10-minute timer
  around it (`RunFindingsRefresh`) was never observed firing on a long-running apid.
- Third-party repository packages that share a source name with a distro package are matched against the
  distro (e.g. NodeSource `nodejs` on Debian showed as "affected, no fix").
- Performance: `defendsec-feeds match` wall time including connect and migrations, ~1.2 million ranges
  loaded: 615 packages 0.95 s, 3,984 packages 3.2 s. No timing at fleet scale, no query plans inspected.
- CI has not run; the branch is not opened as a PR.

## Feature × platform × evidence matrix — additions from slice 4

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Distro-aware matcher (`internal/vuln`) | any | 24 tests incl. backport regressions, mutation-checked | not checked | Debian 13 only (real feeds); **Ubuntu 22.04 and Rocky 9: PENDING** |
| Agent: distro, release, package manager, source packages | linux dpkg | parser tests, green | not checked | run on hermesagent (615 packages) |
| Agent: same, rpm | linux rpm | parser tests on hand-written output | not checked | **not run** |
| Findings storage + `/v1/findings` API | linux, Postgres 16.15 | storepg + control integration tests, green | not checked | real apid + real agent |
| Console findings (advisories, host, detail, policy) | any | model logic unit-tested | not checked | rendered by a built console via curl; not in a browser |
| Zero findings on a fully patched host | Ubuntu 22.04, Rocky 9 | synthetic only (by construction) | not checked | **PENDING** |

## Slice 7a — external surface scanner (migration 022)

- Date: 2026-10-24 UTC (2026-10-23 evening MDT). Host `hermesagent`, go1.26.10 linux/amd64, node v22.23.3.
- Postgres: lookout's own database on titan CT 119 (PG 16), via `TEST_DATABASE_URL`.
- Branch `lookout/7a-surface`. What it adds: `internal/surface` (checks, scanner, fake resolver), migration
  `022_surface.sql`, `storepg/surface.go`, `control/surface.go` (`/v1/assets`, `/v1/surface/findings`,
  `/v1/surface/scan`, daily schedule), controls catalog entries, the Assets and Surface console pages.
  Reference: [SURFACE.md](SURFACE.md).

### Commands

| # | Command | Exit | Result |
| --- | --- | ---: | --- |
| 1 | `go build ./...` | 0 | green |
| 2 | `go vet ./...` | 0 | green |
| 3 | `GOOS=windows go vet ./...` | 0 | green |
| 4 | `TMPDIR=/tmp go test -count=1 ./...` with `TEST_DATABASE_URL` unset | 0 | every package `ok` (database tests skip) |
| 5 | `go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/... ./internal/feeds/runner/...` (the CI integration command) with `TEST_DATABASE_URL` set | 0 | all `ok` |
| 6 | `go test -race -count=1 ./internal/surface ./internal/control` (Postgres set) | 0 | no race reported |
| 7 | `govulncheck ./...` (with `github.com/miekg/dns` v1.1.73 added) | 0 | "No vulnerabilities found" |
| 8 | `scripts/check-reproducible.sh` | 0 | green |
| 9 | `npm test` | 0 | `# tests 89 / # pass 89 / # fail 0`, of which 9 are new (`lib/surface-model.test.ts`) |
| 10 | `npm run lint` | 0 | no errors, no warnings |
| 11 | `npm run build` (Next.js, includes TypeScript) | 0 | green, `/assets`, `/surface`, `/api/assets`, `/api/assets/[id]`, `/api/surface/scan` built |

### Tests

- `internal/surface`: **99 pass** (tests and subtests), 0 fail, 0 skip, 81.6% statement coverage. Every check
  runs on fixtures (`example.com`, RFC 5737 addresses) through a fake resolver, MTA-STS against an HTTPS
  server with a private CA, and TLS against a local TLS server with crafted certificates (healthy, expired,
  5 and 20 days left, wrong name, missing intermediate, self-signed, TLS 1.0/1.1 accepted). The real DNS
  resolver (`NetResolver`) is tested against a local DNS server: DO and CD bits, UDP truncation to TCP,
  next server on error, SERVFAIL as an answer.
- **Mutation-checked** by hand: 17 deliberate breaks of the code (SPF limit 10 to 11, void limit, `+all`
  severity, 7- and 30-day thresholds, DKIM key-size thresholds, DNSSEC AD flag and checking-disabled retry,
  shared-hosting cap, authorisation check removed, query budget removed, loopback allowed, dial guard
  removed, MTA-STS redirect following, sp-weaker inverted, no_rua inverted). Each made a test fail. Two
  survived the first round (the exact-11 SPF boundary, and MTA-STS redirect following, because the
  redirect target also failed); tests were added and both are now killed.
- `internal/storepg` (4 new, real Postgres): asset lifecycle and authorisation, first-seen / resolved /
  reopened bookkeeping across five scans, "a check that could not run resolves nothing", observations
  stored per scan, recording refused for an unauthorised asset.
- `internal/control` (5 new, real Postgres): the whole pipeline through the handlers (declare, scan refused
  while unconfirmed with zero DNS queries, confirm, scan, read findings, fix the zone, rescan, finding
  closes with first-seen before resolved, withdraw confirmation, remove), viewer read-only, asynchronous
  scan, the schedule scans only due and confirmed assets, per-asset cooldown and concurrency.
- `internal/controls`: the new signals and catalog entries pass the existing well-formedness tests.

### Real runs

1. **A production domain** (Mason's company, declared as a domain plus its `www` hostname, no port checks):
   apid and the scanner as built, real DNS from `hermesagent`, real TLS handshakes, one scan in about 2
   seconds, 14 checks assessed and none not assessed. **5 findings, details reported privately.** Every
   one was checked against a manual `dig` or `openssl` and matched, and so were the checks that produced
   no finding: the SPF include chain and its lookup count, the DMARC record, the certificates (the
   SHA-256 fingerprints and the days remaining equal `openssl x509 -fingerprint`), and TLS 1.0 and 1.1
   being rejected (`openssl s_client -tls1` and `-tls1_1` answered alert 70, the scanner recorded
   "protocol version not supported"). The console then rendered both pages from that data.
2. **Port check on a real address**, this host's own LAN address (the titan lab VMs 120/121 are not
   started yet, see below). Three throwaway listeners were started on 8080, 6379 and 5432. Result:
   4 of the 16 ports open, 12 closed, none filtered: 22 (info), 5432 and 6379 (high), 8080 (low). That
   equals what `ss -ltn` showed listening on all interfaces; port 25 listens only on loopback and was
   correctly reported closed. After the listeners were stopped a second scan resolved the three and
   kept 22 open.
3. **Console to apid** with `curl`: login with the admin token, `/assets` and `/surface` rendered with the
   data above (HTML fetched with `curl`; **no browser was used**), `POST /api/assets` (201, unconfirmed),
   scan of an unconfirmed asset (409), loopback address refused (400), confirm and withdraw, remove, no
   session (403). Declare, confirm, remove and scan appear in `/v1/audit` with the acting identity.

### Not verified

- **The titan lab VMs 120 and 121.** They were not started (it needs Mason's approval). The port check has
  run on one real address, but not on those two hosts.
- Only one production domain has been scanned, and it is on Cloudflare with Microsoft 365 mail. A Google
  Workspace domain, a domain with a real MTA-STS policy, a DNSSEC-signed domain, a domain with CAA, a
  certificate close to expiry and a server that accepts TLS 1.0 were **not** seen in a real run: those
  paths are verified on fixtures only.
- MX hosts' own TLS (SMTP STARTTLS) is not tested; see SURFACE.md.
- The daily schedule was run by calling its function in a test, not observed firing on a long-running apid.
- No browser: the pages were fetched as HTML, the client-side forms (declare, confirm, scan now) were
  never clicked.
- IPv6 targets were not exercised outside unit tests. The built-in Cloudflare ranges were copied from
  cloudflare.com/ips on 2026-10-24.
- Behaviour behind a firewall that drops DNS or outbound TCP is covered by the not-assessed paths in
  tests, not by a real blocked network.
- Windows: `GOOS=windows go vet` is green; the scanner never ran there.

## Feature × platform × evidence matrix — additions from slice 7a

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Email auth checks (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT) | linux | 99 tests incl. mutation checks, fixtures | see PR | one production domain, confirmed with `dig` |
| DNS hygiene (DNSSEC, CAA, dangling CNAME) | linux | fixtures; DNSSEC broken/validated on a fake validating resolver | see PR | one production domain: unsigned and no CAA confirmed with `dig`; validated and broken chains **not seen for real** |
| TLS (expiry, name, chain, TLS 1.0/1.1) | linux | local TLS server, crafted certificates | see PR | two real hostnames, confirmed with `openssl` |
| Port check | linux | local listeners, fixtures | see PR | this host's LAN address; **lab VMs 120/121 pending** |
| Storage, API, schedule | linux, Postgres 16 | storepg and control integration tests | see PR | real apid, real scans |
| Console Assets and Surface pages | any | model logic unit-tested | see PR | rendered by a built console via curl; not in a browser |
