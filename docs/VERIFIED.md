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

Branch `scout/4-matcher` (merged, PR #84); measurement and fixes on `scout/4b-matcher-fixes`.
**Exit measurement, 2026-10-23, two real freshly patched hosts: Ubuntu 22.04 = 0 findings after one matcher
fix (it was 2 before); Rocky 9 = 8 findings, all one cause that is not a comparator bug: Red Hat's feed is
ahead of Rocky's repositories. The "zero findings on Rocky 9" criterion is therefore NOT met.** Details in
"Exit measurement" below. The first sections record what was verified before the hosts existed.

### Exit measurement (real hosts)

Hosts: VM 120 Ubuntu 22.04 (`jammy` cloud image, kernel 5.15.0-198, 597 dpkg packages,
`apt list --upgradable` empty and `apt-get --dry-run full-upgrade` 0 upgraded after the last reboot, Ubuntu
Pro not attached) and VM 121 Rocky 9.8 (cloud image, kernel 5.14.0-687.59.1.el9_8, 427 rpm, `dnf
check-update --refresh` exit 0 after reboot), built by grumpy (t_b28b0b55) and inventoried with
`defendsec-agentd -print-inventory` (binary sha256 matched on both). Feeds: the nine-feed snapshot 1 loaded
2026-10-23 20:55 -06:00 (RHEL 9 OVAL last-modified 2026-10-23 21:44 GMT, i.e. current to the hour). Command:
`defendsec-feeds match <inventory.json>` (exit 0 = no findings).

| Host | Matcher | Result |
| --- | --- | --- |
| Ubuntu 22.04 | as merged (7471d23) | exit 2: **2 findings**, `libbpf0` CVE-2022-3534, CVE-2022-3606 |
| Ubuntu 22.04 | + epoch fix | exit 0: **0 findings, 0 unfixed, 0 informational** (237 packages distro-mapped, 1,058 advisories examined) |
| Rocky 9.8 | as merged, and with the epoch fix | exit 2: **8 findings**, all `kernel` 5.14.0-687.59.1.el9_8 → 0:5.14.0-687.60.1.el9_8 (3 high, 5 medium); 194 packages mapped, 4,330 advisories examined |

**Triage.**

1. *Ubuntu `libbpf0`: matcher bug, fixed.* dpkg's `Source:` field and an rpm's `SOURCERPM` name never carry the
   epoch, yet the feed's fixed version does (`1:0.5.0-1ubuntu22.04.1`). The matcher compared the bare source
   version `0.5.0-1ubuntu22.04.1` (epoch 0) to the fixed `1:…` and read it as older. Synthetic inventories and
   unit tests could not show this because they never paired a source version with an epoched binary. Fix:
   `inheritEpoch` in `internal/vuln/match.go` gives the source version the binary's epoch. The same bug
   would have hit every rpm with an epoch (e.g. NetworkManager at epoch 1 on the Rocky host), which the
   Rocky inventory confirms exist. Regression tests
   `TestSourceVersionInheritsBinaryEpoch` (dpkg and rpm, patched and one-behind) and `TestInheritEpoch`;
   reverting the one-line change fails the first with exactly the libbpf finding.
2. *Rocky kernel: not a comparator bug; the feed source is wrong for Rocky.* The 8 CVEs come from a RHEL 9
   advisory issued 2026-10-22 (kernel 687.60.1). Rocky's BaseOS mirror
   (`dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/k/`) listed 687.59.1 as its newest kernel at
   2026-10-24 03:33 UTC, and the VM's `dnf check-update` found nothing newer. So the host **is** fully patched
   as far as Rocky can patch it, and the finding names a build the operator cannot install. Rocky and Alma
   follow RHEL by days, so this will recur after every RHEL kernel advisory. Right fix: load Rocky's and
   Alma's own errata (Rocky: Apollo `/api/v3/advisories/` RLSA entries or the repo `updateinfo`) and match
   `rocky`/`almalinux` hosts against those. Not done in this branch; it is a new feed, not a matcher fix.
   Nothing else on Rocky was flagged out of 194 mapped packages.

**Negative control** (so "0" is not a matcher that flags nothing): the same two inventories with four packages
downgraded (`libssl3`, `openssh-server`, `openssl-libs`, `sudo`) give 110 findings (Ubuntu) and 93 (Rocky).

**Also shown by these hosts:** rpm collection on a real rpm host works (epoch rendered as `1:`, `SOURCERPM`
parsed, 427 rpm packages including the kernel), which was previously unverified.

**Still not shown:** zero findings on Rocky 9; the Ubuntu Pro heuristic (no Pro host); a host older than its
latest point release; browser rendering; CI on the 4b branch.

### Exit measurement, re-run on freshly synced feeds (2026-10-23 21:43 -06:00 / 2026-10-24 03:43 UTC)

Same two inventories (`ubuntu-2204.json` sha256 `6668f98b…1b4c`, `rocky-9.json` sha256 `a4d4da67…6a`),
matcher at `scout/4b-matcher-fixes` (epoch fix included), a new scratch database (`exit4`) and an empty feed
cache, so every feed was downloaded again (`not_modified=false` on all nine). Snapshot **1** of that database;
RHEL 9 OVAL `Last-Modified` 2026-10-23 21:44:21 GMT, fetched 03:43:37 UTC. Commands:
`defendsec-feeds sync` then `defendsec-feeds match --all [--json] <inventory.json>` (`--all` also lists
no-fix entries).

| Host | Packages | Distro-mapped | Fixable (fix to install) | No fix published | Informational | KEV | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 22.04 (VM 120, Pro not attached) | 597 dpkg | 237 | **0** | 0 | 0 | 0 | 0 |
| Rocky 9.8 (VM 121, matched as `rhel 9`) | 422 reported (see below) | 194 | **8** | 0 | 0 | **0** | 2 |

Ubuntu: nothing open, and `--all` shows no no-fix or informational entries either, so there is no ESM-only
row to classify. Rocky: the same 8 `kernel`
findings as before (CVE-2025-22063, -38147, CVE-2026-64481, -68202, -68299, -68448, -80530, -80536;
advisory ids = CVE ids, range ids 625098 … 625602, feed `rhel-9`, all `fixed`, EPSS 0.001–0.005, none in
KEV), installed `5.14.0-687.59.1.el9_8`, fixed `0:5.14.0-687.60.1.el9_8`.

Classification of the 8: **genuine distro lag, not a matcher bug.** At about 03:50 UTC the Rocky BaseOS mirror's
newest kernel is still `kernel-5.14.0-687.59.1.el9_8` (listing of
`dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/k/`: …687.56.1, .57.1, .58.1, .59.1; no .60.1), so
the operator cannot install the build the finding names. The feed is correct for RHEL; the host is a Rocky host.
These are Rocky-lag findings on a host that is fully patched, so they are false positives for a Rocky fleet
until Rocky's own errata (Apollo RLSA / `updateinfo`) is loaded. Not fixed here: a new feed, not a matcher
change. **The zero-findings criterion is met for Ubuntu 22.04 and NOT met for Rocky 9.**

Package count: the card quoted 427 (`rpm -qa`) against 422 in the export. `ParseRPMQuery` drops
`gpg-pubkey` pseudo-packages (`internal/hostinv/packages.go:135`, test `packages_test.go`), which would account for
5 keys; the VM is powered off, so `rpm -qa | grep -c gpg-pubkey` was **not** run and the 5 is unconfirmed on
the host itself.

Not verified in this re-run: the Ubuntu Pro heuristic, other Rocky/Alma point releases, and the repeat of the
negative control (done earlier, unchanged inputs).

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

- **Zero findings on Rocky 9** (see the exit measurement above): 8 kernel findings from the RHEL-ahead-of-Rocky gap. Resolved in slice 4c below: 0 fixable, the 8 are `awaiting_vendor`.
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
| Distro-aware matcher (`internal/vuln`) | any | 24 tests incl. backport regressions, mutation-checked | not checked | Debian 13, Ubuntu 22.04 (0 findings, real host), Rocky 9.8 (8 findings: RHEL feed ahead of Rocky repos) |
| Agent: distro, release, package manager, source packages | linux dpkg | parser tests, green | not checked | run on hermesagent (615 packages) |
| Agent: same, rpm | linux rpm | parser tests on hand-written output | not checked | **not run** |
| Findings storage + `/v1/findings` API | linux, Postgres 16.15 | storepg + control integration tests, green | not checked | real apid + real agent |
| Console findings (advisories, host, detail, policy) | any | model logic unit-tested | not checked | rendered by a built console via curl; not in a browser |
| Zero findings on a fully patched host | Ubuntu 22.04, Rocky 9 | synthetic only (by construction) | not checked | **PENDING** |

## Slice 7a — external surface scanner (migration 023)

- Date: 2026-10-24 UTC (2026-10-23 evening MDT). Host `hermesagent`, go1.26.10 linux/amd64, node v22.23.3.
- Postgres: lookout's own database on titan CT 119 (PG 16), via `TEST_DATABASE_URL`.
- Branch `lookout/7a-surface`. What it adds: `internal/surface` (checks, scanner, fake resolver), migration
  `023_surface.sql`, `storepg/surface.go`, `control/surface.go` (`/v1/assets`, `/v1/surface/findings`,
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

1. **A production domain** (declared as a domain plus its `www` hostname, no port checks):
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
- Only one production domain has been scanned (one mail and DNS provider set). A Google
  Workspace domain, a domain with a real MTA-STS policy, a DNSSEC-signed domain, a domain with CAA, a
  certificate close to expiry and a server that accepts TLS 1.0 were **not** seen in a real run: those
  paths are verified on fixtures only.
- MX hosts' own TLS (SMTP STARTTLS) is not tested; see SURFACE.md.
- The daily schedule was run by calling its function in a test, not observed firing on a long-running apid.
- Browser: the reviewer clicked Scan now in a browser (round 1); declare and confirm forms were only
  exercised through the API.
- IPv6 targets were not exercised outside unit tests. The built-in Cloudflare ranges were copied from
  cloudflare.com/ips on 2026-10-24.
- Behaviour behind a firewall that drops DNS or outbound TCP is covered by the not-assessed paths in
  tests, not by a real blocked network.
- Windows: `GOOS=windows go vet` is green; the scanner never ran there.

## Feature × platform × evidence matrix — additions from slice 7a

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Email auth checks (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT) | linux | 99 tests incl. mutation checks, fixtures | green, run 40063765582 (commit d491180) | one production domain, confirmed with `dig` |
| DNS hygiene (DNSSEC, CAA, dangling CNAME) | linux | fixtures; DNSSEC broken/validated on a fake validating resolver | green, run 40063765582 (commit d491180) | one production domain: unsigned and no CAA confirmed with `dig`; validated and broken chains **not seen for real** |
| TLS (expiry, name, chain, TLS 1.0/1.1) | linux | local TLS server, crafted certificates | green, run 40063765582 (commit d491180) | two real hostnames, confirmed with `openssl` |
| Port check | linux | local listeners, fixtures | green, run 40063765582 (commit d491180) | this host's LAN address; **lab VMs 120/121 pending** |
| Storage, API, schedule | linux, Postgres 16 | storepg and control integration tests | green, run 40063765582 (commit d491180) | real apid, real scans |
| Console Assets and Surface pages | any | model logic unit-tested | green, run 40063765582 (commit d491180) | rendered by a built console via curl; reviewer clicked Scan now in a browser |

| Zero findings on a fully patched host | Ubuntu 22.04, Rocky 9 | synthetic (by construction) | not checked | Ubuntu 22.04: **0 (met)**; Rocky 9: **8 (not met)**, see triage |

## Slice 4c — Rocky/Alma errata feeds and `awaiting_vendor` (migration 022)

Branch `scout/4b-matcher-fixes`, on top of `4d61536`. Problem measured in 4b: a fully patched Rocky 9.8 host had
8 *fixable* kernel findings, all Red Hat fixes (`5.14.0-687.60.1.el9_8`) that Rocky had not yet released (newest
Rocky 9 kernel `687.59.1`, the installed one). Not a matcher bug; rebuild lag. This slice loads Rocky's and
AlmaLinux's own errata and gives such a finding a state that is never "fixable".

### What changed

- Feeds `rocky-8`, `rocky-9` (Apollo `/v2/advisories`, walked page by page, `internal/feeds/rocky`,
  `internal/feeds/fetch/paged.go`) and `almalinux-8`, `almalinux-9` (`errata.full.json`, `internal/feeds/alma`),
  on by default; bulk only, snapshot digests, signed-bundle export/import like every other feed.
- Matcher: Rocky and Alma are matched against their own feed **and** RHEL's (`internal/vuln/match.go`). New kind
  `awaiting_vendor`: fixed by Red Hat, not released by the rebuild. Not fixable, sorted after fixable, KEV ones
  still alert. CentOS Stream / RHEL / Oracle are untouched.
- Migration `022_awaiting_vendor.sql` (idempotent): `advisory_ranges.issued DATE`, `vuln_findings.kind` allows
  `awaiting_vendor`, and a once-only (meta-flagged) reset of the RHEL feeds' loaded digest so ranges loaded before
  this migration get their issue dates on the next sync.
- API: `/v1/findings?kind=awaiting_vendor`; summary gains `awaitingVendor`, `kevAwaitingVendor` (`open` stays the
  fixable count). `defendsec-feeds match` prints fixable / awaiting_vendor / no_fix / informational, and the same
  tally for KEV; `--json` has `counts`. Console: badge, reason line, red notice for exploited CVEs awaiting the vendor.

### Findings about the sources (checked live, 2026-10-24)

- Apollo `/api/v3/advisories/` ignores **every** filter (`cve`, `product`, `kind`, `after_raw`, with or without the
  `filters.` prefix: all returned `total` 10,198) and is 2.7 MB per page of 100. `/v2/advisories` honours
  `filters.product`, `filters.type`, `filters.cve`; release 9 security = 1,558 advisories, 16 pages.
- Apollo's `total` counts 10 advisories twice (1,558 reported, 1,548 distinct names; identical content), and the order of
  CVEs/packages inside an advisory changes between requests. First implementation tripped both: the walk was refused as
  "short" (1,548 of 1,558), and the digest changed on every walk. Fixed (received-vs-total, and a normalised stored form
  with sorted lists); a second walk now reports `unchanged` (digest `56a86fc255db` twice).
- A page takes about 5 s. A walk: Rocky 9 56–75 s, Rocky 8 190–230 s. The full default sync is about 5–6 minutes.

### Exit measurement (real hosts, 2026-10-24 04:31 UTC)

Scratch database `exit4` (the slice-4 database, **upgraded in place**: migration 022 on existing data), feed cache
from the 4b run, then `defendsec-feeds sync` (all 13 enabled feeds fetched; the log is `sync-4c-full.txt`, the final
repeat `sync-4c-final.txt`), then `defendsec-feeds match <inventory.json>`. Same inventories as 4b
(`ubuntu-2204.json`, `rocky-9.json`; VMs 120 and 121, powered off). Latest snapshot 7.

| Host | Packages | Distro-mapped | Fixable | awaiting_vendor | no_fix | Informational | KEV | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 22.04 (VM 120) | 597 | 237 | **0** | 0 | 0 | 0 | 0 | 0 |
| Rocky 9.8 (VM 121, now matched as `rocky 9`) | 422 | 197 | **0** | **8** | 0 | 0 | 0 | 0 |

The 8 are exactly the CVEs of the card (CVE-2025-22063, -38147, CVE-2026-64481, -68202, -68299, -68448, -80530,
-80536); each reads `fixed upstream by Red Hat in 0:5.14.0-687.60.1.el9_8 on 2026-10-22; not yet released by Rocky
Linux`; installed `5.14.0-687.59.1.el9_8`, feed `rhel-9`. Before (4b, same inventory): `8 findings (fix available)`,
exit 2.

**Rocky has not published 687.60.1**, so the 8 did not flip. Mirror listing, taken 04:28 UTC
(`dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/k/`, `measure/mirror-rocky9-kernel.final.txt`):
`kernel-core-5.14.0-687.54.1 (2026-Oct-02), .56.1 (Oct-08), .57.1 (Oct-13), .58.1 (Oct-15), .59.1 (Oct-21)`; zero entries
matching `687.60`. Rocky's Apollo feed and Alma's `errata.full.json` also top out at `687.59.1`. None of the 8 CVEs is
in Alma 9's errata (0 of 1,992 errata mention any), `filters.cve` is empty on Rocky for CVE-2025-22063, and the matcher
found no Rocky range covering the other seven (a covering range would have made them fixable or clean, not awaiting). When Rocky ships
`687.60.1` the 8 become fixable on the next sync; that transition is tested (below) but **has not been observed
on real data**.

The date in the reason comes from Red Hat's OVAL `<issued>`: it was empty until the migration's forced reload re-read
the RHEL feeds (rhel ranges with an issue date: 0 of 407,436 before, 407,436 of 407,436 after).

### Commands and results

| Command | Result |
| --- | --- |
| `go build ./...`, `go vet ./...`, `GOOS=windows go vet ./...`, `gofmt -l` | green |
| CI `postgres-integration` command on the titan test PG (CT 119): `go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/... ./internal/feeds/runner/...` | `ok` ×4; storepg 100 pass, db/migrations 5, control 152, feeds/runner 23; 0 fail, 0 skip |
| `go test -p 1 -count=1 -v ./...` with `TEST_DATABASE_URL` (titan) | 1,000 pass, 1 fail, 5 skip. The fail is the known `TestQuarantinePathMovesFile` EXDEV (same as slice 0). The 5 skips are the eBPF/root, netns script and `pwsh` tests, none in this slice |
| `go test -v ./internal/vuln/... ./internal/feeds/... ./cmd/...` | 185 pass, 0 fail, 0 skip (vuln 44, feeds/fetch 19, alma 3, rocky 6, nevra 3, runner 23) |
| `npm test` / `npm run lint` / `npx tsc --noEmit` / `npm run build` | 83 pass / 0 problems / clean / built |

New tests that pin the behaviour: matcher (`internal/vuln/rebuild_test.go`: awaiting not fixable, flips to fixable
when the rebuild ships, rebuild version wins, RHEL/CentOS unchanged, KEV kept, no own feed ⇒ `no_feed`, Rocky ≠ Alma,
ordering); parsers on fixtures (`alma`, `rocky`, `nevra`); the paged walker (assembly, dedupe, retry, short-walk
refusal, server-side repeats, normalisation, page cap); `runner/rebuild_test.go` (sync of RHEL+Rocky+Alma with a paged
fake Apollo, the query contains only the release filter and the page number, ranges carry issue dates, second sync
`unchanged`, export → signed bundle → import into a second database gives the same rows, an empty walk keeps loaded
data); Postgres (`storepg/rebuild_test.go`: end-to-end awaiting finding persisted, ordered after fixable in SQL,
filtered, counted in the summary, flipped in place; migration allows the kind and rejects others; the one-time RHEL
reload); apid (`control`: Rocky host through `processVulnAlerts` has 0 fixable and 2 awaiting, the KEV one raises an
alert, summary JSON has the new keys, flips to fixable on a new snapshot). On their first run the tests caught the
issue date being dropped between parser and store (runner test) and the new insert placeholder
(`TestAdvisorySQLPlaceholderCounts`); the real sync caught the two Apollo problems above. The Postgres test also pins
the list order: sorting `kind` alphabetically would put `awaiting_vendor` before `finding`.

### Not verified

- **No real AlmaLinux host.** `synthetic-alma-9.json` is the Rocky inventory relabelled `almalinux`: 0 fixable, 8
  awaiting_vendor. That proves the Alma path runs on real feed data, not that an Alma host's package list matches.
- **The flip to fixable on real data** (Rocky ships 687.60.1) has not happened; only fixtures and the Postgres
  integration tests show it.
- **No real Rocky 8 or Alma 8 host.** Their feeds load (Rocky 8: 112,751 ranges, 4,701 advisories; Alma 8: 82,763; Alma 9:
  125,671; Rocky 9: 123,007) and the parsers are the same code, nothing more.
- **Not rendered in a browser.** The console compiles and its model logic is unit-tested; the red notice and the badge
  were not looked at. The apid alert for a KEV awaiting finding is covered by an integration test, not by a running apid.
- **A real KEV awaiting_vendor finding does not exist** in these inventories (KEV 0); KEV handling is tested on fixtures.
- Rocky errata that carry no CVE, or an Apollo that lags Rocky's mirror, could show a shipped fix as awaiting for a while.
  The reverse (fixable when Rocky has not shipped) cannot happen: fixable now requires the rebuild's own errata.
- Apollo availability: the walker retries 5xx and network errors three times per page; a longer outage fails the feed
  and keeps the loaded data. Not exercised against a real outage.
- Rocky/Alma 10: no feed (Red Hat has no v2 OVAL for 10).
- Not opened as a PR; CI had not run on the branch when this was written. (Since then: branch CI was green on `0ff9fe1` and main CI on `5b9eae0`, per the reviewer.)

## Feature × platform × evidence matrix — additions from slice 4c

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Rocky/Alma errata feeds (`rocky-N`, `almalinux-N`) | any | parser fixtures, paged-walker tests, runner sync/export/import (titan PG) | not checked | real feeds loaded into Postgres 16.15 (Rocky 9 5.9 MiB / Alma 9 29.3 MiB stored) |
| `awaiting_vendor` matching | rpm, Rocky/Alma | 9 matcher tests, storepg + apid integration (titan PG) | not checked | Rocky 9.8 VM 121: **0 fixable, 8 awaiting_vendor** (met); Alma: synthetic relabel only |
| Flip awaiting → fixable | rpm, Rocky/Alma | fixtures + Postgres + apid | not checked | **not observed** (Rocky has not shipped 687.60.1) |
| Console: awaiting badge, KEV red notice | any | model logic unit-tested | not checked | **not rendered** |

## Slice 5 — exposure view (migration 024)

Branch `scout/5-exposure-view`, from `5b9eae0` (slice 4c merged), merged with `origin/main` at `b9ee4f6` (slice 7a took
migration 023, so this slice's is **024**). Date of the runs: 2026-10-24 UTC.

### What changed

- `internal/exposure`: the ranking rule (KEV newest-first, EPSS, CVSS, severity label, advisory id), as code.
- `internal/storepg/exposure.go`: advisories grouped by bucket, ranked and paged by keyset in SQL (`ListExposure`),
  one advisory's hosts and snapshots (`GetExposureDetail`), the Monday summary (`ExposureSummary`), the daily trend
  (`ExposureTrend`). `RecordFindingsFor` records how a finding closed from the host's inventory.
- `internal/control/exposure.go`: `GET /v1/exposure/{summary,findings,advisory,trend}`.
- Migration `024_exposure.sql`: `vuln_findings.resolution`, `resolved_installed`, `upstream_fixed_on`;
  `vuln_finding_intervals`; one index.
- Console: Exposure page (`/advisories`), Fleet page cards, provenance drawer, feed-age banner on both, window
  selector over days or audit periods. `lib/exposure-model.ts` holds the ranking check and the rank-reason text.
- `scripts/seed-exposure-demo.sql` (synthetic data, refuses to run unless the database name contains `demo`),
  `docs/screenshots/*.png`, `docs/EXPOSURE.md`.

### Commands and results (this box, Postgres 16 on titan CT 119 for the integration tests)

| # | Command | Result |
| --- | --- | --- |
| 1 | `go build ./...` | exit 0 |
| 2 | `go vet ./...` and `GOOS=windows go vet ./...` | both clean |
| 3 | `TMPDIR=/tmp TEST_DATABASE_URL=… go test -p 1 -count=1 -json ./...` | exit 0: **1,121 pass, 0 fail, 5 skip** (root/eBPF, pwsh, as before); 54 packages pass, 13 have no tests |
| 4 | CI integration command: `go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/... ./internal/feeds/runner/...` | all four `ok` |
| 5 | `npm test` | `# tests 121 / # pass 121 / # fail 0` (was 83 before this slice; 30 new in `lib/exposure-model.test.ts`, 8 from slice 7a) |
| 6 | `npm run lint`, `npx tsc --noEmit -p .` | clean, clean |
| 7 | `npm run build` | green, `/advisories` dynamic |

New tests: `internal/exposure` (5, the rule and its edge cases), `internal/storepg/exposure_test.go` (4, in a throwaway
database per run: SQL order equals `exposure.Compare` at page sizes 1, 3, 5 and 200 with no repeat or gap, buckets and
summary counts, resolution classification for dpkg and rpm, trend from `first_seen`/`resolved_at` including a recurrence and
days before history), `internal/control/exposure_test.go` (2, through apid's handler: auth, paging by cursor, drawer data,
summary, trend by window and by audit period, every 400, UTC timestamps under `TZ=America/Denver`),
and an assertion in `TestVulnPipelineThroughApid` that patching a host closes its findings as `fixed` at the installed
version.

Mutation checks (each applied to the working tree, test run, then reverted): EPSS sorted ascending, KEV date sorted oldest
first (`ListExposure` order test fails both times); archive-on-reopen disabled (trend test fails: the recurrence loses
its earlier interval); KEV date comparison reversed in `compareRank` (1 npm test fails); the headline made to lead with
CVSS (3 npm tests fail).

### Real runs

**Real data, in-place upgrade** (scratch database `slice5real`, a copy of slice 4's database: 70,913 advisories from the
nine real feeds synced 2026-10-24 02:55 UTC, one real host (this box, Debian 13), schema at 021). `defendsec-apid` built
from this branch started against it and applied 022 to 024 in place (`vuln_finding_intervals` exists afterwards; before it
did not). The matcher then re-ran for the host against the real feeds and the console (`npm run dev`) rendered:

- Fleet: "Vulnerability feeds are current — 9 feeds current, oldest confirmed 2 hours ago"; **Fix this week: 5
  vulnerabilities across 1 host**, ranked EPSS first (all five under 0.01, shown to three places so the order is
  visible), then CVSS; the card names the package and the distro's fixed version. Failed configuration checks: 5 high,
  6 medium, 3 low on 1 host (the real open `sca` alerts). Watch: 1,143 with no fix published, 0 awaiting vendor.
  The 307 informational findings appear nowhere.
- Exposure, watch list: 1,143 advisories, 25 per page; following `Next` gives rows 26–50 of 1,143 with **no row in
  common** with page 1; `Previous` is offered. The page took 0.4 s.
- Trend: one known day (the first snapshot is from today), the earlier 89 days drawn as "no data".

**Synthetic demo data** (scratch database `expo_demo`, `scripts/seed-exposure-demo.sql`: 24 invented hosts, `CVE-2099-*`):
screenshots of every surface the card asks for are in `docs/screenshots/`:
`exposure-ranked-list.png` (KEV newest first, then EPSS, then CVSS; a CVSS 9.8 with EPSS 0.04 ranks 7th), 
`exposure-provenance-drawer.png` (hosts, installed vs fixed version, age, feed and snapshot with SHA-256),
`exposure-resolved-drawer.png` (closed findings: "Fixed: inventory shows demo-ssh 1.1-demo (fix was 1.1-demo)"),
`exposure-watch-list.png` (no fix published; "Fixed by Red Hat on 2026-10-22; awaiting Rocky/Alma"; the red KEV callout),
`fleet-fix-this-week.png`, `fleet-trend.png`. Acknowledging one host's finding through `POST /api/findings` showed
`acknowledged` on that row only in the drawer, and reopening restored `open`.

### Not verified

- **Branch CI** is green on `60d8e7f` (all six jobs: go, postgres-integration, node, isolation, provisioning, secrets-scan; run 40066538275). This file was edited after that run, so the head moved by a docs-only commit; its run is in the handoff.
- **Ranking and the red callout on real KEV data.** The real host has no KEV finding, so KEV ordering, the KEV callout and
  `awaiting_vendor` rows are seen only on synthetic data and in tests. No real Rocky/Alma host was matched in this slice.
- **The trend on real history.** It has one real day. The multi-month shape in the screenshot is synthetic.
- **Resolution on a real host.** `fixed` / `package_removed` is proven by integration tests (dpkg and rpm comparators,
  and through apid's `matchDevice`), not by patching a real host and watching it close. Findings that closed before
  migration 024 show "the reason was not recorded".
- **Load.** The grouped query has not been timed at 10,000 hosts; at one host it is 0.4 s end to end. Each page re-groups
  open findings.
- **Acknowledged** is the operator's console triage; it is shown per host in the drawer, not on list rows, and it does not
  change any count or the ranking.
- **Unsupported-OS hosts** are counted in the console from the fleet it already loads (the OS policy lives there); they
  are not in `/v1/exposure/summary`.
- **Windows hosts** have no feed coverage; they are counted as "not assessed", never as clean.
- Trend counts use each finding's current kind for its whole interval (an awaiting-vendor finding that became fixable
  counts as fixable from its first day).
- Screenshots were taken against `npm run dev`, so the Next.js dev indicator is visible in the corner.
- The agent → apid inventory path was not re-run for this slice (the matcher ran through apid's periodic refresh); that
  code is unchanged except that it now passes the inventory to `RecordFindingsFor`.

## Feature × platform × evidence matrix — additions from slice 5

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Ranking KEV → EPSS → CVSS (`internal/exposure`, SQL, `compareRank`) | any | Go + npm tests, 4 mutation checks | green (run 40066538275) | ranked a real host's 5 fixable findings; KEV not present |
| `/v1/exposure/{summary,findings,advisory,trend}` | linux, Postgres 16 | storepg + control integration (titan PG) | green (run 40066538275) | called through a real apid on a real database |
| Keyset paging | linux, Postgres 16 | page sizes 1/3/5/200, no gap or repeat | green (run 40066538275) | 1,143 advisories, page 2 has no overlap with page 1 |
| Resolution recorded from inventory | dpkg, rpm | integration tests incl. through apid | green (run 40066538275) | not observed on a real host |
| Trend from first_seen/resolved_at | linux, Postgres 16 | integration test with recurrence | green (run 40066538275) | one real day |
| Console: Exposure, Fleet cards, drawer | any | model logic unit-tested | green (run 40066538275) | rendered in a browser on real and synthetic data |

## Slice 7b — surface findings in the exposure view (migration 025)

- Date of the runs: 2026-10-24 UTC. Host `hermesagent`, go1.26.10 linux/amd64, node v22.23.3. Postgres: lookout's own
  database on titan CT 119 (PG 16) via `TEST_DATABASE_URL`; every new storepg test runs in a throwaway database.
- Branch `lookout/7b-surface-exposure`, from `b910939` (slices 5 and 7a merged; migration 025 is the next free number).
  Reference: [EXPOSURE.md](EXPOSURE.md#external-surface-findings-slice-7b), [SURFACE.md](SURFACE.md#evidence-export).

### What changed

- `internal/exposure`: surface findings join the ranking: critical and high right after KEV, medium and low like a
  vulnerability with no EPSS and a CVSS-equivalent of their severity, info never. `internal/storepg/exposure.go`: one
  `UNION ALL` list with six keyset keys; `surface_exposure.go`: summary, drawer, trend series, evidence export.
- Migration `025_surface_history.sql`: `surface_finding_intervals`, `surface_scans.changes`, one index. A reopened surface
  finding now restarts `first_seen` and keeps the interval that ended (it used to keep the first `first_seen`).
- Every recorded scan appends a `surface_scan_recorded` chain entry with the scan's SHA-256 digest in the same transaction
  (`auditInTx` split out of `Audit`). `internal/evidence/surface.go`: the bundle's `surface` section and its verification;
  `defendsec-verify` prints it.
- Console: surface rows in Fix this week and the Exposure list, the surface drawer, the "Seen from outside" Fleet card, a
  second trend chart on its own scale. Seed `scripts/seed-exposure-demo.sql` extended; five screenshots in `docs/screenshots/`.
- **A change to slice 5's code:** the trend's day boundaries followed the database session's time zone
  (`LEAST(d + interval '1 day', …)` read a timestamp as local time). With the server on America/Denver a finding first seen at
  03:00 UTC on the 22nd was counted on the 21st. Now UTC days; `TestTrendDayBoundariesIgnoreSessionTimezone` fails without it.

### Commands and results

| # | Command | Result |
| --- | --- | --- |
| 1 | `go build ./...`, `go vet ./...`, `GOOS=windows go vet ./...` | exit 0, clean |
| 2 | `TMPDIR=/tmp go test -count=1 -json ./...` with `TEST_DATABASE_URL` unset | exit 0: 977 tests pass, 167 skip (database tests); 54 packages pass |
| 3 | the same with `TEST_DATABASE_URL` set (`-p 1`) | exit 0: **1,148 tests pass, 0 fail, 5 skip** (root/eBPF, pwsh, as before); 54 packages pass (slice 5 reported 1,121) |
| 4 | CI integration command: `go test -p 1 -count=1 ./internal/storepg/... ./db/migrations/... ./internal/control/... ./internal/feeds/runner/...` | all four `ok` |
| 5 | `go test -race -p 1 -count=1 ./internal/evidence ./internal/exposure ./internal/storepg ./internal/control ./internal/surface` | all `ok`, no race |
| 6 | `govulncheck ./...` | "Your code is affected by 0 vulnerabilities" (one vulnerability in a required module that the code does not call, as before) |
| 7 | `scripts/check-reproducible.sh` | green |
| 8 | `npm test` | `# tests 142 / # pass 142 / # fail 0` (121 before; new: 6 in `lib/exposure-model.test.ts`, 15 in `lib/surface-exposure.test.ts`) |
| 9 | `npm run lint`, `npx tsc --noEmit -p .`, `npm run build` | clean, clean, green |

### Tests added

- `internal/exposure` (4): the mixed order, a surface row ignoring KEV/EPSS/CVSS it was handed, KEV above an exposed port, the
  score table.
- `internal/storepg/surface_exposure_test.go` (12, throwaway databases): the mixed list in the order the rule gives
  (a KEV vulnerability, critical and high ports and SPF, then EPSS, then DMARC `p=none` between the CVSS-6 and CVSS-4
  vulnerabilities, then the low CAA finding; info never listed); the SQL order equals `exposure.Compare` and paging by keyset
  at limits 1, 2, 4 and 200 returns every row once; surface never in the watch list or `kevOnly`; resolved findings move to the
  Resolved list and a removed asset's findings leave every list and count while the rows stay; **missing evidence never ranks**
  (a check that could not run produces no row; a finding whose latest check could not run stays, marked unconfirmed, with its
  old `last_seen`); the summary counts (assets, unauthorised, scanned, by severity, info, affected, last scan, checks not
  assessed); the drawer with its raw observation and refused keys; the trend series (own series, unknown before the first
  scan, a closed gap not counted as open, no leak into the vulnerability series); the evidence export verifying on a real
  database and failing on an edited observation and on a moved open date; unattested scans named, not failed; and day
  boundaries under a `America/Denver` session.
- `internal/evidence/surface_test.go` (10): attested scans and recomputed intervals; five ways to alter a finding's dates and
  eight ways to alter an observation, a change or a scan, each failing; reformatted JSON hashing the same; a withheld scan; an
  unattested scan; an edited provenance sentence; no surface check without a section; a failed scan not cascading into its
  asset's findings.
- `internal/control/exposure_surface_pg_test.go` (1, through apid's handlers on a fake resolver): scan, list (critical SPF `+all`
  above medium DMARC), drawer with the raw observation, 400/404 for bad keys, summary and trend, fix the zone and scan again
  (the finding leaves the list and appears in Resolved), signed export, `Verify` on the bundle.
- `internal/control/surface_pg_test.go`: a scan that fails (authorisation withdrawn while it ran) is written to the ledger as
  `surface_scan_failed`, for the schedule and for a manual scan; removing the schedule's call makes the test fail.
- `lib/exposure-model.test.ts` / `lib/surface-exposure.test.ts`: the same order as the Go test (`compareRank` mixed order,
  `isRanked`), the reason text, the card text ("External surface: 5 findings (1 high) across 3 assets, last scanned 2 hours
  ago", never "0 findings" for an unscanned surface), the Fix this week description and empty text, intervals, the observation
  text, the separate trend chart.

**Mutation checks** (each applied to the working tree, tests run, then reverted): Go ranking SQL: urgent band to 2, medium
scored 8.0, info not excluded, surface rows in the watch bucket, removed assets still listed, reopened finding keeping its
`first_seen`, attestation written under another action name: each made at least one test fail. Verifier: digest comparison
skipped, closed date ignored, chain entry without a scan not flagged, change type not in the digest (needed one more test,
now present), unattested counted as attested: each made at least one test fail.

### Real runs

- **Seeded console** (database `defendsec_demo_7b`, `scripts/seed-exposure-demo.sql`: 24 invented hosts, `CVE-2099-*`, five
  invented assets on `example.com`/`example.net` and 192.0.2.10 / 198.51.100.7; a built console on `next start` against a real
  `defendsec-apid`): the Fix this week list mixes the two kinds in the order the rule gives (3 KEV vulnerabilities; SMB 445,
  RDP 3389 and a certificate expiring in 4 days; then medium vulnerabilities; DMARC `p=none` after the CVSS-6.5 and 5.3
  ones; the low CAA and MTA-STS findings; the low vulnerability last). The Fleet card reads "External surface: 6 findings
  (1 critical, 2 high) across 4 assets, last scanned 2 hours ago", with the check that could not run and the unconfirmed
  asset named. Screenshots: `docs/screenshots/exposure-ranked-mixed.png`, `exposure-surface-drawer-smb.png`,
  `exposure-surface-drawer-dmarc-reopened.png` (two intervals: closed 28 days, open 20 days),
  `exposure-resolved-mixed.png`, `fleet-surface-card-and-trend.png` (the surface bar chart on its own scale beside the
  vulnerability chart). They contain only seeded data.
- **Lab port check on a real host (the check 7a left pending).** Lab VM 120 (`defendsec-ubuntu2204`, Ubuntu 22.04.5, a DHCP
  address on the private LAN), declared as an `ip` asset and confirmed through the admin API by the operator's instruction
  (the lab VMs are the scanner's designated test target), a real `defendsec-apid` on a fresh database with the schedule off, the real
  scanner (no fake resolver or dialer):
  1. Baseline scan, nothing listening but SSH: 1 finding, `ports.open 22/tcp` **info**; Fix this week empty; summary
     "0 findings, 1 informational note".
  2. A throwaway listener (a Python script that accepts and closes) started on 5432 as setup, scan: **new
     `ports.open 5432/tcp`, severity high**, "PostgreSQL (5432/tcp) is reachable", ranked first in Fix this week
     (`fixable.total` 1, `surface.findings` 1). `ss -ltn` on the VM showed the listener.
  3. Listener killed (`ss -ltn` showed only 22 afterwards), scan: **resolved 1, open 1**; the finding left the fix list and
     appeared under Resolved with `resolvedAt`; an independent connect from this host got `Connection refused` on 5432 and
     succeeded on 22.
  4. The signed evidence export of that database (`defendsec-verify`): audit chain intact (9 entries), "3 scans: 3 attested",
     "2 findings: 2 with open and closed dates recomputed from attested scans and matched", exit 0. The 5432 finding's
     interval is `06:34:23Z` to `06:35:39Z`, exactly the two scans. The same bundle with that closed date moved by an hour:
     **exit 1**, "the bundle claims … to 07:35:39Z, the attested scans give … to 06:35:39Z".
  Only the TCP port check was exercised on a real host (the VM has no domain); DNS, email and TLS checks stay verified by
  fixtures and the 7a real run. The listener was killed and its script deleted afterwards; `ss -ltn` on the VM shows only the original listeners (53 on loopback, 22).
- **Evidence export through `defendsec-verify`.** The control test's bundle (`DEFENDSEC_TEST_BUNDLE_OUT=…`, never set in
  CI) was run through the built binary. On the shared test database the output was: `ok surface scans 166 scans: 2 attested …,
  164 unattested …`, `ok surface findings 258 findings: 6 with open and closed dates recomputed from attested scans and
  matched, 252 unattested …`, "VERIFIED — every check passed." plus the note that 164 scans carry no chained entry (they
  were stored before this slice, or their ledger entries were cleared by other tests). Then three edits to the JSON, each run
  again: an observation of an attested scan edited, **exit 1** ("scan 165 does not match its chained digest"); a finding's
  closed date moved to 2099, **exit 1** ("the bundle claims … to 2099-01-01T00:00:00Z, the attested scans give …"); the
  asset's scans removed from the bundle, **exit 1** ("scan 165 is recorded in the chain but missing from the bundle").

### Not verified

- **No real domain was scanned in this slice** and the scanner is unchanged, so the 7a real run is not repeated. The lab VM
  port check from 7a is done (see Real runs); only VM 120 was used, VM 121 (Rocky) was not scanned.
- **The ranking rule is a judgement, not a measurement.** Critical and high surface findings above every non-KEV
  vulnerability (so a non-KEV CVE with EPSS 0.9 ranks below an exposed RDP port) and the CVSS-equivalents (medium 5.0, low
  2.0) were chosen to match the examples in the card and the principle of slice 5; nobody has compared them with a real
  client's list. They are in one place per language and easy to change.
- **Screenshots are seeded data.** The seeded scans have no chained entry, so an evidence export of that database would list
  them as unattested. The surface trend in the screenshot is synthetic.
- **Attestation starts with this slice.** Scans stored by 7a (and any earlier real run) are exported and named unattested; the
  dates of a finding on an asset with such a scan are not proven. Findings reopened before this slice lost their closed days.
- **Evidence size at scale** is unmeasured: observations are never pruned, so the section grows with every scan (the demo-scale
  test bundle with 166 scans is 0.6 MB). The digest is defined by the code in `internal/evidence/surface.go` (length-prefixed
  fields, JSON re-encoded by Go's `encoding/json`); there is no independent implementation of the verifier.
- **Surface observations are still never pruned.** Not built on purpose: deleting an attested scan's observations makes
  the scan fail its digest, so retention needs a design that archives or folds scans (see SURFACE.md).
- **Surface findings and `acknowledged`.** The console's acknowledge action exists for host findings only; a surface row has
  none.
- **Hotspots.** `internal/storepg/exposure.go` (list SQL, summary, trend), `lib/exposure-model.ts` (ranking, types) and
  `components/fix-this-week.tsx` were all edited, and slice 8 (Datto RMM) and slice 12 (M365 identity findings) will want rows in
  the same list; a generic "finding source" would be a cleaner seam than a third `UNION ALL` member.

## Feature × platform × evidence matrix — additions from slice 7b

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Surface findings in the ranked list (`internal/exposure`, SQL, `compareRank`) | any | Go + npm tests, 12 mutation checks | see handoff | seeded data in a browser; not a real client |
| Surface summary card, trend series | linux, Postgres 16 | storepg + control integration, npm | see handoff | seeded data in a browser |
| Surface drawer with raw observation | linux, Postgres 16 | storepg + control integration | see handoff | seeded data in a browser |
| Reopened finding keeps its closed gap (migration 025) | linux, Postgres 16 | integration test | see handoff | not observed on a real domain |
| Scan digest chained in the audit log; surface section verified by `defendsec-verify` | linux, Postgres 16 | evidence unit tests (10) + storepg/control integration | see handoff | exported by a real apid handler (fake resolver); verifier binary run on it, intact and three tampered ways |

## Slice 10 — application end-of-life, Windows edition-aware Supported OS (migration 026)

Branch `scout/10-app-eol-r2` from `b910939` (main after slice 5; the first push, `scout/10-app-eol` at `12af94b`, is abandoned: its history held two credential-shaped example URLs that TruffleHog flags, and pushed history is not rewritten). Design in [EOL.md](EOL.md). Postgres: PG 16 on titan CT 119 for the integration tests, the user-space PG 16.15 (`slice10`, a clone of `slice5real` that already held the real feeds) for the real runs.

### What changed

- **Feed** `endoflife` (endoflife.date API v1 `/products/full`): same pipeline as the other feeds (snapshot, SHA-256, status row, shrink guard, signed bundle). Keeps the 15 application products the mapping table can produce plus `windows` and `windows-server`, in `eol_releases`. An unchanged document is reloaded when the stored calendar lacks a product this build keeps.
- **Origin** on every package: dpkg from `apt-cache policy` (the apt `Origin:` of the repository carrying the *installed* version, repository address with credentials removed), rpm from `Vendor`/`Packager`. Proto `SoftwareItem.origin` (5) and `origin_repo` (6), optional; an old agent keeps working and its packages are "not assessed".
- **Rule**: origin decides. Distribution packages are never judged; third-party and unmanaged software is judged against the upstream calendar; unknown origin is not assessed.
- **Findings** kind `eol` (`EOL:<product>:<cycle>`), severity `high` past security support and `low` past active support, in the fix bucket, ranked at the level of a high vulnerability (security-EOL in the urgent band after KEV, EOAS with the low CVSS-only ones; see EXPOSURE.md). Controls CIS v8 2.2 and NIST SI-2 through the new signal `software.supported`.
- **Windows Supported OS** driven by the calendar by edition and build, replacing `WINDOWS_MIN_BUILD = 20348`. Agent reports `EditionID` (`HeartbeatRequest.os_edition` = 8, `devices.os_edition`). `GET /v1/lifecycle/os`. `DEFENDSEC_SUPPORTED_OS=windows=<build>` still overrides.

### Exit measurement (real hosts, 2026-10-24, matcher `--as-of 2026-10-24`, scratch DB `slice10` with all feeds loaded)

Lab VMs 120 (Ubuntu 22.04) and 121 (Rocky 9.8), the fully patched cloud images, inventories collected by the slice's static agent (`defendsec-agentd -print-inventory`, read-only). Binaries: `defendsec-feeds` built from `origin/main` (`b910939`) and from this branch, same database, same inventories.

| Inventory | Binary | fixable | awaiting_vendor | no_fix | informational | eol |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Ubuntu 22.04, old (no origin) | main | 0 | 0 | 0 | 0 | n/a |
| Ubuntu 22.04, old (no origin) | branch | 0 | 0 | 0 | 0 | **0** |
| Ubuntu 22.04, with origin | branch | 0 | 0 | 0 | 0 | **0** |
| Rocky 9.8, old (no origin) | main | 0 | 8 | 0 | 0 | n/a |
| Rocky 9.8, old (no origin) | branch | 0 | 8 | 0 | 0 | **0** |
| Rocky 9.8, with origin | branch | 0 | 8 | 0 | 0 | **0** |

- **(a)** 0 app-EOL findings on both patched lab hosts. On Ubuntu with origin: `app eol: 5 mapped to a product: 5 the distribution's own (not judged), 0 origin unknown` (python3.10 and its libraries are upstream-EOL and Canonical-supported). Origins read on the real hosts: Ubuntu 596 of 597 packages `Ubuntu` (1 with none), Rocky 422 of 422 `Rocky Enterprise Software Foundation`.
- **(c)** The finding set (advisory, CVE, package, kind) is identical between main's binary and the branch's on all four inventories: no change in vulnerability counts (Rocky keeps its 8 `awaiting_vendor`, Ubuntu 0).
- **(b)** VM 120 made client-like: `add-apt-repository ppa:ondrej/php` (Sury's PHP repository is a PPA on Ubuntu; `packages.sury.org` is Debian-only), `apt-get install php8.0-cli` (installed `1:8.0.30-25+ubuntu22.04.1+deb.sury.org+1`, `php8.0 --version` = `PHP 8.0.30`), inventory collected: 5 packages with origin `LP-PPA-ondrej-php`. Matcher output:

```
app eol:    9 mapped to a product: 5 the distribution's own (not judged), 0 origin unknown (not assessed), 0 no release data (not assessed), 0 supported
result:     0 fixable, 0 awaiting_vendor, 0 no_fix, 0 informational, 1 eol
SEVERITY  CVE          PACKAGE     INSTALLED                                 FIXED IN        KIND  FEED       NOTE
high      EOL:php:8.0  php8.0-cli  1:8.0.30-25+ubuntu22.04.1+deb.sury.org+1  upgrade to 8.4  eol   endoflife  PHP 8.0 reached end of life on 2023-11-26; origin LP-PPA-ondrej-php
```

  Exactly one finding (four PHP packages, one finding), naming PHP 8.0 and 2023-11-26, with the Sury PPA as origin. The vulnerability counts did not change.
- **Cleanup**: php8.0 packages, the PPA, its key and `/tmp/agentd` removed from VM 120 (`dpkg -l | grep -c php` = 0, `/etc/apt/sources.list.d` empty, no `ondrej` in `apt-cache policy`); `/tmp/agentd` removed from VM 121, which was otherwise untouched.

### Commands and results (this box)

| Command | Result |
| --- | --- |
| `go build ./...`, `go vet ./...`, `GOOS=windows go vet` (cmd, posture, hostinv) | green, no output |
| `TMPDIR=/tmp TEST_DATABASE_URL=… go test -p 1 -count=1 -v ./...` | exit 0: 1183 pass (subtests included), 0 fail, 5 skip (BPF, pwsh, netns: unrelated) |
| `npm test` | 144 / 144 (was 121 on main) |
| `npm run lint`, `npx tsc --noEmit`, `npm run build` | green |
| `make proto` | only `agent.pb.go` changes, as expected for the two new fields |
| Mutation: `today <= eolFrom` in `windowsSupport` | 1 test fails (the one that crosses the real EOL date) |
| Mutation: server editions not narrowed to server cycles | 6 tests fail |

### Windows check (the defect found in slice 5's screenshots)

Unit cases in `lib/os-lifecycle.test.ts` and `lib/supported-os.test.ts`, on a real calendar (the `windows` and `windows-server` products fetched 2026-10-24, 69 releases, in `lib/testdata/os-calendar.json`):

| Build | Edition | Judged 2026-10-24 | Flips on |
| --- | --- | --- | --- |
| 14393 | Server 2016 (`ServerStandard`) | **supported** | 2027-01-12 |
| 17763 | Server 2019 (`ServerStandard`) | **supported** | 2029-01-09 |
| 14393 | Windows 10 LTSB 2016 (`EnterpriseS`) | unsupported | 2026-10-13 |
| 17763 | Windows 10 LTSC 2019 (`EnterpriseS`) | supported | |
| 17763 | Windows 10 1809 Enterprise | unsupported | |
| 19044 | Windows 10 LTSC 2021 / IoT LTSC | supported | 2027-01-12 |
| 19044 | Windows 10 21H2 Pro | unsupported | |
| 19045 | Windows 10 22H2 | **unsupported** (consumer ESU not counted) | 2025-10-14 |
| 22631, 26100 | 11 Pro vs Enterprise vs LTSC | edition decides | |
| 17763 / 14393 | edition not reported | **unknown** | |

The test "the verdict changes on the real end-of-life date" checks the day before and the day of for Server 2016, Server 2019, LTSB 2016, 22H2 and LTSC 2021.

### Not verified

- **No Windows host.** `EditionID`/`ProductType` are read by the PowerShell script, which has not run on a Windows machine (the Go parser is tested on JSON, the script text is only checked to ask for the values). The Windows software-name mappings are unit-tested on names only.
- **The console was rendered in a browser (round 2) only on synthetic data** (`scripts/seed-exposure-demo.sql`): the EOL rows, the host-page note and the Windows reason line are seen on invented hosts, not on a real fleet or a real Windows host.
- **No end-to-end run through a real apid and agent** for an `eol` finding: the client-like result is the matcher CLI on a real inventory; the storage, exposure list, drawer and resolution are covered by integration tests on a real Postgres with synthetic inventories.
- **Origin for dnf `from_repo`** is not read (rpm vendor and packager only). Software outside the package manager on Linux is not seen.
- Linux distributions still use the floors in `lib/supported-os.ts`, not the calendar.
- Sury's repository was tested as Ondrej's PPA on Ubuntu 22.04; `packages.sury.org` on Debian 11 (the motivating case) was not run, only a hand-written `apt-cache policy` fixture of it.

### Round 2 (review changes, 2026-10-24)

Branch head after merging `origin/main` (`7bc5b19`, slice 7b) into `scout/10-app-eol-r2`; the merge is a merge commit, no history rewritten. What changed:

- **Migration renumbered** `025_app_eol.sql` → `026_app_eol.sql` (main took 025 for `025_surface_history.sql`); `migrations_test.go` pins both. **In-place upgrade, real data:** scratch DB cloned from `slice5real` (main's 024 schema, 1,455 findings, 70,913 advisories); the branch's apid started twice against it (it applied 025 and 026 before failing to bind its port, already held by the demo apid, so no migration error either time): `eol_releases` and `surface_finding_intervals` exist afterwards, row counts unchanged (1,455 / 70,913).
- **Ranking, decided by the CEO** (card: "below KEV, next to high vulnerabilities"): security-EOL (`eol`, severity high) is in the urgent band after KEV with the critical/high surface findings, CVSS-equivalent 8.0; EOAS (`eoas`, low) is in the rest band, CVSS-equivalent 2.0, below every vulnerability with an EPSS score and below security-EOL. Stage decides, not the severity label. Go (`internal/exposure`: `EOLScore`, `Band`), the SQL `ORDER BY` (`k1`, `k4`) and TS (`rankBand`, `EOL_SCORE`) state it once; `docs/EXPOSURE.md` and `docs/EOL.md` describe the merged rule.
- **Tests:** `TestEOLJoinsTheOrderNextToHighVulnerabilities`, `TestSecurityEOLRanksAboveActiveSupportEOLWhateverTheLabels`, `TestEOLIgnoresVulnerabilityFieldsAndKEVStillWins`, `TestEOLScoreRanksOnlyKnownStages` (Go), `TestEOLRanksNextToHighVulnerabilities` (Postgres: SQL order equals `exposure.Compare` over a list with KEV, EPSS-scored, CVSS-only, unscored and two eol rows, and keyset paging at page sizes 1, 2, 3, 200), three TS tests with the same cases. Seven mutations each fail a test: security-EOL in the rest band (Go: 2 fail; TS: 2 fail), security-EOL not in the urgent band in SQL (1 fail), EOAS scored 9.0 in Go (2 fail) and in TS (2 fail), EOAS scored 8.0 in SQL (1 fail), EOAS in the urgent band in SQL (1 fail). (An earlier version of the SQL test did not catch EOAS scored 8.0; a CVSS-only 5.0 vulnerability was added to it.)
- **Console, rendered** in a browser against a synthetic database (`scripts/seed-exposure-demo.sql`, invented hosts, `example.com`/RFC 5737 only; PHP 8.0 and Node 16 past security support, PHP 8.2 past active support; Windows Server 2016 (14393, `ServerStandard`), Windows 10 LTSB 2016 (14393, `EnterpriseS`) and Windows 10 22H2 (19045) with the four real calendar rows). The list order seen in the browser: three KEV, SMB (critical surface), Node.js 16, PHP 8.0, RDP and an expiring certificate (high surface), then EPSS-scored CVEs, CVSS-only ones, DMARC p=none, PHP 8.2 (past active support), two low surface findings, an unscored CVE. Screenshots: `docs/screenshots/eol-fleet-fix-this-week.png`, `eol-exposure-ranked-list.png`, `eol-drawer-security-eol.png`, `eol-drawer-active-support.png`, `eol-host-linux-third-party.png`, `eol-host-windows-ltsb-unsupported.png` ("security updates ended 2026-10-13", Failing), `eol-host-windows-server-supported.png` ("security updates until 2027-01-12", Passing). Two small finds while looking: the drawer and the host-page row showed the raw id `EOL:php:8.0` as the title (now "PHP 8.0"), and main's Fix this week description, taken as is in the merge, would have said nothing of end-of-life releases (now "9 vulnerabilities with a fix to install and 3 end-of-life releases to upgrade, across 16 hosts and 6 external surface findings").
- **Exit measurements re-run with the merged matcher** (`defendsec-feeds match --as-of 2026-10-24`, DB `slice10`, the inventories collected from VMs 120 and 121 in round 1; the VMs were not touched in round 2): Ubuntu 22.04 old and with origin: 0 findings, 0 eol (`EOLMapped 5`, 5 origin unknown on the old inventory, 5 the distribution's own with origin); Rocky 9.8: 0 fixable, 8 awaiting_vendor, 0 eol; the finding sets are identical to the matcher built from `b910939` (main before slice 7b); the PHP 8.0 PPA inventory: exactly 1 eol finding, `EOL:php:8.0 php8.0-cli 1:8.0.30-25+ubuntu22.04.1+deb.sury.org+1`, "PHP 8.0 reached end of life on 2023-11-26 ... (LP-PPA-ondrej-php)". nitpick re-collected the inventories from the live VMs in review round 1 with the same result.
- **Branch CI on the merged tree:** https://github.com/WASP512/defendsec/actions/runs/40074768825, head `4dd58b6`, 6/6 jobs success (go, postgres-integration, node, isolation, provisioning, secrets-scan).
- **Tests, merged tree:** `go test -p 1 -count=1 -v ./...` with `TMPDIR=/tmp` and Postgres: exit 0, 1,215 pass, 0 fail, 5 skip, 56 packages ok; `npm test` 168/168; `tsc`, `eslint` clean.

## Feature × platform × evidence matrix — additions from slice 10

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| endoflife feed (snapshot, bundle, age, shrink guard) | Postgres 16 | runner integration tests incl. signed bundle and reload | run 40072034774 | real sync of endoflife.date, 370 releases, 17 products |
| Package origin | dpkg (Ubuntu 22.04) | `apt-cache policy` real output fixtures, Sury hand fixture | run 40072034774 | read on VM 120 (597 pkgs) |
| Package origin | rpm (Rocky 9.8) | query parser tests | run 40072034774 | read on VM 121 (422 pkgs) |
| `eol` findings, origin decides | dpkg | matcher + storepg integration | run 40072034774 | 0 on patched Ubuntu/Rocky; 1 on a PHP 8.0 PPA host |
| Windows Supported OS by edition and build | windows | table of build/edition pairs, date flips, mutations | run 40072034774 | none; reason lines rendered on synthetic hosts |
| EOL ranking next to high vulnerabilities (Go = SQL = TS) | linux, Postgres 16 | Go, TS and Postgres tests, 7 mutations | run 40074768825 (6/6 jobs, on 4dd58b6, the merged tree) | rendered on synthetic data |

## Slice 8 — Datto RMM collector and Microsoft update feed (migration 027)

- Date: 2026-10-24 (MDT). Host: `hermesagent`, go1.26.10 (toolchain download), node 22, Postgres 16 on titan CT 119 (own database).
- Branch `lookout/8-datto-rmm`. What is in it: `internal/rmm/datto` (read-only API client), `internal/rmm` (collector), `internal/feeds/msrc`
  (KB to CVE feed), `internal/vuln/windows.go` (missing-KB matcher), `internal/secret/file.go` (credentials from files), migration 027,
  `internal/control/rmm.go` and the console pages. Design and the vendor facts it rests on: [DATTO-RMM.md](DATTO-RMM.md).

### Commands run

| # | Command | Result |
| --- | --- | --- |
| 1 | `go build ./...`, `go vet ./...`, `GOOS=windows go vet ./internal/rmm/... ./internal/vuln/...` | exit 0, no output |
| 2 | `unset TEST_DATABASE_URL; TMPDIR=/tmp go test -count=1 ./...` | 60 packages `ok`, 0 failed (the database tests skip) |
| 3 | `TEST_DATABASE_URL=… go test -p 1 -count=1 -v <pkg>` (the CI integration packages plus `./internal/rmm/...`), tests and subtests counted by `--- PASS` | rmm 30, rmm/datto 18, feeds/msrc 7, feeds/runner 27, vuln 56, secret 2, control 167, storepg 125, db/migrations 5; **0 fail**. `internal/rmm` also reports 1 skip: a local demo seeder kept out of git (`.git/info/exclude`), absent in CI |
| 4 | `npx tsc --noEmit`, `npm run lint`, `npm test`, `npm run build` | tsc and lint clean; **183 pass, 0 fail, 0 skipped**; `next build` green |

`TestEveryIntegrationPackageRunsInCI` failed at first (`internal/rmm` has database tests CI did not run); `internal/rmm/...` is now in the
`postgres-integration` job's command in `.github/workflows/ci.yml`, and the test passes.

### What each claim rests on

- **Client** (`internal/rmm/datto`, fixtures in `internal/rmm/dattotest/fixtures`, a fake Datto server): token flow and caching, refresh after expiry,
  401 and 400 from the token endpoint as *auth* (credentials never echoed), 403 never retried, 429 waits `Retry-After` and gives up, 5xx retried then
  failed, pagination of sites, devices and software (and a `nextPageUrl` on another host is refused, redirects are not followed), UIDs validated
  before they reach a URL, request pacing, cancelled context, and `TestClientHasNoWriteCalls` (no method but GET plus the token request).
  **Fixtures only; no call has been made to a real Datto account.**
- **Collector** (`internal/rmm`, Postgres): read of a site maps missing KBs to CVEs; **a missing KB that fixes a KEV-listed CVE ranks first in Fix
  this week** (`TestMissingKBThatFixesKEVRanksFirstInFixThisWeek`); an installed KB closes its findings as fixed; a KB no longer listed (and not
  installed) is no longer affected; **a stale audit keeps its findings and is never clean**; a never-audited device is *no data*; coverage ages out
  between reads without asking RMM; wrong credentials leave existing evidence alone; three 403s in a row stop the run; a 429 stops it with a
  partial result; an unreadable device keeps its findings and the run is partial; a software failure does not stop the patch match; **no Microsoft
  feed is `no_feed`, not clean**; a device that left the site, or a site change, retires rows; **an agent and RMM reporting the same machine are one
  host** (serial first, then host name, ambiguity is no match); a new KEV listing re-ranks stored findings without calling RMM.
- **Microsoft feed** (`internal/feeds/msrc`, `internal/feeds/runner`): reduction of a CVRF month, month selection, download of only the revised
  months, a failed month fails the whole fetch, one range per (CVE, KB), KEV enrichment, opt-in configuration.
- **API and audit** (`internal/control/rmm_test.go`, Postgres): auth per route, 403 for a viewer, site must be in the live list, bounds on the stale
  threshold, waited read, 409 while another read runs, device list and detail, and that choosing a site and a read are written to the ledger.

### Real runs

- **The real Microsoft feed (the public API, no key).** `defendsec-feeds` with `msrc` enabled into a scratch database loaded **27,985 ranges for
  3,778 advisories (26 of them KEV-listed) across 543 distinct KBs** from the 12 most recent monthly documents, `feed_snapshots` row
  `msrc record_count 27985`. This is the only part of the slice that touched a real external service.
- **Console and API in a browser against a fixture Datto server.** A real `defendsec-apid` and the production console build on a scratch database
  (the real Microsoft feed above, two fixture devices: a Windows 10 22H2 PC audited 8 hours ago with three listed updates, and a Server 2019 whose
  audit is 32 days old; the two KB numbers were replaced by the two real KBs with the most KEV CVEs so the ranking is real). Result: Fix this week
  lists 30 vulnerabilities from that host led by KEV rows with "exploited in the wild since …"; the RMM page shows "2 Windows devices", "1 device not
  assessed: audit older than 7 days, missing evidence, not a clean result", "Third-party application vulnerabilities are not assessed from RMM data"
  and the stale server as *Evidence too old* with 0 findings and no clean mark; Windows 10 22H2 carries "unsupported OS"; every fact on the device
  page names its source. Screenshots: `docs/screenshots/rmm-*.png`. A signed evidence export of that database verified (`defendsec-verify`: audit chain
  intact, "VERIFIED — every check passed"). **Seeded data, not a client.**
- **Not run: a read of a real Datto RMM site.** It needs the read-only API user Mason creates himself; the setup is in DATTO-RMM.md and the card is
  waiting on it.

### Not verified

- **Which `patchStatus` values return update lists on a real account.** `NoData` and `NoPolicy` devices are treated as *not assessed* when their
  lists are empty (and `NoData` always); that real accounts return empty lists for them, and complete lists for `FullyPatched`, `ApprovedPending`,
  `RebootRequired` and `InstallError`, is unobserved.
- **Any real Datto RMM response.** Field names, page sizes, whether a one-site security level can list sites, how many requests a real device costs
  and whether `NOT_APPROVED` lists everything Windows offers are all unobserved. Fixtures follow Datto's published OpenAPI document.
- **KB to CVE is only as good as the feed's window.** An update older than 12 months, or a KB whose Remediation names another product, is not mapped
  (and counted, not guessed). Whether the CVE list RMM's KBs give matches what Microsoft Update would install on a given build was not checked.
- **Third-party Windows software has no vulnerability matching** (by design, in this slice), and **slice 10's application end-of-life mapping is not
  applied to RMM software**, although slice 10 has merged: RMM gives a display name and a version with no publisher or origin, and the mapping keys
  on package names and repository origin, so applying it would be a guess. Follow-up once a real site shows what the names look like.
- **Evidence export:** RMM findings are in the same table as agent findings and flow into the exposure list and trend; the signed bundle (audit
  chain, surface, compliance) does not carry host findings today for either source. Slice 7c is where that changes.
- **Not run:** mutation checks, a load test with a large site, a Windows agent next to an RMM device on a real machine (the dedupe is tested with
  fixtures), the Windows agent's own inventory against RMM's (no comparison made).
- **Hosts table shows RMM devices as "Offline"** an hour after a read although RMM said online at read time (the online badge is derived from last seen,
  as for agents).

### Round 2 (review changes, 2026-10-24)

- **Merged `origin/main` (slice 10, 44cbbdf).** Migration renumbered `026_rmm.sql` to `027_rmm.sql` (main took 026 for `026_app_eol.sql`);
  `migrations_test.go` pins both files and the `eol_releases` relation next to the RMM ones. Conflicts were in `migrations_test.go`, `VERIFIED.md`,
  `runner/config.go` (both feed kinds kept), `devices.go` (the agent device load keeps `os_edition` *and* `source = 'agent'`), `findings.go`
  (the host-state write keeps main's EOL columns) and `supported-os.ts` (below).
- **One Windows end-of-support source: main's.** My own build tables (`WINDOWS_CLIENT_EOS`, `WINDOWS_SERVER_EOS`, `windowsEndOfSupport`) are gone;
  `lib/supported-os.ts` and its test are main's unchanged, and `unsupportedRmm` / `osSupportLine` in `lib/rmm-model.ts` ask `supportedOs` /
  `windowsSupportOf` (`lib/os-lifecycle.ts`, the endoflife.date calendar, edition read from the RMM caption since RMM gives no EditionID). Proven in
  `lib/rmm-model.test.ts` on main's real calendar fixture: Windows 10 Pro 22H2 is unsupported, Windows 10 Enterprise LTSC 2021 and Server 2019 are
  supported, Server 2012 R2 is unsupported, an empty build is unknown, and **with no calendar loaded a Windows device is unknown, never unsupported**.
  The RMM pages warm the calendar like the agent pages do. In a browser on the merged head (below), Windows 10 22H2 carries *unsupported* and the
  Fleet "Also check" list names it.
- **A device RMM has no patch evidence for is not assessed, never covered** (`internal/rmm/patchstatus_test.go`, Postgres): `NoData` (even with a list),
  `NoPolicy` with empty lists, and no patch status with empty lists are stored `no_data` with a reason that says it is not a clean result, counted
  under *not assessed* in the RMM summary and absent from the exposure summary's assessed hosts; `NoPolicy` or a missing status **with a listed update**,
  and `FullyPatched` with empty lists, stay `covered`; a device that goes from covered to `NoData` keeps its open findings. Mutations of the guard
  (each `case` removed, `NoPolicy` and missing status made to ignore the lists) are killed by those tests (5 of 5, plus 1 equivalent mutant that only
  changes an internal state label no code reads).
- **Two KBs fixing one CVE name the host once** (`TestTwoMissingKBsForOneCVENameTheHostOnce`), and `docs/screenshots/rmm-*.png` were retaken on the
  merged head (real MSRC feed and endoflife calendar in a scratch database, fixture Datto server, production console build, fixture hosts only):
  the Fix this week rows read "1 host: DEMO-PC-01".
- **One ledger entry per site choice:** the store writes `rmm_site_selected` inside the settings transaction; the duplicate `rmm_site_select` from the
  handler is removed and a test asserts it is gone. Every read is recorded `rmm_sync_recorded`; a manual request also records who asked (`rmm_sync`);
  a scheduled read has no `rmm_sync` entry. Stated in DATTO-RMM.md.
- **Re-run on a database that already had the old migration:** scratch database `lookout_rmm8` (schema from the pre-merge head, with RMM data) was opened by the
  merged `defendsec-apid`: it started, applied `026_app_eol` and `027_rmm` without error, and a fixture read plus the endoflife sync worked on it. That is
  a re-run of idempotent migrations on existing data, **not** an upgrade from main's 026 schema (that proof is the reviewer's).

## Feature × platform × evidence matrix — additions from slice 8

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| Datto RMM client (auth, paging, 401/403/429, read-only) | any | 18 tests against a fake Datto server | see handoff | **not run** against a real account |
| RMM collector: OS, software, patch summary, per-KB list; `NoData`/`NoPolicy` are not assessed | Windows devices via RMM | 30 integration tests | see handoff | **not run** against a real account |
| Missing KB to CVE to KEV ranking in Fix this week | Windows via RMM | matcher 6 + collector integration | see handoff | real Microsoft feed (27,985 ranges), fixture devices, in a browser |
| Stale audit is missing evidence, never clean | Windows via RMM | integration tests | see handoff | fixture device with a 32-day-old audit, in a browser |
| Agent and RMM dedupe (serial, host name) | Windows | unit + integration | see handoff | not run on a real machine |
| Microsoft Security Update Guide feed (`msrc`) | any | 7 + 2 runner tests | see handoff | **real API**, 12 months |
| Credentials from files (`internal/secret`) | linux | 2 tests | see handoff | not run with a real key |

## Slice 11 — repository health: expired keys, stale indexes, unreliable pending updates (migration 028)

Branch `scout/11-repo-health-r3`, one commit on `335b07a` (main after slices 10 and 8; slice 8 took migration 027, this slice's is 028). The first two pushes, `scout/11-repo-health` (`320b75e`: its history names a client in code comments) and `scout/11-repo-health-r2` (`4ee057f`: branch CI's TruffleHog step flagged credential-shaped example URLs in tests), are abandoned, because pushed history is not rewritten. The measurements below were taken on that tree; the one change since is cosmetic (comments, and three test URLs now assembled at run time), and the two packages touched (`internal/repohealth`, `internal/hostinv`) were re-run on this tree, the rest by branch CI. Design in [REPO_HEALTH.md](REPO_HEALTH.md). Postgres: PG 16 on titan CT 119 for the integration tests; the user-space PG 16.15 (`slice11b`, a clone of `slice10` that already held the real feeds, so the merged migrations 027 and 028 ran in place on a database that held 026) for the lab runs.

### What was built

- **Agent** (`internal/hostinv/repohealth.go`, read-only): per enabled apt source, `gpgv` on the Release file apt already holds, against the keyring that source uses; Release `Date:`/`Valid-Until:`; `update-success-stamp`. Per enabled dnf/yum/zypper repository: the `gpgkey` files and imported `gpg-pubkey` keys (expiry, revocation) and the age of the cached `repomd.xml`. Nothing refreshes, nothing writes. The keyring reaches `gpgv` as an in-memory file (`memfd`; `gpgv` reads nothing from a pipe).
- **Server** (`internal/repohealth`, `internal/vuln`): judges the report. Findings kind `repo_health`, basis `host`, advisory `REPO:<12 hex>`; key problems, `no_index` on apt and `signature_bad`/`unsigned`/`key_revoked` are **high**, stale and expired indexes are **medium**; controls NIST SI-2 and CM-6, CIS v8 7.3 and 7.4. Threshold `DEFENDSEC_REPO_STALE_DAYS` (default 7). Stored with the verdict (`devices.repo_health`).
- **Ranking:** high in the urgent band at 8.0, medium in the rest band at 5.0; Go, SQL and TS state it once each.
- **Console:** Fix this week rows and description; host page notice, "0 pending — unreliable, not zero" and a Package repositories table; Patches page, dashboard card, hosts list and the "No pending patches" policy (`unknown`, never `pass`).
- **Added scope from slice 10's review:** the agent's `apt-cache policy` no longer writes `/var/cache/apt/pkgcache.bin` (see exit (c)).

### Exit measurements (real hosts: VM 120 Ubuntu 22.04, VM 121 Rocky 9.8; 2026-10-24)

The agent was built from the merged head (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build`), copied to the VM, enrolled against an apid on this server (`defendsec-apid` from the same head, DB `slice11b`), and run as root as the real daemon (`-heartbeat 10s`, 30 s per step). The test repository is a signed apt repository (`file:` source) whose key was created with `gpg --faked-system-time 20260101T000000 ... 1d`, so it expired on 2026-01-02, and whose Release was signed half-way through its life.

**(a) The expired-key condition, step by step** (`e11/lab_sequence.sh`, output kept):

```text
===== 1. clean host (test repository not present)
sources.list.d entries: 0
time=2026-10-24T08:52:55.011Z level=INFO msg="inventory ok" software=597 fim=6 patches=0
-- findings (kind repo_health):                              <- none
-- device verdict:
reliable	4	[]
defendsec-ubuntu2204 0 reliable
===== 2. expired-key condition: enabled repository signed by an expired key
Err:1 file:/tmp/ds-lab1/repo dstest InRelease
  The following signatures were invalid: EXPKEYSIG 13EDAB264F59ECF5 DefendSec Test Repo (expired lab key) <lab@example.invalid>
W: GPG error: file:/tmp/ds-lab1/repo dstest InRelease: The following signatures were invalid: EXPKEYSIG 13EDAB264F59ECF5 ...
E: The repository 'file:/tmp/ds-lab1/repo dstest InRelease' is not signed.
apt-get update exit=100
-rw-r--r-- 1 root root 0 2026-10-24 08:53:23.701533459 +0000 /var/lib/apt/periodic/update-success-stamp
-- findings (kind repo_health):
high	REPO:0d0827f4a9ed	key_expired		file:/tmp/ds-lab1/repo dstest
-- device verdict:
unreliable	5	[file:/tmp/ds-lab1/repo dstest: signing key 13EDAB264F59ECF5 has expired]
defendsec-ubuntu2204 0 unreliable file:/tmp/ds-lab1/repo dstest: signing key 13EDAB264F59ECF5 has expired
fixable: {"findings": 7, ... "repoHealth": {"findings": 1, "advisories": 1}}
hosts: {"total": 2, "assessed": 2, "notAssessed": 0, "patchUnreliable": 1}
===== 3. repository removed
apt-get update exit=0
-- findings (kind repo_health):
high	REPO:0d0827f4a9ed	key_expired	no_longer_affected	file:/tmp/ds-lab1/repo dstest
-- device verdict:
reliable	4	[]
fixable: {"findings": 6, ... "repoHealth": {"findings": 0, "advisories": 0}}
hosts: {"total": 2, "assessed": 2, "notAssessed": 0, "patchUnreliable": 0}
```

Exactly one `repo_health` high finding for the repository, the host's pending updates `unreliable` with the reason (the host listed 0 pending), and both go away when the repository is removed and the host re-collected. An earlier run of the same sequence with the pre-merge build gave the same result and also rendered the pages in the console (`next dev`, logged in with the admin token, page text read with curl): the Fix this week row ("Updates from this repository have stopped: signing key expired ... install the vendor's current signing key (signed-by keyring), then apt-get update"), the host page notice "Pending updates are unreliable (missing evidence)" with "0 pending — unreliable, not zero", the Package repositories table (expired key, `Release dated 2026-01-01`), the Patches page banner, the hosts list "updates unreliable", and, after removal, "No pending updates reported." (the console reads apid's presence file, which lags by up to a minute). The advisory detail carries controls `nist-800-53:SI-2`, `nist-800-53:CM-6`, `cis-v8:7.3`, `cis-v8:7.4` (and their CMMC, 800-171, CJIS mappings).

**A fact worth recording:** `apt-get update` exits **100** with an expired-key repository and **still touches `update-success-stamp`**. A fresh stamp therefore does not clear a repository; each one is verified on its own (REPO_HEALTH.md says so).

**(b) Both patched lab hosts give no `repo_health` finding** (this head's agent and matcher, `e11/exit_patched.sh`):

```text
== ubuntu-2204: repos: 4 checked, 0 with a problem; pending updates: reliable
   result: 0 fixable, 0 awaiting_vendor, 0 no_fix, 0 informational, 0 eol, 0 repo_health
== rocky-9:     repos: 3 checked, 0 with a problem; pending updates: reliable
   result: 0 fixable, 8 awaiting_vendor, 0 no_fix, 0 informational, 0 eol, 0 repo_health
```

Ubuntu: the four stock sources, key `871920D1991BC93C`, `Release` dated 2022-04-21 (the base pocket, not stale because the host refreshed that day), 2026-10-23 and 2026-10-24. Rocky (the RPM path on a real host): `baseos`, `appstream`, `extras`, key `350d275d`, cached `repomd.xml` 5 hours old. The 8 awaiting_vendor are the unchanged slice 4c kernel rows.

**(c) The agent no longer writes apt's cache** (`e11/vm_cachecheck.sh` on VM 120; old agent = slice 10's, new = this branch; "stale" = `touch -d 2026-10-01` on both `.bin` files, "missing" = deleted; the cache was rebuilt with `apt-cache gencaches` before each case):

```text
[old agent, cache stale]   before: pkgcache.bin mtime=2026-10-01 00:00:00  after: mtime=2026-10-24 08:45:02   (rewritten)
[old agent, cache missing] before: MISSING                                  after: pkgcache.bin mtime=2026-10-24 08:45:06 (recreated)
[new agent, cache stale]   before: pkgcache.bin mtime=2026-10-01 00:00:00  after: mtime=2026-10-01 00:00:00   sha256 83a0abc8667fe7a1 unchanged
[new agent, cache missing] before: MISSING                                  after: MISSING
```

The same holds for `srcpkgcache.bin`. The old agent is the control: it changed the file in both cases. The two inventories are identical apart from `repoHealth` (`cmp_inv.py`: "inventories identical apart from repoHealth: True"), so origins did not change. Cost: `apt-cache policy` builds the cache in memory, about 1.6 s per call instead of 0.1 s (measured on VM 120), so the calls are batched.

**(d) `gpgv` reports an expired key as a good signature** (measured on VM 120, gpgv 2.2.27, and on this host's gpgv): exit 0, "Good signature", and `KEYEXPIRED` and `EXPKEYSIG 13EDAB264F59ECF5` in `--status-fd` output. The collector parses the status lines. The Go test `TestRealGPGVReportsExpiredAndMissingKeys` makes its own expired key with `gpg --faked-system-time` and runs the real `gpgv` through the in-memory keyring path: expired key, wrong keyring (`NO_PUBKEY`), a file keyring, and a tampered file (`BADSIG`).

### Tests

- `go build ./...`, `go vet ./...`, `GOOS=windows go vet ./...`, `gofmt -l`: clean.
- `TMPDIR=/tmp go test -p 1 -count=1 -v ./...` with Postgres (titan CT 119) on the merged head: exit 0, **1,327 pass, 0 fail, 5 skip** (Windows query scripts, isolation with real traffic and three sensor tests: the environment), 61 packages ok.
- `npm test` 195/195 (168 on main plus the new file), `eslint` and `tsc --noEmit` clean.
- New tests: `internal/repohealth` (gpgv status parsing from real captured output, apt source parsing in both syntaxes, OpenPGP expiry from real keys including a revoked one, `.repo` parsing, assessment rules); `internal/hostinv` (a fixture host tree and a fake `gpgv`: healthy, expired, no-index, trusted=yes, missing keyring, gpgv not runnable, deb822 with armored and inline keys, `file:` repositories, credentials redacted, rpm keys and metadata age, imported keys, plus the real-`gpgv` test); `internal/vuln` (findings, stats, the threshold, a missing or empty report is not "assessed", advisory id); `internal/exposure` (rank rule); `internal/storepg` (`TestRepoHealthFindingEndToEnd`: store, controls, exposure list and summary, detail, a missing report does not close the finding, fixed, reopened with the interval kept, removed; `TestRepoHealthRanksWithEverythingElse`: SQL order equals `exposure.Compare` over KEV, EPSS-scored, CVSS-only, EOL, high surface, high and medium repository rows, with keyset paging at 1, 2, 3 and 200; `TestRepoHealthReportPersistsWithItsVerdict`); `lib/patch-reliability.test.ts` (ranking, wording, the policy, "never a clean zero").
- **Mutations**, each reverted (`e11/mutations.sh`, kept outside git), each fails a test: SQL band for repository rows (1 fail), SQL score high 8.0→7.0 (1), SQL score medium 5.0→6.0 (1), Go band (1 in storepg, 2 in `internal/exposure`), fix bucket drops `repo_health` (2), TS `rankBand` (3), TS `effective` (1). The slice 10 review's survivor (the SQL security-EOL constant `-8.0`, which could become `-1.0` with every test green) now fails `TestRepoHealthRanksWithEverythingElse` (run: `-8.0` → `-1.0`, 1 fail, reverted); that test puts an EOL row, a high repository row and a high surface row at 8.0 in one list.

### Not verified

- **No real RPM host with a bad key or a stale cache.** The RPM path ran on a real Rocky 9.8 host with healthy repositories only; expired and stale rpm repositories are fixtures. `repomd.xml` signatures (`repo_gpgcheck`) are not verified, a remote `gpgkey=` URL is not fetched, and dnf `from_repo` (slice 10's "not verified" item) is **not** read: the checks here do not need per-package origin, so I did not add it. It stays a follow-up.
- **No http repository with an expired key on a real host.** The lab repository is a `file:` source (apt keeps no copy, so the index is verified in place). For an http source apt keeps the last good index and the collector verifies it with the keyring; that path ran against fixtures and the real `gpgv`, not a real http mirror.
- **zypper has not run on any host.**
- **Windows, macOS** have no repository evidence; the console shows no verdict. The Datto RMM hosts (slice 8) are not touched.
- The **DefendSec console was rendered in a browser only as page text over HTTP**; I did not look at screenshots.
- The lab VMs were returned to how I found them: the test source, keyring, agent state and binaries removed, `apt-get update` exit 0, `dstest` absent from `apt-cache policy`, `pkgcache.bin` rebuilt.

## Feature × platform × evidence matrix — additions from slice 11

| Feature | Platform | Unit | CI | Real host |
| --- | --- | --- | --- | --- |
| apt repository signature and key expiry (`gpgv` status) | Ubuntu 22.04 | real captured `gpgv` output, fake-`gpgv` fixture host, real `gpgv` with an expired key | see the card | VM 120: expired key found, healthy host clean |
| apt index staleness (`Date`, `Valid-Until`, refresh stamp) | Ubuntu 22.04 | table of dates and thresholds | see the card | healthy host clean; no stale index staged |
| dnf/zypper key expiry and metadata age | Rocky 9.8 | fixtures | see the card | VM 121: healthy, 3 repositories, no finding; no bad key staged |
| `repo_health` findings, close and reopen | Postgres 16 | matcher, storepg integration | see the card | VM 120 through apid: 1 finding, resolved on removal |
| Pending updates marked unreliable | Postgres 16, console | TS and Go tests | see the card | VM 120: `unreliable` with the reason, then `reliable` |
| Agent does not write apt's cache | Ubuntu 22.04 | — | — | VM 120: old agent rewrote it, new agent did not (stale and missing) |
| Repository rows in the ranking (Go = SQL = TS) | linux, Postgres 16 | Go, TS and Postgres tests, 7 mutations | see the card | seen through apid on VM 120 |
