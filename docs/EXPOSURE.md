# Exposure view

The console's main surface (Fleet and Exposure pages) and the API behind it
(`/v1/exposure/*`). It answers one question for a small fleet or a client: **what do we fix
this week, and is it getting better?**

Everything here is computed by `defendsec-apid` from the findings the matcher stores (see
[MATCHING.md](MATCHING.md)); the console asks for one page at a time and never receives the
fleet's findings.

## What is a finding here

The matcher stores one row per host, advisory and package family (`vuln_findings`). The
exposure view groups those rows **by advisory**: one entry per CVE (or distro advisory id),
with the hosts it affects. That is the unit a technician schedules ("patch openssl on these
eight hosts"), and the unit that is ranked.

Findings fall into two lists and one that is never counted:

| List | Contains | Counted as work this week |
| --- | --- | --- |
| **Fix this week** (`bucket=fix`) | `finding`: the host's own distribution has a fix to install | yes |
| **Watch** (`bucket=watch`) | `unfixed` (no fix published) and `awaiting_vendor` (Red Hat fixed it, Rocky/Alma has not shipped the rebuild) | no |
| not listed | `informational` (will_not_fix, ESM-only on a host without ESM) | never |

An exploited-in-the-wild (KEV) advisory in the watch list gets a **red callout** on both pages:
a patch cannot close it today, so it needs a mitigation. An `awaiting_vendor` entry reads
"Fixed by Red Hat on 2026-10-22; awaiting Rocky/Alma" (the date is the Red Hat erratum date,
stored in `vuln_findings.upstream_fixed_on`).

## Ranking

Most urgent first (`internal/exposure`, mirrored by `lib/exposure-model.ts` `compareRank`):

1. **On the CISA KEV list** before everything else. Among KEV entries, the most recently added
   first; an entry with no recorded date last.
2. **EPSS**, high to low (the probability of exploitation in the next 30 days).
3. **CVSS** base score, high to low.
4. The vendor's severity label (critical, high, medium, low, unknown).
5. The advisory id, so the order is total and a keyset cursor is stable.

A missing EPSS or CVSS score ranks after any score, including 0: unknown is not zero.

**End-of-life software** (slice 10, [EOL.md](EOL.md)) is in the fix bucket beside the patches: upgrading is the fix. It has
no EPSS or CVSS, and nothing will ever patch it, so it enters the order next to the high vulnerabilities, the way a
surface finding does (rules in `internal/exposure/rank.go`, "End-of-life findings"):

- **Past end of security support** (stage `eol`, severity `high`): the **urgent band**, right after KEV, with the critical
  and high surface findings, and before every vulnerability that is not on KEV, whatever its EPSS. Its
  CVSS-equivalent is 8.0 (`exposure.EOLScore`), so a critical surface finding (9.5) ranks above it; a high surface
  finding ties on 8.0 and on the severity label, and the row id breaks the tie (`EOL:` sorts before `surface:`).
- **Past end of active support only** (stage `eoas`, severity `low`): security fixes still arrive. EPSS none, CVSS-equivalent
  2.0: the rest band, after every vulnerability that has an EPSS score, with the low CVSS-only ones, below every
  security-EOL row.

The stage decides, not the severity label. The price of the first rule is the one the surface rule already pays: a non-KEV
CVE with a very high EPSS ranks below an unpatchable release; revisit it with real data. The SQL `ORDER BY` (`k1` band, `k4`
score), `exposure.Compare` and `compareRank` state this one rule and are tested against each other with eol rows at
page sizes 1, 2, 3 and 200. The row's reason reads "Past end of security support since 2023-11-26 · no one patches it any
more, so every future flaw stays open · no exploitation score applies · installed from deb.sury.org, not the distribution
· ranks after exploited vulnerabilities and before every other vulnerability, as no fix will ever come", and the row
names the release ("PHP 8.0") and the upgrade target rather than a fixed version.

Every row carries the reason it ranks where it does, and **CVSS is never the headline**:

- KEV: "Exploited in the wild since 2026-09-14 · EPSS 0.71 · CVSS 9.8"
- not KEV, with EPSS: "EPSS 0.71 · not on the CISA KEV list · CVSS 9.8"
- CVSS only: "No exploitation signal (not on the CISA KEV list, no EPSS score) · ranked by CVSS 9.8"
- nothing: "No exploitation signal and no CVSS score · vendor severity high"

"Since 2026-09-14" is the date the advisory entered the KEV catalog, which is what the feed
records; it is not the date exploitation began.

The console re-checks every page it is handed with `isRanked` and warns if apid returned it out
of order (an apid and console that disagree on the rule).

## External surface findings (slice 7b)

The Fix this week list also holds the **external surface findings** of the scanner in
[SURFACE.md](SURFACE.md): one row per finding (not per host), next to the vulnerabilities, in the same keyset-paged
order. A surface row has no KEV flag, EPSS or CVSS, so it enters the order by its severity:

| Order | Rows |
| --- | --- |
| 1 | KEV vulnerabilities (as above) |
| 2 | **critical and high surface findings**: live for anyone on the internet with no foothold or exploit needed (an SMB, RDP or database port that answers, an expired certificate, `+all` in SPF, a missing DMARC record). Critical before high, then the older finding first |
| 3 | everything else by EPSS, then CVSS, then severity. A **medium or low surface finding has no EPSS** and ranks like a vulnerability with no EPSS score and the CVSS-equivalent of its severity (medium 5.0, low 2.0), so DMARC `p=none` sits among the medium vulnerabilities |

`info` findings (DNSSEC unsigned, SSH reachable on a server) are observations, never ranked and never counted, like an
informational vulnerability. **Missing evidence never ranks**: a check that could not run produces no finding. A finding
whose check could not run on its latest pass stays listed from its last confirmation and is marked *unconfirmed*
(`surface.unconfirmed`), with the date; it is not refreshed and not dropped.

The price of putting critical and high surface findings above every non-KEV vulnerability is that a non-KEV CVE with a very
high EPSS ranks below an exposed RDP port. That is a judgement, written into `internal/exposure` and its tests; revisit it
with real data.

The "why it ranks here" line never leads with a number that does not exist:

- critical/high: "Live for anyone on the internet: no foothold or exploit needed · critical severity · ranks after exploited
  vulnerabilities and before every other vulnerability"
- medium/low: "No exploitation signal (external surface finding) · ranked by severity medium · alongside vulnerabilities with no
  EPSS score"

Where the rule lives, three times and always the same: `internal/exposure` (`Band`, `SurfaceScore`, `Compare`), the SQL in
`storepg/exposure.go` (tested against `Compare` at page sizes 1, 2, 4 and 200) and `lib/exposure-model.ts` (`rankBand`,
`SURFACE_SCORE`, `compareRank`; the console warns if apid returns a page out of order).

Surface rows are only in the fix bucket. They are never in the watch list (nothing is "waiting on a vendor"), never in the
KEV callout (`kevOnly=1` keeps only exploited vulnerabilities), and a removed asset's findings leave every list and count
(the rows are kept as evidence). A resolved surface finding is in the Resolved list, with the day it closed.

**Summary and trend.**

- `GET /v1/exposure/summary` gains `surface` (assets, unauthorised, scanned, findings, `bySeverity`, info, assetsAffected,
  `lastScanAt`, `checksNotAssessed`) and `fixable.surface` / `fixable.total` (the length of the list). The Fleet page shows
  **"External surface: N findings (x high) across M assets, last scanned <time>"**; a surface never scanned reads "not scanned
  yet", never "0 findings", and checks that could not run are named. Fix this week now counts both kinds in its description
  and in its tab.
- `GET /v1/exposure/trend` gains a **series of its own**: `surface` (open critical, high, medium and low findings per UTC day),
  `surfaceHigh` (the critical and high part) and `surfaceKnown` (false before the first surface scan: the zeros mean no data).
  The console draws it as a second bar chart on its own scale: hundreds of vulnerabilities would flatten a handful of
  findings, and the point is that an email-authentication fix visibly pays off. A finding that closed and came back counts
  as closed in between (migration 025, `surface_finding_intervals`), except for findings reopened before slice 7b, whose
  closed days were never recorded.

**Drawer.** A surface row opens `/advisories?advisory=surface:<id>`: the finding, how to fix it, **open on / closed on** (every
interval), and the raw observation behind it (the record text or certificate fields, so it can be compared with `dig` or
`openssl`). `GET /v1/exposure/advisory?id=surface:<12 digits>` answers `{source: "surface", detail: {finding, intervals,
confirmed, latest, unconfirmed}}`; a malformed key answers 400, an unknown one 404.

**Evidence export.** Surface findings, intervals and every scan's raw observations ride in the signed evidence export (any
bundle, scoped or not). What `defendsec-verify` proves, and what it does not, is in [SURFACE.md](SURFACE.md#evidence-export).

## Status

| Status | Source |
| --- | --- |
| `open` | the matcher still confirms the finding |
| `acknowledged` | an operator's note in the console (the triage store); it does not remove the finding from any count |
| `resolved` | the matcher no longer confirms it; the row is kept with `resolved_at` |

A resolved finding records **how** it closed (`vuln_findings.resolution`), from the inventory
the same report carried:

| `resolution` | Meaning |
| --- | --- |
| `fixed` | the package is installed at or above the fixed version (`resolved_installed` is the version) |
| `package_removed` | the package is no longer installed |
| `no_longer_affected` | the package is still there below the fix (or there was no fix), but the advisory data no longer lists it: a feed reclassified or withdrew it |
| *(empty)* | closed before this column existed, or closed without an inventory in hand |

When a closed finding comes back, the row reopens with a new `first_seen` and the interval that
ended is copied to `vuln_finding_intervals`, so "open on date A, closed on date B" and the
trend survive a recurrence.

Age is `first_seen` to now (open) or `first_seen` to `resolved_at` (closed): the age of the
current open interval.

## API

All endpoints are read-only `GET`s on the admin API, authenticated like `/v1/findings` (admin
or viewer token), and need Postgres (otherwise 503).

### `GET /v1/exposure/findings?sort=rank&status=open&bucket=fix&limit=&cursor=`

One page of advisories, ranked. `sort` must be `rank` (the only order). `status` is `open`
(default) or `resolved`. `bucket` is `fix` (default) or `watch`. `kevOnly=1` keeps only KEV
advisories. `limit` is 1–200 (default 50). The response carries `next`, an opaque keyset
cursor, empty on the last page, and `total`, the number of advisories matching across pages.
Paging is a keyset over the rank key, not an offset, so findings added or closed between two
requests do not shift the next page. (A row whose own rank changes between requests can still
move: the cursor is a position in the order, not a snapshot.)

Each row: `advisoryId`, `cve`, `summary`, `severity`, `kev`, `kevAdded`, `epss`, `cvss`,
`kinds`, `hostCount` and the first five `hosts`, `findingCount`, `packages`, `fixed`,
`firstSeen`, `resolvedAt`, `awaitingSince`, `source` (`vulnerability` or `surface`) and, on a surface row,
`surface` (asset, check, finding id, detail, fix, `lastSeen`, `unconfirmed`). Bad parameters and bad cursors answer 400.

### `GET /v1/exposure/advisory?id=<advisory id>&bucket=fix&status=open`

The provenance drawer: the advisory record, every affected host's finding (up to 500; installed
and fixed version, `firstSeen`, `resolvedAt`, `resolution`, `resolvedInstalled`, feed and
feed date, `snapshotId`, `rangeId`, and the triage `key`), and the feed snapshots those
findings reference (each feed's URL, fetch time, record count and SHA-256). 404 if nothing
matches.

### `GET /v1/exposure/summary?top=5`

What the Monday screen needs, in counts and short lists:

- `hosts`: `total`, `assessed`, `notAssessed`, `silent` (no report for 7 days) and the ten
  longest-silent hosts. A host that was never matched, or that no feed covers, is **not
  assessed**; an empty list for it says nothing.
- `fixable`: findings, advisories, hosts, and the KEV part.
- `watch`: `unfixed`, `awaitingVendor` and `kev` (the red callout).
- `sca`: open failed configuration checks, by severity.
- `fixThisWeek`: the top `top` rows of the fix list (1–25, default 5).
- `kevWatch`: the exploited advisories with nothing to install.

The unsupported-OS list is not here: the OS support policy lives in the console
(`lib/supported-os.ts`, `DEFENDSEC_SUPPORTED_OS`), so the Fleet page counts those hosts itself
from the fleet it already holds.

### `GET /v1/exposure/trend?from=&to=` or `?periodId=`

Open findings per UTC day: `open` (fixable), `kev` (the KEV part of `open`) and `watch`
(nothing to install). The window is `from`/`to` (RFC 3339; default the last 90 days) or an
**audit period** (`periodId`, from `/v1/audit/periods`), so the same question can be asked of
a quarter; at most 366 days. A day counts the findings first seen by its end and not yet
closed. The response says what the series is built from (`caveats`):

- Days before the first feed snapshot are `known: false`: their zeros mean no data, not a
  clean fleet.
- A finding whose kind changed over its life (awaiting vendor, then fixable) counts under its
  current kind for its whole interval.
- The series starts at the first feed snapshot; history before that was never recorded.

## Console

- **Exposure** (`/advisories`): the ranked list (vulnerabilities and, since slice 7b, external surface findings) with the reason on every row, tabs for
  Fix this week, Watch and Resolved, the feed-age banner, the red KEV callout, a not-assessed
  banner, keyset paging (Previous/Next links; `back` keeps a stack of cursors because the
  cursor only moves forward), and a provenance drawer (`?advisory=<id>`, so a view is a URL).
- **Fleet** (`/`): the feed-age banner, the red callout, the **Fix this week** card (top five
  with host counts), **Also check** (unsupported OS, silent hosts, failed checks by severity,
  the watch count) and **Is it getting better?** with a window selector (30/90/180 days or an
  audit period).

## Demo data

`scripts/seed-exposure-demo.sql` fills an empty database (name must contain `demo`) with 24
invented hosts and `CVE-2099-*` advisories so the console can be looked at without a fleet.
The screenshots in `docs/screenshots/` come from it. It proves rendering, not matching.
