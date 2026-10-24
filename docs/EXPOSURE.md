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

Every row carries the reason it ranks where it does, and **CVSS is never the headline**:

- KEV: "Exploited in the wild since 2026-09-14 · EPSS 0.71 · CVSS 9.8"
- not KEV, with EPSS: "EPSS 0.71 · not on the CISA KEV list · CVSS 9.8"
- CVSS only: "No exploitation signal (not on the CISA KEV list, no EPSS score) · ranked by CVSS 9.8"
- nothing: "No exploitation signal and no CVSS score · vendor severity high"

"Since 2026-09-14" is the date the advisory entered the KEV catalog, which is what the feed
records; it is not the date exploitation began.

The console re-checks every page it is handed with `isRanked` and warns if apid returned it out
of order (an apid and console that disagree on the rule).

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
`firstSeen`, `resolvedAt`, `awaitingSince`. Bad parameters and bad cursors answer 400.

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

- **Exposure** (`/advisories`): the ranked list with the reason on every row, tabs for
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
