# Vulnerability feeds (`defendsec-feeds`)

`defendsec-feeds` mirrors authoritative vulnerability data into the advisory schema (migration 019)
and records what it loaded. It downloads **whole published files and nothing else**: no package
name, host name or other fleet data is ever sent anywhere. The inventory is only ever matched
against these files locally.

It replaces `scripts/ingest-osv.py`, which sent the fleet's package names to `api.osv.dev`.

## What it loads

| Feed name | Source | Writes | Notes |
| --- | --- | --- | --- |
| `kev` | CISA KEV JSON | `advisories.kev`, `kev_added` | CVEs no other feed describes get a stub advisory (severity `unknown`, no ranges). CVEs CISA drops lose the flag. |
| `epss` | FIRST EPSS CSV (gz) | `advisories.epss`, `epss_date` | ~395k scores; only advisories that exist are updated. |
| `ubuntu-<codename>` | Canonical USN OVAL (`com.ubuntu.<codename>.usn.oval.xml.bz2`) | ranges, `distro=ubuntu`, `release=22.04` … | One range per **binary** package, with the source package alongside. |
| `debian` | Debian Security Tracker JSON | ranges, `distro=debian`, `release=12`/`13` | Includes `not_affected`, `will_not_fix`, `under_investigation`. Keyed by **source** package. |
| `rhel-8`, `rhel-9` | Red Hat OVAL v2 (`rhel-N.oval.xml.bz2`) | ranges, `distro=rhel`, `release=8`/`9` | Fixed errata only. Each range carries the erratum's issue date (`advisory_ranges.issued`). |
| `rocky-8`, `rocky-9` | Rocky Linux errata service (Apollo), `/v2/advisories`, walked page by page | ranges, `distro=rocky`, `release=8`/`9` | What **Rocky has released**, as opposed to what Red Hat has. See "Rebuild distributions" below. |
| `almalinux-8`, `almalinux-9` | AlmaLinux `errata.full.json` (`https://errata.almalinux.org/N/errata.full.json`, 30-45 MB) | ranges, `distro=almalinux`, `release=8`/`9` | What **Alma has released**. Same section. |
| `suse-leap-16.0`, `suse-tumbleweed` (`suse-leap-15.6` available) | SUSE per-CVE OVAL, `-affected` variant | ranges, `distro=opensuse-leap`/`opensuse-tumbleweed` | `fixed`, `affected` (no fix yet) and `not_affected`. |
| `osv-<ecosystem>` | OSV bulk `<ECOSYSTEM>/all.zip` | ranges with no distro, `ecosystem=PyPI` … | **Off by default.** For software the fleet runs outside the package manager. |

NVD is deliberately not a source: it does not carry distro fixed versions.

`defendsec-feeds list` prints every feed this build knows and which are enabled.

### How a matcher should read the ranges

These are decisions the parsers made so slice 4's matcher can rely on them.

- **`distro` is the `/etc/os-release` `ID`, `release` is its `VERSION_ID`** (`ubuntu`/`22.04`,
  `debian`/`12`, `rhel`/`9`, `opensuse-leap`/`16.0`). `opensuse-tumbleweed` is rolling and has a
  NULL release. CentOS Stream and Oracle Linux are matched onto `distro=rhel` and the **major**
  version. Rocky and AlmaLinux are matched against **both** their own feed and RHEL's (see below).
- **`fix_state`**: `fixed` means "installed older than `fixed` is vulnerable"; `not_affected` and
  `will_not_fix` and `under_investigation` carry no version; `affected` means affected with no fix
  published.
- **Several rows for one CVE and package are normal** (several errata, several branches). The feed
  asserts each; choosing among them is the matcher's job.
- **Ubuntu Pro (ESM) fixes use `ecosystem = 'Ubuntu:Pro'`.** A host without a Pro subscription
  cannot install them, so they must not be offered as available fixes to it.
- **Debian ranges are keyed by source package** (`package = source_package`): the tracker does not
  list binary names. The matcher must map an installed binary package to its source (dpkg's
  `Source` field) first. Ubuntu OVAL does list binaries.
- **Epochs are kept as published** (`1:3.0.1-43.el9_0`, `0:2.470.0-160000.3.1`). Use the dpkg/rpm
  comparators in `internal/vuln`, which understand them.

### Rebuild distributions (Rocky, AlmaLinux)

Rocky and Alma rebuild Red Hat's packages and publish their own errata only after the rebuild, so
a fix reaches them days after it reaches RHEL. Matching a Rocky host against Red Hat's feed alone
reported fixes the operator could not install (measured 2026-10-24: eight kernel CVEs on a patched
Rocky 9.8, fixed upstream in `5.14.0-687.60.1`, with Rocky's newest published kernel at `687.59.1`).
So these hosts are matched against two feeds, and the finding says which one the fix came from:

- Rocky/Alma's own errata cover the CVE: that erratum's fixed version is the fix to install.
- Only Red Hat has the fix: the finding is **`awaiting_vendor`** ("fixed upstream by Red Hat in
  `<version>` on `<date>`; not yet released by Rocky Linux"). It is not fixable, and it flips to
  fixable by itself on the first sync after the rebuild ships.

CentOS Stream and RHEL keep using Red Hat's feed directly. A Rocky or Alma host is only reported as
assessed when its own feed is loaded; with Red Hat's feed alone it is `no_feed`, because that feed
cannot say whether the rebuild shipped anything. All four rebuild feeds are on by default.

How the sources were checked (2026-10-24), because the first guess about Rocky's API was wrong:

- **Rocky.** `https://apollo.build.resf.org/api/v3/advisories/` **ignores every filter** (`cve`,
  `product`, `kind`, `after_raw`, and the `filters.`-prefixed forms all returned the same 10,198
  advisories), caps `size` at 100, and a page of 100 is 2.7 MB. `/v2/advisories` honours
  `filters.product=Rocky Linux 9`, `filters.type=TYPE_SECURITY` and `filters.cve`, takes
  `limit` (at most 100) and a zero-based `page`, and returns 1,558 release-9 security advisories in 16
  pages. DefendSec walks that, with only the release and the page number in the query. A walk takes
  about 1 to 4 minutes per release (the service answers a page in roughly 5 s).
- **Apollo quirks the walker handles.** Its `total` counts ten advisories twice (same name, same
  content), so the walk compares the records *received* with `total` and stores each name once; and
  the order of the CVEs and packages inside an advisory changes between requests, so the stored file
  keeps only the fields the parser reads, with lists sorted. The stored file is
  `{"advisories":[...]}` (about 6 MB for release 9, 9 MB for release 8), identical bytes for identical
  data: a second sync reports `unchanged`. A walk that comes back empty or short is refused and the
  loaded data stays.
- **Alma.** `errata.full.json` is one document (`schema_version`, `data`), streamed while parsed.

Both parsers skip module-stream builds, source RPMs and errata without a CVE, and count what they
skipped in the sync output.

### What is deliberately not covered (and counted, not guessed)

Every run prints per-feed `skipped:` counts. The known gaps:

- **Linux kernel on Ubuntu.** USN kernel definitions test the *running kernel* (`uname`), not an
  installed package. They are skipped (`kernel running-version test`). Kernel exposure needs its own
  handling.
- **RHEL AppStream module streams.** Errata that apply only when a stream is enabled (`Module
  nodejs:18 is enabled`) are skipped (`module-stream range`): without knowing the enabled streams
  they would be false positives. The Red Hat `-including-unpatched` feed (affected / will-not-fix)
  is not read either.
- **OSV `last_affected` events and `GIT` ranges**, which cannot be expressed as "fixed in".
- **Withdrawn OSV records**, and OVAL definitions or tracker rows with no CVE identifier.

## Running it

```
defendsec-feeds sync                  # fetch what changed, load it
defendsec-feeds sync --dry-run        # fetch + parse + count; write nothing to the database
defendsec-feeds sync --only debian    # one feed (KEV/EPSS only re-apply when included)
defendsec-feeds status                # per-feed state
defendsec-feeds list                  # the feed catalogue
defendsec-feeds export feeds.tar      # signed bundle of the cached feeds
defendsec-feeds import feeds.tar      # verify and load a bundle
```

Install: copy `packaging/systemd/feeds.env.example` to `/etc/defendsec/feeds.env`, install the
`defendsec-feeds` binary to `/usr/local/bin`, copy `defendsec-feeds.service` and
`defendsec-feeds.timer` to `/etc/systemd/system/`, then
`systemctl enable --now defendsec-feeds.timer`. The timer is **not** enabled by the installer.
The service reads the database URL from `/etc/defendsec/apid.env`, so it always loads into the
database apid uses. Migrations are applied on start (idempotent, advisory-locked), so the first
sync works on a fresh database.

Configuration is the environment, plus `/etc/defendsec/feeds.env` when present (a real environment
variable wins over the file). Every variable is documented in `feeds.env.example`.

### Behaviour worth knowing

- **Conditional fetch.** `ETag`/`If-Modified-Since` are sent when the cached copy came from the same
  URL. A 304, or a 200 with an identical SHA-256, loads nothing.
- **Resumable.** Each feed is loaded in its own transaction and its `feed_status` row is written
  when it commits. A run that dies half way is simply run again: feeds already loaded show
  `unchanged`, the rest load. (A partial download never replaces a cached file; it is written to a
  temporary name and renamed only after the whole body arrived.)
- **A feed owns a scope of ranges** (a distro + release, or an OSV ecosystem). Loading replaces
  exactly that scope, atomically, and merges advisory text into the shared advisory rows: highest
  severity and highest CVSS score any feed asserts win; empty fields are filled; a KEV stub's text is
  replaced by the first real record.
- **Refuses data that looks wrong.** A feed that parses to zero ranges, or that shrank to under half
  its previous size (when it had at least 1000 records), is not loaded and the previous data stays.
  `--force` overrides the shrink check. A file that fails to parse is not kept in the cache (the
  previous good copy is put back), so `export` never ships it.
- **Failures keep their age.** A failed attempt records the error and attempt time but leaves
  `last_success_at` alone, so a feed that has been failing for a week shows as a week old.
- **Snapshots.** A sync that loads anything creates one `feed_snapshots` row listing every feed
  present (name, URL, fetch time, SHA-256, record count). Runs that load nothing create none. A
  run killed after creating its snapshot leaves it with zero record counts; the next run makes a
  new one.
- **One run at a time**: a Postgres advisory lock stops a timer firing during a manual sync.
- **Only `https`** URLs (plain `http` for loopback); no credentials in URLs; a token in a mirror
  URL's query string is stripped from everything stored, logged, exported or served.

### Admin API and console

`GET /v1/feeds` (admin or viewer token) returns, per feed: `lastSuccess`, `ageSeconds`, `stale`
(older than 7 days, or never succeeded), `recordCount`, `snapshotId`, `sha256`, `lastError`, plus
`anyStale`, `oldestAgeSeconds` and `latestSnapshotId`. The Advisories page shows a banner: **red if
any feed is more than 7 days old or has never synced**, amber if the age cannot be established
(status unreadable, no feed ever synced, or a recent sync had errors), plain otherwise.

## Matching an inventory by hand

```
defendsec-agentd -print-inventory > inv.json       # on the host; reads the package db, contacts nothing
defendsec-feeds match inv.json                       # read-only: stores nothing, raises nothing
defendsec-feeds match --json --all inv.json          # full result, including unfixed/informational
```

Output (and `--json`'s `counts`) tallies the findings as **fixable** (a fix is released for this
host's distribution), **awaiting_vendor** (fixed by Red Hat, not yet released by Rocky/Alma),
**no_fix** (affected, no fix anywhere) and **informational**, then repeats the tally for the CISA
KEV entries among them. `awaiting_vendor` rows are always listed; `--all` adds the other two.

Exit status: 0 no *fixable* findings, 2 at least one, 3 not assessed (no feed covers the host's
distro and release). `awaiting_vendor` never makes the status 2. See [MATCHING.md](MATCHING.md).

## Air-gapped installs

On the connected install: `defendsec-feeds sync` then `defendsec-feeds export feeds.tar`.
`export` never fetches; it bundles the cached files, so run `sync` first. The bundle is a tar:

```
manifest.json         feed names, URLs (query stripped), fetch times, digests
feeds/<name>/data     each feed file exactly as published
SHA256SUMS            digest of manifest.json and every feed file
SHA256SUMS.sig        base64 Ed25519 signature over SHA256SUMS (domain "defendsec-feeds-v1")
signer.pub            the signer's public key (informational; never used to decide trust)
```

It is signed with that install's **control key** (`<data-dir>/pki/control-ed25519.key`). The
signature uses its own domain string, so it can never be replayed as a command signature.

Carry `feeds.tar` and the signer's public key (`<data-dir>/pki/control-ed25519.pub`) to the
air-gapped box and verify the key out of band. There:

```
defendsec-feeds import --trust-key /media/exporter-control.pub /media/feeds.tar
```

(or list the key in `DEFENDSEC_FEEDS_TRUSTED_KEYS`). `import` accepts only keys *you* named plus
that box's own control key. It refuses a bundle with an extra, missing, duplicated or unsigned
member, a link, an odd path or any digest mismatch, before writing anything to the cache. Feeds the
box has not enabled are skipped. A bundle older than the cached copy is refused as a rollback
(`--force` overrides). Imported feeds are recorded with the **bundle's fetch time**, so the age
shown in the console is the age of the data, not of the import.

## Sizes and timings (measured)

See [VERIFIED.md](VERIFIED.md), "Slice 3", for the measured sizes, counts, timings and peak
memory from a real run on a 2-vCPU, 4 GB host.
