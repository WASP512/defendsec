# Application end-of-life

A host can run software its upstream no longer patches and be fully up to date as far as every distribution
tracker is concerned, because no tracker covers it. The case that started this slice: a Debian 11 VM running
**PHP 8.0.30 from the third-party Sury repository**. PHP 8.0 has been end-of-life since 2023-11-26. Debian
does not ship PHP 8.0, so the matcher had nothing to say about it ("not assessed").

DefendSec now checks software against [endoflife.date](https://endoflife.date/docs/api/), with one rule that
decides everything.

## Origin decides

| Where the package came from | What DefendSec does |
| --- | --- |
| **The host's own distribution** (Debian's archive, Ubuntu's, Rocky's, ...) | **Nothing.** It follows the distribution's support lifecycle, which the Supported-OS policy and the distro trackers already cover. Ubuntu 22.04's `python3.10` and OpenSSL 3.0 are upstream end-of-life and Canonical-supported: no finding. |
| **A third-party repository** (Sury, PGDG, NodeSource, a PPA, Remi, nginx.org, Microsoft, ...) or software installed on a host with **no package manager** (Windows) | Judged against the upstream release calendar. Nobody else is backporting fixes to it. |
| **Origin could not be read** (an agent older than this slice, a version no repository lists any more) | **Not assessed.** Never a finding and never counted clean. |

The agent reads the origin without changing anything (`internal/hostinv/origin.go`):

- **dpkg:** `apt-cache policy` with no arguments lists every source with the `Origin:` its Release file declares
  (`release o=Debian,...`); `apt-cache policy <packages>` lists, per version, the sources that carry it. The origin of a
  package is the source that carries the *installed version*. If the distribution carries that version too, the
  distribution wins. A version no repository carries any more has no origin; the server then looks for third-party
  signatures in the version string (`sury`, `nodesource`, `pgdg`, `+maria~`, `.remi`, `1rl1`, `ppa`) and otherwise leaves
  it unknown. A Release file whose `Origin:` names nothing (NodeSource's says `. nodistro`) is replaced by the
  repository's host. Repository addresses are reported with credentials and query strings removed.
- **rpm:** the `Vendor` tag, and the `Packager` (e-mail address removed) as evidence or when the vendor is blank. A
  Rocky package's vendor is the Rocky Enterprise Software Foundation; an EPEL package says `Fedora Project`, which on a
  Rocky or RHEL host is a third party and is treated as one.
- **Windows:** no package manager, so everything on the host was installed by hand: third party.

Which labels are a distribution's own is a table in `internal/lifecycle/origin.go`. A distribution that is not in the
table cannot be told apart from its repositories: its packages stay unknown rather than being guessed at.

The inventory carries two new optional fields on each package, `origin` and `origin_repo` (proto fields 5 and 6 of
`SoftwareItem`). An old agent leaves them empty and keeps working; the server then does not judge its packages.

The decision is made on the server (`lifecycle.ClassifyOrigin`), not in the agent, so the rule can improve without an
agent update.

## The mapping table

`internal/lifecycle/mapping.go`: a curated, tested table from installed package name (and version) to an endoflife.date
product and release cycle. A package the table does not know is not assessed. The patterns are narrow on purpose:
Debian's `php-fpm` is version `2:8.2+93`, which is not PHP's version, so it is not mapped, while `php8.0-cli` names its
release.

| Product (endoflife.date) | dpkg | rpm | Windows (display name) |
| --- | --- | --- | --- |
| `php` | `php8.0-cli`, `libapache2-mod-php8.0`, ... (release in the name) | `php80-php-cli` (Remi), `php`/`php-cli`/`php-fpm`/`php-common` (upstream version) | |
| `nodejs` | `nodejs` (upstream version) | `nodejs` | |
| `python` | `python3.9`, `libpython3.10-stdlib`, ... | `python3.11`, `python311` | |
| `postgresql` | `postgresql-16` | `postgresql16-server` | |
| `mysql` | `mysql-community-server`, `mysql-server`, `mysql-server-8.0` | `mysql-community-server`, `mysql-server` | |
| `mariadb` | `mariadb-server`, `mariadb-server-10.6` | `MariaDB-server` | |
| `nginx` | `nginx` | `nginx` | |
| `apache-http-server` | `apache2` | `httpd` | |
| `redis` | `redis-server`, `redis` | `redis` | |
| `mongodb` | `mongodb-org`, `mongodb-org-server`, ... | same | |
| `dotnet` | `dotnet-sdk-8.0`, `dotnet-runtime-8.0`, `aspnetcore-runtime-8.0` | same | `Microsoft .NET Runtime - 6.0.25` |
| `eclipse-temurin` | `temurin-17-jdk` | `temurin-17-jdk` | `Eclipse Temurin JDK with Hotspot 17.0.8+7` |
| `amazon-corretto` | `java-17-amazon-corretto-jdk` | `java-17-amazon-corretto-devel` | |
| `microsoft-build-of-openjdk` | `msopenjdk-21` | `msopenjdk-21` | |
| `mssqlserver` | | | `Microsoft SQL Server 2016` |

The Windows rows are unit-tested on names only: no Windows host has reported through them.

A release cycle is looked up by the longest dotted prefix the feed lists (`8.0.30` finds `8.0`; `.NET 8.0.1` finds `8`).
A third-party package whose release the feed does not list is counted as "no release data" and not assessed.

Windows Server itself is not in the table: operating systems follow the Supported-OS policy.

## The feed

Feed name `endoflife`, kind `endoflife`, `https://endoflife.date/api/v1/products/full` (API v1, schema 1.x; a bulk
document of about 3 MB with every product and release cycle). It goes through the same pipeline as every other feed:
conditional fetch, a `feed_snapshots` row with the SHA-256, the status row behind the feed-age banner, the shrink guard,
signed offline bundles (`export` / `import`) and a refusal to replace good data with a bad download. The parser fails on
malformed JSON, on a schema other than 1.x, on a `total` that disagrees with the products present (a truncated
download), and when none of the wanted products is in the document. Only the products the mapping table can produce are
kept (15 of 485 products, about 300 release cycles) in the `eol_releases` table, replaced wholesale on each load.

It is enabled by default (`DEFENDSEC_FEEDS_ENABLED` unset). The calendar is judged against the day the matcher runs, not
the day the feed was fetched, so a stale calendar still flags a release that went end-of-life last week.

## Findings

Kind `eol`, in the same "Fix this week" bucket as a patch to install: upgrading is the remedy. One finding per host, per
product release, however many of its packages are installed (`EOL:php:8.0` on a host with `php8.0-cli`, `-fpm` and
`-common` is one finding naming all three). Fields: the product, release cycle, the date the stage began, the origin
(label and repository), the packages, the release to upgrade to and when its security support ends, the latest release
in the cycle, a link, and the feed snapshot it was computed from.

| Stage | Meaning | Severity |
| --- | --- | --- |
| `eol` | Security support has ended (`eolFrom` is today or earlier). Nobody issues fixes. | `high` |
| `eoas` | Active support has ended; security fixes continue until end of life. | `low` |

Software past end of *security* support ranks above software past end of *active* support.

**The upgrade target** is the oldest newer release that still has active support (the smallest jump that does not land
on a release already winding down), else the oldest still receiving security fixes. When no newer supported release
exists the finding says the fix is more than an upgrade.

**Controls** come from the catalog, not from the finding: CIS v8 2.2 ("ensure authorized software is currently
supported") and NIST SP 800-53 SI-2 (flaw remediation), through the signal `software.supported`.

**Resolution.** A finding closes when a run no longer confirms it. The package is gone: `package_removed`. The package is
still there at another version (the host upgraded it): `fixed`. The same package at the same version, but the calendar
or the origin reading changed: `no_longer_affected`.

### Where it ranks

The exposure ranking is KEV, then EPSS, then CVSS, then the severity label. An end-of-life finding has no EPSS or CVSS,
so it ranks **among the unscored findings**: after every finding that has an exploitation score, and by its severity
label against the other unscored ones. A release past security support (`high`) sits with the unscored high-severity
vulnerabilities; one past active support (`low`) sits with the unscored low ones. The ranking code is unchanged, and
the "why it ranks here" line says what the calendar says instead of "no exploitation signal".

This is one reading of "below KEV and next to high vulnerabilities". It puts end-of-life behind every vulnerability with
an EPSS score, however small. If it should sit higher, it is a one-key change in the SQL ranking, `internal/exposure` and
`compareRank`, with their tests.

## Windows end of support (the Supported OS policy)

The Supported OS policy used to hold one Windows number, `WINDOWS_MIN_BUILD = 20348` (Server 2022), so Windows Server 2016
(build 14393, supported until 2027-01-12) and Server 2019 (17763, until 2029-01-09) were reported as no longer getting
security updates. A build number cannot work: client, server and LTSC editions share builds.

| Build | Edition | Support ends |
| --- | --- | --- |
| 14393 | Windows Server 2016 | 2027-01-12 |
| 14393 | Windows 10 LTSB 2016 | 2026-10-13 |
| 17763 | Windows Server 2019, Windows 10 LTSC 2019 | 2029-01-09 |
| 17763 | Windows 10 1809 Enterprise or Pro | 2021 |
| 19044 | Windows 10 LTSC 2021 | 2027-01-12 |
| 19044 | Windows 10 21H2 Enterprise or Pro | 2024 |
| 19045 | Windows 10 22H2 | 2025-10-14 |

Windows is now judged from the `windows` and `windows-server` products of the same endoflife feed (`lib/os-lifecycle.ts`),
by **edition and build**:

- **The edition** is the Windows `EditionID` registry value, reported by the agent as the optional `os_edition`
  (`HeartbeatRequest` field 8; `devices.os_edition`, migration 025). Old agents leave it empty, and the OS caption then
  stands in for it where it names the edition ("Windows Server 2016 Standard", "... Enterprise LTSC"); the verdict says
  when it was read from the caption. Datto RMM reports an edition too; slice 8 fills the same field.
- **The cycle** is found by its newest build (`latest`, `10.0.14393`); the edition picks among the cycles that share it:
  `windows-server` cycles for `Server*` editions (semi-annual `-sac` cycles only for `*ACor`); for client editions the
  `-w` cycles (Home, Pro, Pro Education, Pro for Workstations), `-e` (Enterprise, Education, IoT Enterprise), `-e-lts`
  (`EnterpriseS`, Enterprise LTSC and LTSB), `-iot-lts` (`IoTEnterpriseS`), and the suffix-less cycles, which have one date
  for every edition.
- **Supported** means `today < eolFrom`: `eolFrom` is the first day without security updates. Paid extended security
  updates (`eoesFrom`) do not count: Windows 10 22H2 has them to 2028 and is reported unsupported.
- **Edition unknown is unknown, never unsupported.** Every cycle the build could be is judged; if they agree the answer
  stands (22H2 is over for every edition), and if they disagree (14393 is Server 2016 and Windows 10 1607) the result is
  `unknown` and says why. No calendar loaded, no build, a build the calendar does not list, a cycle with no end date: also
  `unknown`.
- `DEFENDSEC_SUPPORTED_OS=windows=<build>` still works and wins over the calendar, for an operator who wants a plain build
  floor. Linux floors are unchanged.

The console reads the calendar from `GET /v1/lifecycle/os` (admin API) and caches it for five minutes; a failed read keeps
the last good calendar. The host's detail line says why: "Windows Server 2016: security updates until 2027-01-12".

Linux distributions are still judged by the floors in `lib/supported-os.ts`; moving them onto the same calendar is a
follow-up.

## What it does not see

- **Software installed outside the package manager on Linux** (`/usr/local`, a binary unpacked from a tarball, a
  container image, `nvm`, a Python virtualenv). The agent reads the package database only.
- **A host whose agent predates origin reporting** (its packages are "not assessed" until the agent is updated).
- **A release the table or the feed does not know**, and any product not in the table.
- **dnf `from_repo`.** The rpm origin is the vendor and packager recorded in the package, not the repository dnf
  installed it from.
- **Paid extended support.** A release past end of life that a vendor still patches for money (MariaDB, SQL Server ESU) is
  reported as end of life; the finding carries `eoesFrom` where the feed has one.
- **Windows** has never run through this path on a real host: the edition logic is unit-tested against the real calendar
  (fetched 2026-10-24), the agent script's `EditionID` read has not run on a Windows host, and `defendsec-agentd` on
  Windows has not reported an edition to a control plane.

An empty list is read next to what was examined: each host records how many of its packages the table knew, how many were
the distribution's own and how many had no readable origin (`host_vuln_state.eol_*`; the host page prints it, and
`defendsec-feeds match` prints an `app eol:` line).
