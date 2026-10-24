# How findings are computed

A finding is one advisory that applies to one package on one host. DefendSec computes them in
the control plane (`defendsec-apid`) from two inputs: the packages each agent reports, and the
advisory ranges `defendsec-feeds` loads from the distributions' own security data
([FEEDS.md](FEEDS.md)). The console only reads the result.

## Why not compare with an upstream version

Distributions fix vulnerabilities by backporting. Ubuntu 22.04 fixed CVE-2024-6387 in
`1:8.9p1-3ubuntu0.10` and never shipped OpenSSH 9.8p1. Comparing the installed build with the
upstream floor `9.8p1` flags every patched host. So the matcher keys on
`(distro, release, source package, CVE)` and compares against the version *that distribution*
says fixed it, with that distribution's version ordering (dpkg or rpm, chosen from the host's
package manager, not guessed from the version string).

## What the agent reports

Added to the existing inventory report; every field is optional, so older agents keep working
(they are matched by binary name, and a host that reports no distro is shown as not assessed).

| Field | Source |
| --- | --- |
| `distro`, `distro_release` | `/etc/os-release` `ID`, `VERSION_ID` |
| `package_manager` | `dpkg` or `rpm` |
| `software[].name`, `.version` | `dpkg-query` / `rpm -qa` (rpm versions carry the epoch) |
| `software[].source_package`, `.source_version` | dpkg `Source:` field; rpm `SOURCERPM` |

dpkg lists only packages in state `ii` (installed). An rpm installed in several versions (the
kernel) is reported once, at the newest. The full list is reported, not a prefix: a clean result
has to mean every package was examined (the old collector stopped at 80).

`defendsec-agentd -print-inventory` prints exactly this (no hostname, no addresses) as JSON and
contacts nothing, for offline matching and for support requests.

## Matching rules

1. **Distro mapping.** CentOS Stream and Oracle Linux are matched against the RHEL feed by major
   release. Rocky and AlmaLinux are matched against **their own errata and RHEL's**, by major
   release (rule 5). A range applies to a package through its source package (Ubuntu, Debian) or
   its binary name (RHEL, SUSE). When the range is keyed on the source, the installed *source*
   version is compared, so a binNMU (`2.36-9+deb12u4+b1`) is judged as `2.36-9+deb12u4`.
2. **Fix state.**
   - `fixed`: a finding if the installed version is below the fixed one; clean at or above it.
     If several fixed ranges apply (security pocket and ESM) reaching any of them is clean.
   - `not_affected`: no finding, ever, for that advisory and package.
   - `affected` with no fix: kind **unfixed**.
   - `will_not_fix`, `under_investigation`: kind **informational**.
   - `introduced`: a package older than the first vulnerable version is not affected.
3. **Kinds.** `finding` (fixable) has a fix to install and is the "fix these" list.
   `awaiting_vendor`, `unfixed` and `informational` are stored and shown, never counted as things
   to patch. A fully patched Debian host still has `unfixed` entries because Debian's tracker lists
   open CVEs; Ubuntu and RHEL feeds only carry fixed errata. Order everywhere: finding,
   awaiting_vendor, unfixed, informational, then KEV, severity, EPSS.
4. **Ubuntu Pro.** A range from `Ubuntu:Pro` counts only on a host that evidently uses Pro (an
   installed `+esm`/`~esm` package). Otherwise the fix cannot be installed and the entry is
   `unfixed`. This is a heuristic: the agent does not report `pro status` yet.
5. **Rebuild hosts (Rocky, AlmaLinux).** A fix reaches them after Red Hat's. Each advisory is judged
   from both feeds' ranges:
   - installed at or above *either* feed's fixed version: patched (reaching a published fix is
     never a finding);
   - otherwise, if the **rebuild's** errata list a fix above the installed version: `finding`, and
     the version to install is the rebuild's;
   - otherwise, if only **Red Hat** has one: `awaiting_vendor`, with the reason "fixed upstream by
     Red Hat in `<version>` on `<date>`; not yet released by Rocky Linux". Not fixable, not "fix
     this week", but still shown, still counted per host, and a KEV one still raises an alert (the
     CVE is exploited whether or not there is anything to install) and the console's red notice.
   When the rebuild ships, the next match (new feed snapshot) turns it into a `finding` in place.
   Without the rebuild's own feed loaded the host is `no_feed`: Red Hat's feed cannot say whether
   the rebuild shipped anything, so nothing is invented either way. RHEL and CentOS Stream skip all
   of this and use Red Hat's feed directly.
6. **Upstream floors** (`distro IS NULL`, ecosystem `legacy` only) are used for software the
   distro feed has no entry for, and only through `Assess()`, which answers "unknown" for a
   distro-built version below an upstream floor rather than guessing. OSV language ecosystems
   are never matched against OS packages.
7. **Coverage.** Each run records whether a feed could speak for the host: `covered`,
   `no_feed` (distro known, no feed loaded for that release) or `no_distro`. A host with no
   findings and no coverage was not assessed; the console says so.

## What each finding records

`advisory_id`, `range_id`, `snapshot_id`, `feed` (name) and `feed_date` (when that feed was
fetched), plus the installed and fixed versions, severity, KEV and EPSS. An `awaiting_vendor`
finding's `feed` is Red Hat's (where the fix is) and its `reason` says who has not released it. Findings are never
deleted: a finding that goes away gets `resolved_at`, and one that returns reopens with a new
`first_seen`. `range_id` is evidence, not a foreign key, because ranges are replaced on every feed
sync; `snapshot_id` is the durable reference.

## When it runs

On every inventory report (skipped if neither the packages nor the feed snapshot changed), and
for every host shortly after `apid` starts and whenever a new feed snapshot appears (checked every
ten minutes). Alerts are raised only for findings on the CISA KEV list, or critical with a fix
available.

## API

`GET /v1/findings?deviceId=&kind=finding|awaiting_vendor|unfixed|informational&resolved=1&limit=`,
`GET /v1/findings/{id}` (advisory, matched range, snapshot with each feed's URL, fetch time and
SHA-256), `GET /v1/findings/summary[?deviceId=]` (per host: `open`, `kev`, `awaitingVendor`,
`kevAwaitingVendor`, `unfixed`, `informational`; `open` is the fixable count and never includes
`awaitingVendor`). Same tokens as the other read endpoints. The ranked, grouped view the console
shows is `/v1/exposure/*`; see [EXPOSURE.md](EXPOSURE.md).

## Known limits

- **Third-party repositories.** dpkg and rpm do not record where a package came from. A vendor
  build that shares a source name with a distro package (for example NodeSource's `nodejs`) is
  matched against the distro's data for that name. Where the vendor version is higher than the
  distro's fix it reads as patched, which may be wrong.
- **Kernels.** The running kernel is not reported, and Ubuntu/RHEL running-kernel definitions are
  skipped by the feed parsers. Installed kernel packages are matched like any other; the newest
  rpm kernel is used.
- **Module streams** (RHEL AppStream) are skipped by the feed parsers, so a package from a
  non-default stream is not matched.
- Fixed versions can only be as good as the feed: a distribution that has not yet published an
  advisory looks clean.
- **awaiting_vendor needs both Red Hat's and the rebuild's feeds to be current.** If Rocky has
  shipped a fix under an erratum that carries no CVE, or Apollo is behind, a fixable item can
  show as awaiting until the feed catches up. The reverse cannot happen: a finding is only
  "fixable" when the rebuild's own errata list it.
- Rocky 10 and AlmaLinux 10 are not covered: no feed is enabled for release 10 (Red Hat publishes no v2 OVAL feed for it yet, so there is nothing to compare the rebuild with).
