# Repository health (slice 11)

A package manager that cannot trust one of its repositories does not always say so. On 2026-10-22 a client host's PHP
repository key had expired. `apt-get update` printed a warning for that one repository, carried on with the others, and
left the host's last good index in place. The host kept answering "nothing to install" for packages whose index had
stopped moving. DefendSec takes pending updates from the package manager, so on that host it would have repeated the lie.

This slice reads, per enabled repository, whether the host is still getting and verifying what the repository publishes.
When it is not, the repository is a finding and the host's pending-updates list is marked **unreliable**.

## What is checked, and what is not changed

The agent reads and reports; the **server** judges (`internal/repohealth`). The staleness threshold is therefore one setting
for the fleet, and changing it re-judges every host at its next report.

**The check never refreshes anything.** Nothing runs `apt-get update`, `dnf makecache` or `zypper refresh`, and nothing
writes to apt's or dnf's state. The point of the check is that a refresh can fail quietly; a check that refreshed would
hide the thing it looks for.

### apt (Debian, Ubuntu)

For every enabled source in `/etc/apt/sources.list`, `sources.list.d/*.list` and `*.sources` (one-line and deb822):

1. The `InRelease` (or `Release` + `Release.gpg`) that apt already holds under `/var/lib/apt/lists` is verified with
   `gpgv` against the keyring **that source uses**: its `signed-by` (a keyring file, an armored `.asc`, a list of
   fingerprints, or an inline key) or, without one, `trusted.gpg` and `trusted.gpg.d`. The keyring is handed to `gpgv`
   as an in-memory file (`memfd`); nothing is written to the host. A `file:` repository keeps no copy in `lists`, so its
   index is verified where it is.
2. `gpgv`'s `--status-fd` lines are parsed, not its exit code. **An expired key exits 0 with "Good signature"**; only the
   `EXPKEYSIG` and `KEYEXPIRED` lines say otherwise (measured, see VERIFIED.md). One `GOODSIG` wins; otherwise the most
   informative failure is reported: `EXPKEYSIG`, revoked key, `BADSIG`, `NO_PUBKEY`.
3. `Date:` and `Valid-Until:` of the Release file, and the host's last refresh: `/var/lib/apt/periodic/update-success-stamp`,
   or the lists directory's modification time when the host has no stamp.
4. Key expiry dates are read from the keyring files with a small OpenPGP packet reader (dates only, no cryptography).

apt names a lists file after the address it fetched. The usual flat repository (`deb URI ./`) is fetched from `URI/./`, so the
file is `<host>:<port>_._InRelease`, not `<host>:<port>_InRelease` (measured on Ubuntu 22.04 with a local http repository; the
first version looked for the wrong name and reported such a repository as `no_index`).

`gpgv` is run argv-only (no shell) with fixed options, on files under `/var/lib/apt/lists` or the source's own keyring.
It is the only new program. It reads; it cannot write to a keyring.

The agent's own `apt-cache policy` calls (origin for slice 10) now pass `-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=`:
run as root, apt rewrites `/var/cache/apt/pkgcache.bin` when it is missing or older than the indexes. With the options apt
builds the same cache in memory, about 1.6 s per call instead of 0.1 s, so the calls are batched.

### dnf, yum, zypper

For every enabled repository in `/etc/yum.repos.d`, `/etc/zypp/repos.d` (variables `$releasever` and `$basearch`
substituted): the `gpgkey` files it names (local `file://` keys only; the key's expiry and revocation are read), the keys
`rpm` has imported (`gpg-pubkey`, which win over the file when the ids match), and the modification time of the cached
`repomd.xml`, which the client touches whenever it fetches or revalidates it. A repository with `gpgcheck=0` and a repository
whose key is a remote URL are reported as **not checked**, which is not a finding. The agent does not verify `repomd.xml`
signatures (`repo_gpgcheck`) and does not read per-package origin (`from_repo`); see "What it does not see".

## Verdicts

Per host, `reliable`, `unreliable` or `unassessed`:

- **reliable**: every enabled repository was checked and passed.
- **unreliable**: a repository failed a check, **or a check could not be made** (for instance `gpgv` is not installed).
  "0 pending" from such a host means "none that the package manager can see". The console says so wherever pending updates
  appear and never prints a clean zero for it.
- **unassessed**: the agent reports no repository evidence (an older agent, or a package manager it does not read). Shown as
  before, with a note that it was not cross-checked.

The verdict is stored with the report (`devices.repo_health`, assessment and time), so the console does not re-judge.

## Findings

Kind `repo_health`, basis `host`, one per repository with a problem, advisory id `REPO:<12 hex>` (a hash of the repository
id, which is an address with slashes and spaces). It is in the **fix** bucket: updates from that repository have stopped, and
the fix is work for this week.

| Problem | Severity | When |
| --- | --- | --- |
| `key_expired` | **high** | the signing key has expired (`EXPKEYSIG`; an rpm key whose expiry has passed) |
| `key_missing` | **high** | the repository's key is not in the keyring it is verified against (`NO_PUBKEY`, a `signed-by` file that is gone) |
| `key_revoked`, `signature_bad`, `unsigned` | **high** | revoked key, a signature that does not verify, no valid signature |
| `no_index` | **high** on apt, medium on dnf and zypper | an enabled repository with no index on the host: apt never fetched it or refused it (an untrusted key is the usual cause); dnf has no cached `repomd.xml` for it |
| `index_expired` | medium | `Valid-Until` has passed: apt refuses such an index itself, so nothing new arrives from it |
| `index_stale` | medium | the index is older than the threshold (default **7 days**, `DEFENDSEC_REPO_STALE_DAYS` on apid) |

Several problems on one repository are one finding at the highest severity, listing them all. "Stale" means different things
by manager: for apt, `Date:` is when the publisher published, and some publishers publish rarely (Ubuntu's base pocket has said
2022-04-21 for years), so an old `Date:` alone is not a finding; it is one when the host has **also** not refreshed within the
threshold. For dnf and zypper the cached `repomd.xml` age is the host's knowledge, so it is judged directly.

The finding's text names the repository, every problem, the dates it rests on and the fix: get the vendor's current key
from the vendor, check its fingerprint against the vendor's site, install it as its own keyring and reference it with
`signed-by=`, then refresh. Controls: NIST 800-53 SI-2 and CM-6, CIS v8 7.3 and 7.4, with their CMMC, 800-171 and CJIS
mappings, through the signal `repo.health`.

A finding resolves when the repository passes (`fixed`) or is no longer enabled on the host (`no_longer_affected`). A report
that is missing, empty or from an older agent **does not close** it: missing evidence is not a repaired repository.

### Where it ranks

A high-severity repository problem (a key problem, or no index on an apt host) is in the **urgent band**, after KEV, with the critical/high surface findings and security-EOL,
CVSS-equivalent 8.0: a repository whose key has expired hides every vulnerability it would have fixed. A stale index (medium)
is in the rest band at CVSS-equivalent 5.0, with the CVSS-only medium vulnerabilities. Ties are broken by the kind of row
(vulnerability, end-of-life, repository, identity, surface; `exposure.TieRank`), then by the row id. The rule lives in `internal/exposure/rank.go`, the SQL `k1`/`k4` in `internal/storepg/exposure.go`
and `rankBand`/`effective` in `lib/exposure-model.ts`, and `TestRepoHealthRanksWithEverythingElse` checks SQL against Go with
a row of every kind.

## Where it shows

- **Fleet and Fix this week:** the repository rows, and "N package repositories whose updates have stopped" in the description.
  An empty list says how many hosts' pending updates cannot be trusted.
- **Host page:** a notice above Pending patches ("Pending updates are unreliable (missing evidence)", with the reasons) and
  "0 pending — unreliable, not zero"; a Package repositories table (signature state, key, dates) for every enabled repository.
- **Patches page, dashboard card, hosts list:** hosts with an unreliable list are named, and the dashboard count is marked as a floor.
- **Policies:** "No pending patches" is `unknown`, not `pass`, for such a host.
- **CLI:** `defendsec-feeds match` prints `repos: N checked, M with a problem; pending updates: reliable|unreliable|unassessed`
  with the reasons, and takes `--stale-days`.

## What it does not see

- **What the host holds is the only evidence.** The agent cannot tell why apt has no index for a repository; it reports `no_index`
  and the verification result of whatever it could find.
- **A repository whose key had already expired when apt first fetched it has no index** on an http source: apt refuses the
  file and keeps no copy, so there is nothing to verify and the finding is `no_index` (still high), not `key_expired`. The
  fix text says an expired or untrusted key is the usual cause and that `apt-get update` names it. `key_expired` is what the
  host reports when apt once fetched the index with a valid key and the key expired afterwards (the 2026-10-22 sequence).
- **`update-success-stamp` is not a health signal.** On the lab host `apt-get update` exited 100 with an expired-key repository and
  still touched the stamp (VERIFIED.md), so a fresh stamp does not clear a repository: each one is verified on its own.
- **dnf and zypper:** key expiry and cached-metadata age only. `repo_gpgcheck` signatures on `repomd.xml` are not verified;
  per-package repository (`from_repo`) is not read.
- **Remote `gpgkey=` URLs** and repositories with `gpgcheck=0` are not checked (reported as such, not as findings).
- **Windows, macOS, sample hosts:** not applicable; the console shows no verdict.
- **Not run on a real RPM host with a bad key.** The RPM paths were exercised on a real Rocky 9 host with healthy repositories,
  and on fixtures with expired keys.
