# Datto RMM collector

Windows coverage with **nothing new installed on the PCs**. Every managed PC already runs the Datto
RMM agent, which records the OS, the installed software and the patch state. DefendSec reads that back
through Datto's read-only REST API and turns it into hosts and findings that rank in **Fix this week**
next to the agent-sourced ones. It is slice 8 of the [plan](DIRECTION.md).

## What it does and does not claim

| It does | It does not |
| --- | --- |
| Reads the OS caption, version and build of every Windows device in **one** RMM site | Run jobs, components, quick jobs, scripts; change a device, a UDF, a site or a key |
| Reads the audited software list (name, version) and shows it as inventory | **Match third-party applications to CVEs.** The RMM gives a name and a version with no publisher or package identity, so a browser or PDF reader CVE is **not assessed**. The console says so |
| Reads the updates RMM lists as **not installed** and maps each KB to the CVEs it fixes through Microsoft's Security Update Guide | See an update RMM does not list, or a KB outside the feed's window (12 months by default): counted, never guessed |
| Ranks a missing KB that fixes a **KEV-listed** CVE at the top of Fix this week, like any other KEV finding | Claim a device is patched because RMM's summary says `FullyPatched`: it shows RMM's summary as RMM's word, and findings come only from the per-KB list |
| Marks a device whose last audit is older than the threshold (default 7 days, 1-90) **not assessed, missing evidence**, keeps the findings it had, and never counts it clean | Treat "no findings" on a stale, never-audited or unreadable device as a pass |
| Flags Windows 10 (end of support 2025-10-14) and old Server builds through the Supported-OS policy | Cover macOS or Linux hosts RMM also knows: those devices are counted as "not Windows" and skipped |

## Mapping

- **One DefendSec instance = one RMM site.** The site UID is chosen in the console from the live site
  list (a typed UID that RMM does not list is refused). Changing the site retires the old site's devices.
- **One RMM device = one DefendSec host**, keyed `rmm-<deviceUid>`, with `devices.source = 'rmm'`.
  RMM rows live in Postgres only; apid never loads them into the agent store, so no agent code path
  (commands, isolation, heartbeat, the distro matcher) treats one as an enrolled agent.
- **Same machine reported by the DefendSec agent as well:** matched on the BIOS serial number when both
  sides have a real one, otherwise on the short host name (an agent with a *different* real serial is
  another machine with a reused name; two candidates are ambiguous, and an ambiguous match is no
  match). The RMM row is then left out of the host list and the host counts (`merged_into`), keeps its
  own findings, and the device page shows which source each fact came from.
- A device that leaves the site (or whose site is no longer the selected one) is **retired**: its row and findings stay as evidence but
  leave every list and count, as a revoked agent does. Nothing is closed as fixed because a device vanished.

## Findings

For every missing update that has a KB number and that the Microsoft feed knows, one finding per CVE
it fixes (kind `finding`, the same table agent findings use), so they flow into Fix this week, the
trendline and the exposure summary unchanged. `approved_pending` (the site's policy approved it and it
is waiting to install) is preferred over `not_approved` when RMM lists a KB twice. When a KB RMM listed
as missing is no longer listed, the collector reads the device's installed updates once more: if the KB
is there the finding closes as **fixed** (with that reason), if not it closes as no longer affected. Coverage per device is one of `covered`, `stale`, `no_data`, `no_feed`
(the Microsoft feed is not loaded: *not assessed*, never clean). The software list and the pending-update list of an audited device
are stored on the device's `rmm_devices` row and shown as inventory.

`defendsec-feeds` with `msrc` in `DEFENDSEC_FEEDS_ENABLED` (it is opt-in because the first sync is a few
hundred MB) loads [Microsoft's Security Update Guide](https://api.msrc.microsoft.com/cvrf/v3.0) as
ranges with distro `windows`, package `KB<digits>`; KEV and EPSS enrich them as for every other feed.
Digest, offline bundle and `feed_snapshots` work as for the other feeds.

## What was verified against the vendor, 2026-10-24

Checked against Datto's API help page
(<https://rmm.datto.com/help/en/Content/2SETUP/APIv2.htm>), its OpenAPI document
(`<API URL>/api/v3/api-docs/Datto-RMM`, mirrored at
<https://raw.githubusercontent.com/api-evangelist/datto/refs/heads/main/openapi/datto-v2-device-api-openapi.yml>),
Kaseya's announcement of the patch endpoints
(<https://www.kaseya.com/platform/innovations/datto-rmm-api-enhancements-patch-data-and-granular-access-controls/>)
and Microsoft's CVRF API. **Not** verified against a live Datto account: see "Not verified" below.

| Call | Purpose | Permissions Datto lists |
| --- | --- | --- |
| `POST <api>/auth/oauth/token` (password grant with the API key as username and the secret as password, public client `public-client`) | bearer token, refreshed when it expires | an API key and secret generated for a user |
| `GET /api/v2/account/sites` | the site picker | Setup > Global Settings: View, Sites > Sites: View |
| `GET /api/v2/site/{siteUid}/devices` | devices with `operatingSystem`, `lastSeen`, `lastAuditDate`, `online`, `patchManagement` summary | Sites > Sites: View, Sites > Devices: View |
| `GET /api/v2/audit/device/{deviceUid}` | OS version/build, BIOS serial | same |
| `GET /api/v2/audit/device/{deviceUid}/software` | installed software | same |
| `GET /api/v2/device/{deviceUid}/patches?installStatus=APPROVED_PENDING` and `NOT_APPROVED` | **per-KB** list of updates not installed (so the per-KB gap the card feared does not exist) | Sites > Sites: View, Sites > Devices: View |
| `GET /api/v2/system/request_rate`, `/api/v2/system/pagination` | quota and page size | Setup > Global Settings: View |

Facts the client is built on: responses return **at most 250 rows per page** and carry
`pageDetails.nextPageUrl`; query requests are limited to **600 in any 60 seconds**, counted across the whole account (every integration), with a one-second delay once 90% is used; tokens expire after 100 hours; persistent requests past the limit give a 403 and a temporary IP block (Datto says wait five minutes). The client paces
at 5 a second, honours `Retry-After` on a 429, gives up after a bounded
number of retries (two on a 429), and stops a run after three 403s in a row because Datto answers 403 to an address it
has blocked for ignoring 429. The API host is the platform's (`pinotage`, `merlot`, `concord`, `vidal`,
`zinfandel`, `syrah` `-api.centrastage.net`), and the client sends credentials only to a name of that
shape, never follows a redirect, and never follows a `nextPageUrl` that names another host. Also available
and **deliberately unused**: `GET /api/v2/site/{siteUid}/patches` (one call per site instead of one per device;
a cheaper later option once it has been run against a real account).

**Read-only, enforced:** `internal/rmm/datto` has no method for anything but `GET` (apart from the token
request) and a test (`TestClientHasNoWriteCalls`) fails if a request method, a path for jobs, components,
quick jobs, alerts, variables, UDFs, warranty, moving a device or resetting keys appears.

### Not verified

- **No call has been made to a real Datto RMM account.** Every Datto response in the tests is a scrubbed
  fixture shaped from the OpenAPI document (fake UIDs, `DEMO-*` host names). The real run is pending the
  API user (below). Field names, page behaviour and the real number of requests per device are
  fixture-proven only.
- Whether a security level limited to one site's device visibility can still call `/v2/account/sites`.
- Whether `NOT_APPROVED` lists every update Windows offers or only those RMM has catalogued.
- The mapping from `operatingSystem` captions to a Windows build uses the audit's build number; captions
  RMM writes differently from the fixtures fall back to "build unknown" (the console says so).

## Setup (for the administrator; Datto's own steps, checked on the pages above)

1. **Enable the API for the account.** An Administrator opens *Setup > Global Settings > Access Control*,
   turns on **Enable API Access** and saves.
2. **Create a read-only security level.** *Setup > Security Levels > Create Security Level*, named for example
   `DefendSec read-only`. Under *Device visibility* enable **Sites** and add **only the client site** DefendSec
   will read (this limits what the key can ever see). Under *Permissions* set **Sites > Sites: View**,
   **Sites > Devices: View** and **Setup > Global Settings: View** (the site list needs it); everything else
   None. Turn every remote control tool off.
3. **Create a dedicated API user.** *Setup > Users*, a new user that is not a person, with that security level
   and an API Component Level that gives it **no components**.
4. **Generate the keys.** Open the user and click **Generate API Keys**. Copy the **API Key**, the **API
   Secret Key** (hidden once you leave the page) and the **API URL** (`https://<platform>-api.centrastage.net`).
5. **Hand them over as files**, never in chat or a ticket: the key and the secret each in their own file, mode
   `0600`, readable only by the apid service account. Then set for apid
   `DEFENDSEC_RMM_API_URL`, `DEFENDSEC_RMM_KEY_FILE`, `DEFENDSEC_RMM_SECRET_FILE`. The files are re-read on every
   read, so rotating a key needs no restart. `internal/secret.ReadFile` refuses an empty or oversized file, a file
   with more than one token, or one writable by group/others, and never puts the value in an error.
6. In the console, **Datto RMM**: pick the site, then **Read now**. Reads then repeat every 6 hours
   (`DEFENDSEC_RMM_INTERVAL`, 1h-24h; `DEFENDSEC_RMM_SCHEDULE=off` disables it).
7. Add `msrc` to `DEFENDSEC_FEEDS_ENABLED` and run `defendsec-feeds sync` so missing updates can be mapped to CVEs.

**Revoke it later:** *Setup > Users*, the API user, regenerate or delete the keys (or deactivate the user);
delete the security level; turning off *Enable API Access* ends every API user's access. Remove the two files.

## Rate and cost

Per Windows device with a fresh audit the read costs one audit call, the software pages (250 per page) and
two patch calls (one per install status), about 4-6 requests; a device with a stale audit costs none beyond
the device list. A 100-PC site is a few hundred requests, a minute or two at the 5 a second pace, against the
account's 600 a minute. The count of each read is stored (`rmm_syncs.requests`) and shown on the page.

## API surface of DefendSec itself (admin port, token or admin session)

`GET /v1/rmm/status`, `GET /v1/rmm/sites`, `PUT /v1/rmm/settings` (admin; the site must be in the live
list), `POST /v1/rmm/sync` (admin; `{"wait":true}` to wait), `GET /v1/rmm/syncs`, `GET /v1/rmm/devices`,
`GET /v1/rmm/devices/{id}`. Choosing a site and asking for a read are written to the audit chain
(`rmm_site_select`, `rmm_sync`). The console proxies them at `/api/rmm/*`.

## Data kept

Migration 026: `devices.source`, `devices.merged_into`, `rmm_settings` (one row), `rmm_devices` (what RMM
said at the last read, with the software and pending-update lists), `rmm_patches` (the KB list),
`host_patch_state` (coverage per host and why), `rmm_syncs` (one row per read, with counts
and the reason for anything not assessed). No credential, no response body and no RMM token is stored. The
client site's name and the host names are client data: they live in the database and never in this repository.

## Screenshots (seeded demo data, not a client)

`docs/screenshots/rmm-page.png` (the Datto RMM page: what is not covered, devices, reads), `rmm-device.png` (one device: every
fact names its source, the KB list with KEV callouts, the software list marked inventory-only) and `rmm-fleet.png` (Fix this week
with Windows findings and the summary card). The data is a fixture Datto server (`DEMO-*` hosts, fake UIDs); the KB numbers were
swapped for two real KBs of the real Microsoft feed so that the KEV ranking is real.
