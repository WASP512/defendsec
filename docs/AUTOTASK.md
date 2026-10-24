# Autotask tickets from Fix this week (slice 14)

DefendSec turns the **Fix this week** list into tickets in the Autotask queue a client's technicians already work from. It is built so that a re-run
never opens a second ticket for the same thing, so a person can read exactly what it will send before it sends anything, and so every ticket action is
in the hash-chained audit log.

One DefendSec instance maps to **one Autotask company**, chosen by id on the Autotask page. Nothing about the client's taxonomy is a default in code:
the queue, status, priorities, source, issue type, sub-issue type and note type are all **picklist values read live from Autotask** and chosen by the
operator. This is the only integration of DefendSec that can write to another system, and it is dry-run first by construction.

## What becomes a ticket

One ticket per **remediation action**, never one per CVE and host. An action is what a technician does in one sitting.

| Source | One ticket is | Example title |
| --- | --- | --- |
| Vulnerabilities (fixable only) | one package family (the source package the matcher groups by), on every host with an open fix for it | `Update openssl on 4 hosts` |
| End-of-life software | one release of one product, on every host that runs it | `Upgrade PHP 8.0, past end of security support, on 2 hosts` |
| External surface | one finding id across the assets it affects; **an open port, a dangling name and a DKIM selector are per subject** (closing 445 is not closing 3389) | `DMARC policy is p=none (and 2 other assets)` |
| Identity | `mfa.not_registered` is one ticket for every account; **every other identity finding is its own ticket** (a rule that hides payment mail must not sit in a list) | `Register MFA for 12 accounts` |

The unfixed and awaiting-vendor findings (the watch list), informational findings and `info` surface findings are never ticketed.

**Urgency** of an action is that of its most urgent member:

- vulnerabilities: **critical** if any advisory is on the CISA KEV list; **high** if any has EPSS ≥ 0.10, CVSS ≥ 7.0 or a vendor severity of high or critical;
  **medium** if any is medium or has CVSS ≥ 4.0; low otherwise;
- end-of-life: past end of security support is high, past end of active support only is low;
- surface and identity: their own severity.

The operator sets the lowest urgency that **opens** a ticket (critical, high or medium; default **high**; low is never ticketed). An action that already
has a ticket is followed whatever its urgency does later. Critical, high and medium each map to a priority picklist value the operator chooses.
**These cut-offs are a judgement**, not measured against a real client list.

## The ticket

- **Title**: the action, then the tag, `Update openssl on 4 hosts [DS-3f9a1c0b2e]`. The title says how many hosts there were when the ticket was opened; notes keep it current.
- **Description** (plain text; Autotask's rich text is not used): what, why it ranks (KEV, EPSS, CVSS as they are, never a number that does not exist), who is
  affected (one line per host with installed and fixed versions and the advisories), the fix-it text (the package manager's command per host family), a link to
  Fix this week if the console address is set, and the key footer. It is cut to the field's limit (read live, 8,000 characters in the fixture) by counting the
  hosts it left out; **the footer with the key is never cut**.
- **Fields**: company, status, priority (by urgency), queue, source, issue type and sub-issue type (the last four optional), and a due date (days per urgency,
  default 2, 7 and 14), because Autotask requires `dueDateTime` unless the ticket category sets one.

## Idempotency: the key is on both sides

- **DefendSec side**: `autotask_tickets`, one row per action and *generation*, holding the Autotask ticket id and the tag. Every run reads it first.
- **Autotask side**: the tag in the ticket's **title** and a footer line in the description. The title is used because it is searchable with `contains`.
  The ticket's *External ID* fields are deliberately not used: Autotask's best-practice guide asks integrations to leave them to the customer.
- Before every create the run searches the company's tickets for the tag. A ticket that already carries it is **adopted**, not duplicated. That covers the
  one dangerous gap, a crash or a lost answer between "the ticket was created" and "DefendSec recorded it". A 5xx or a timeout on a create is never retried
  blindly: the error says the ticket may exist and the next run looks it up by its tag.
- A new **generation** (own tag) is opened only when the earlier ticket was completed in Autotask and the action needs a ticket again.

## Lifecycle

| What DefendSec sees | What it does |
| --- | --- |
| a new host, advisory or account in an action that has an open ticket | one **note** on that ticket ("New since this ticket was opened"), once |
| more advisories on a host already in the ticket | a note ("What is open changed on") |
| a host or finding fixed | a note with the **evidence from DefendSec's own record**: `web-01: openssl 3.0.2 observed, at or above the fixed version 3.0.2-0ubuntu1.19 at 2026-10-25 09:30 UTC (2 findings closed)`; a package removed or a feed reclassifying it is said as exactly that, and a host or asset that was removed is "no longer reported (…how it closed is not on record)" |
| everything of an action fixed | a final note; the ticket is **left open** (auto-complete is **off by default**) |
| auto-complete on, everything fixed | the note, then the status the operator named as "completed". If the completion fails it is retried without a second note |
| urgency rises (the advisory is now on KEV) | a note saying so; **the ticket's priority is not changed** |
| findings return after being resolved | a note on the old ticket if it is still open; a **new ticket** if it was completed |
| a technician completed the ticket while findings are open | **left alone**: no reopening, no second ticket, no note; flagged "needs a look". A new host or finding that the closed ticket never covered gets a new ticket |
| the ticket was deleted in Autotask | not recreated; flagged |

DefendSec never changes a priority, a queue, an assignee or any field of an existing ticket. The only change it makes to a ticket is its status, to complete it,
and only if the operator switched auto-complete on.

## Safety

- **Dry run is the default and changes nothing.** It reads (the hourly threshold, the company, the live picklists, the tickets it follows, one tag search per
  planned create) and sends no create, no note and no update; a test asserts the only POST it makes is a query. It lists the **exact** ticket (payload and
  description) and every note it would add. With no credentials it still shows the tickets, marked *not read from Autotask*.
- **Going live needs a dry run behind it.** Each settings value that decides where a ticket goes or what it says is part of a *fingerprint*. Saving mode
  `live`, and every live run, require the newest dry run that **read Autotask and found no problem** to have the same fingerprint. Change the company, queue,
  a priority, the threshold or anything else and live waits for a new dry run. Saving changes while live switches back to dry-run mode.
- A live run also needs the settings in live mode (`POST /v1/autotask/run` answers 409 otherwise), the credentials, and at most **10 new tickets per run**
  by default (1 to 50). The rest wait for the next run, so a first run does not flood a queue.
- **The schedule** (every 6 hours; `DEFENDSEC_AUTOTASK_INTERVAL` 1h to 24h, `DEFENDSEC_AUTOTASK_SCHEDULE=off` disables) acts **only on an instance whose
  settings are in live mode**. A dry-run instance is never touched by it.
- **Fail closed.** Settings that are incomplete, a picklist value that is no longer active or a sub-issue type that does not belong to the issue type, a
  company that is not active, refused credentials, the hour's request count at half of Autotask's threshold, a spent request budget: each stops a live run
  with the reason in the run's history. Nothing it could not check is assumed fine.
- **Credentials are files, never typed or stored.** `DEFENDSEC_AUTOTASK_SECRET_FILE` (the API user's secret) and `DEFENDSEC_AUTOTASK_CODE_FILE` (the integration
  code), each one value, mode 0600 (a file writable by group or others is refused, one readable by them gets a warning on the page), read each time apid talks to Autotask. The API only accepts the user's
  *name* and the company id; a pasted `secret` is a `400`. The credentials are sent only to an `https://*.autotask.net/atservicesrest` URL: a zone URL typed in
  or returned by zone discovery is checked first, `client.New` refuses any other host itself, and the client never follows a redirect (a 3xx is an error; Go would
  otherwise carry the `UserName`, `Secret` and `ApiIntegrationCode` headers to the new host and replay a POST body). No error, log line, ledger entry or status holds a value.
- **Audit ledger.** `autotask_settings_changed`, `autotask_sync` (who asked for a run), `autotask_dry_run`, `autotask_run`, and for every ticket action
  `autotask_ticket_created`, `autotask_ticket_adopted`, `autotask_ticket_note_added`, `autotask_ticket_completed`, `autotask_ticket_state`, each written in
  the same transaction as the row it changes (a refused commit leaves no entry). The text of a dry run's tickets is in the run record, not in the chain.
- **Rate limits.** Requests are sent **one at a time** (Autotask allows three threads per endpoint), counted against a per-run budget (300), and a 429 waits for its `Retry-After` (up to 60 s,
  then the run stops).

## The Autotask REST API facts this relies on

Checked against Datto/Kaseya's developer help on **2026-10-24** (`https://autotask.net/help/developerhelp/Content/APIs/REST/…`). A fake service (`internal/autotask/atest`)
implements exactly these; **none of it has been observed against a real Autotask database yet**.

| Fact | Source page |
| --- | --- |
| Credentials are three request headers of an **API User (API-only)**: `UserName`, `Secret`, `ApiIntegrationCode` (the "tracking identifier"; for an internal integration, a *Custom (Internal Integration)* identifier). 401 on failure. Content type JSON | `General_Topics/REST_Security_Auth.htm` |
| Zone discovery: `GET https://webservices.autotask.net/atservicesrest/v1.0/zoneInformation?user=<api user>` → `{zoneName, url, webUrl, ci}`; needs no authentication; the zone URLs are `https://webservices<N>.autotask.net/atservicesrest` (also `prde`, `pres`) | `API_Calls/REST_ZoneInformation.htm`, `General/API_Zones.htm` |
| **10,000 requests per hour per database**, across every integration; latency of 0.5 s from 50 % and 1 s from 75 %; `GET /v1.0/ThresholdInformation` → `{externalRequestThreshold, requestThresholdTimeframe, currentTimeframeRequestCount}`; 5-minute execution timeout; queries return at most 500 records, ids ascending | `General_Topics/REST_Thresholds_Limits.htm` |
| **Thread limit**: three simultaneous threads per tracking identifier and object endpoint for integrations built after 2023.1; a fourth gets **429**. "Serialize your requests" | `General/ThreadLimiting.htm`, `General_Topics/REST_BestPractices.htm` |
| Query: `POST /v1.0/<Entity>/query` with `{"filter":[{op,field,value}], "IncludeFields":[…], "MaxRecords":n}`; ops `eq noteq gt gte lt lte beginsWith endsWith contains exist notExist in notIn`; top-level filters are ANDed; at most 500 OR conditions; response `{items, pageDetails}` | `API_Calls/REST_Basic_Query_Calls.htm`, `REST_Advanced_Query_Features.htm` |
| Create: `POST /v1.0/Tickets` → `{"itemId": n}`; update: `PATCH /v1.0/Tickets` with the id and only the fields to change; any non-200 is an error; a rule violation answers 500 with `{"errors":[…]}` | `API_Calls/REST_Creating_Resources_POST.htm`, `REST_Updating_Data_PATCH.htm` |
| `GET /v1.0/<Entity>/entityInformation/fields` → `fields[]` with `isRequired`, `isPickList`, `picklistValues[] {value, label, isDefaultValue, sortOrder, parentValue, isActive, isSystem}`, `picklistParentValueField` (a sub-issue type's parent is the issue type) | `API_Calls/REST_EntityInformationCall.htm`, `General/Picklists.htm` |
| Tickets: `title` ≤ 255, `description` ≤ 8000, `externalID` ≤ 50; `dueDateTime` required unless the ticket category has both date and time configured; `queueID` required by the category's "Queue is Required" setting; `issueType`/`subIssueType` never required by the API, and a sub-issue type needs its issue type; `priority` must be active on create; the API ignores the category's other required and list settings | `Entities/TicketsEntity.htm` |
| TicketNotes: a child of Tickets; `description` ≤ 32000, `title` ≤ 250, `noteType` and `publish` pick lists | `Entities/TicketNotesEntity.htm` |
| Companies: `GET /v1.0/Companies/{id}`, queryable by `companyName`, `isActive` | `Entities/CompaniesEntity.htm` |
| Datetimes are UTC, `yyyy-mm-ddThh:mm:ss.ms` | `API_Calls/REST_API_Calls.htm` |
| Integrations should not fill the *External* fields with generated data and should set `Ticket.Source` to identify their tickets | `General_Topics/REST_BestPractices.htm` |

**Verified only by reading, not by the page text I could extract:** the *child* path for a ticket note, `POST /v1.0/Tickets/{id}/Notes`. The help site's
"Finding resource and child access URLs" page says child collections have their own URLs and are listed in Swagger, which needs an authenticated session;
the path used is the documented convention (`GET atservicesrest/v1.0/ContactGroups/3/Contacts/`) applied to Tickets, and it is **the first thing to check
in the real run**. The fake service accepts the same path, so passing tests do not prove it.

Also not read from a page: which picklist field is `isRequired` on a given database (the code reads it live, and an operator-chosen value that Autotask refuses
comes back as a rejected create with Autotask's own words), and whether `completedDate` is exposed as queryable (it is read with `IncludeFields`, so it
only has to be returned).

## Endpoints (apid)

`GET /v1/autotask/status`, `PUT /v1/autotask/settings`, `GET /v1/autotask/picklists`, `GET /v1/autotask/companies?q=`, `POST /v1/autotask/run {dryRun?, wait?}`
(dry run unless `"dryRun": false`), `GET /v1/autotask/runs`, `GET /v1/autotask/runs/<id>`, `GET /v1/autotask/tickets`. Admins write; viewers read. Picklists and
company search are admin-only because they spend requests.

## Setup guide for the administrator (what the real run needs)

1. In Autotask: **Admin → Resources/Users (HR) → Resources/Users → New**. Name it like an email address, for example `defendsec-api@<your domain>`. On the
   **Security** tab choose the security level **API User (system)** (API-only). **Better**: copy that level and, in the copy, restrict it to Tickets, Ticket
   Notes and Companies, because the standard level is full administrator access (the REST security page says so). Do not let its password expire: an API
   user cannot change it and the integration would stop.
2. On the same tab, under **API Tracking Identifier**, choose **Custom (Internal Integration)**. The code that appears is the integration code. A user with
   the HR security level can see it later.
3. Put the user's password in one file and the integration code in another on the DefendSec server, one line each, `chmod 600`, and give apid
   `DEFENDSEC_AUTOTASK_SECRET_FILE` and `DEFENDSEC_AUTOTASK_CODE_FILE`. **Never type either into a chat or a page.**
4. Create a **test company** (or pick an internal one) and a **test queue** (**Admin → Features & Settings → Service Desk → Queues**). If you can, add a
   **Source** named *DefendSec* (same place, Sources), so technicians can tell the tickets apart and a workflow rule can route them.
5. Open **Autotask** in the DefendSec console. Enter the API user's name, search for the company and pick it, wait for the lists to load, choose the queue,
   the status of a new ticket, a priority for critical, high and medium, optionally the source, issue type and sub-issue type (the issue type is where a
   security ticket belongs in your own taxonomy, for example *Cybersecurity & Cloud*), the note type and who may see a note (internal is the careful
   choice: a note names hosts). Save.
6. **Show me the tickets (dry run)**. Read them. Nothing has been sent. When they are right, **Go live**. Only that company and that queue are ever written to.
7. To stop: *Stop opening tickets* on the page, or deactivate the API user in Autotask. To remove DefendSec's access completely, delete the two files.

## What is not done in this slice

- No webhook or two-way sync: DefendSec learns that a ticket was completed by asking Autotask on its next run, not by being told.
- No attachment, no time entry, no ticket charge, no contact or configuration-item link, no impersonation (tickets are created by the API user).
- No mapping of a host to an Autotask configuration item: the host names are in the ticket text.
- Windows hosts known only through the Datto RMM collector are ticketed by the same rules as any host with fixable findings; their fix-it text is the generic
  "install the vendor's update" because no package manager is known.
- A ticket's title is not rewritten when the host count changes; the notes are.
- A surface finding whose last observation was *not assessed* (the exposure view flags it as stale) is still ticketed from the older data: the candidate list does
  not read that flag. It is resolved, and noted on the ticket, only when a later observation shows it fixed.
- An MFA ticket takes the priority of its most urgent member, so one critical Global Admin and several medium accounts open one ticket at the critical priority.
  Splitting the administrators into their own ticket is not done.
- A note is not idempotent. If Autotask carries out a note but the answer is lost, the run says so and the next run may add the same news a second time (a ticket
  is protected by its tag; a note has none). A note is never retried within a run.
