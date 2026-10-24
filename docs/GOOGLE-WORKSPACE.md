# Google Workspace identity posture (slice 13)

DefendSec reads what a client's Google Workspace domain says about **how easily its accounts could be taken over, and how mail could be hidden or
redirected once one is**. It is the counterpart of [M365.md](M365.md) and fills the same tables, the same Identity page area, the same finding kind
(`identity`) and the same ranking in **Fix this week**. It is read-only, agentless and per client instance: one DefendSec instance reads one domain,
through one service account the client's super administrator authorises.

Same lesson as slice 12: a mailbox filter that moves every QuickBooks/Intuit message out of the inbox hides a payment-redirection fraud from the owner. A
tool that only looks at hosts cannot see that.

## What it reads, and what it never reads

**Reads** (Admin SDK Directory API and Gmail API, all `GET`):

- the user list: id, primary address, name, aliases, whether the account is a super administrator or a delegated administrator, whether it is **enrolled
  in 2-Step Verification** and whether 2-Step Verification is **enforced** for it, suspended, archived, guest, whether its Gmail mailbox is set up, and its
  organisational unit path,
- for each mailbox that can be signed in: the **auto-forwarding setting** (on or off, the address, what Gmail does with the original) and the
  **definitions of its filters** (their criteria and their actions).

**Never reads**: a message. No body, no subject, no sender of any mail, no attachment, no thread, no label name. No sign-in log, no Drive, calendar or chat.
The Directory read asks for a fixed field list (`fields=...`) so phone numbers, addresses, recovery addresses and the like are not even requested. The Gmail
client has **no method that names a message**: `GmailSettings` accepts exactly two resources, `autoForwarding` and `filters`, and always for `users/me`
(the user the token acts as). `TestCollectOnlyReadsSettingsAndNeverTouchesAMessage` records every request of a full read and fails on any method other
than `GET`, on any path outside the users list and those two settings, and on any request that names a message.

The evidence stored with a finding is the filter's criteria and actions, the forwarding setting, or the enrolment flags. A filter's criteria (for
instance `from: noreply@intuit.com`, `subject: invoice`) are part of the filter, not of any message.

The only non-`GET` request is the OAuth token request. `internal/gws/google` has no method that creates, updates or deletes anything.

## The checks

Findings are of kind `identity`, provider `google`. A check group is **assessed** or **not assessed** as a whole. A group that could not run (a scope not
delegated, an API not enabled, a throttle that did not clear) produces no finding and resolves none: missing evidence is not a pass and not a failure.
The groups reuse slice 12's ids (`mfa`, `admin-roles`, `inbox-rules`), with Google's labels; there is no `legacy-auth` group.

| Group | Finding | Severity | Meaning |
| --- | --- | --- | --- |
| 2-Step Verification (`mfa`) | `2sv.not_enrolled` | **critical** super administrator, **high** delegated administrator, **medium** any other user | The account is not enrolled in 2-Step Verification. Suspended and archived users cannot sign in and guests sign in elsewhere: they are left out and counted. |
| | `2sv.not_enforced` (one per domain) | **high** if an administrator is not covered by enforcement, **medium** if a not-enrolled user is not, **low** if everyone not covered is at least enrolled | `isEnforcedIn2Sv` is false for some active user. Enrolled is not enforced: an enrolled user can turn it off again. |
| Super administrators (`admin-roles`) | `roles.super_admin_count` | medium | More active super administrators than the limit (default 4, 1 to 50, set on the Identity page). Google names no maximum, so the number is DefendSec's judgement. |
| | `roles.single_super_admin` | low | Exactly one. Google advises more than one so the domain survives a lost account. A resilience finding, not an exposure. |
| Gmail forwarding and filters (`inbox-rules`) | `gmail.autoforward_external` | **high**; **critical** if Gmail also archives, trashes or marks the original read | Auto-forwarding is on, to an address outside the domain's names and the trusted domains. |
| | `gmail.filter_forward_external` | **high**; **critical** if the filter also hides the mail or its criteria match finance words | A filter's `forward` action goes to an address outside. |
| | `gmail.filter_hides_mail` | **critical** if the criteria match finance words (invoice, payment, remittance, wire, ACH, bank, QuickBooks, Intuit, payroll, bill.com, purchase order, direct deposit, plus the operator's own); **high** if they match security-notice words (security alert, password, verification code, sign-in, suspicious, unusual activity) or the filter has no criterion and trashes, spams or skips everything; **medium** otherwise | A filter adds `TRASH` or `SPAM`, removes `UNREAD` (marks read) or removes `INBOX` (skips the inbox). |

**Severity of a super administrator without 2-Step Verification.** The card said "admins high, users medium". It says `critical` here for a *super*
administrator and `high` for a delegated one, because slice 12 ranks a Global Administrator without MFA critical and this slice reuses slice 12's ranking.
A super administrator controls the whole domain exactly as a Global Administrator does. This is a judgement; it is one line in `CheckTwoStep`.

One finding per filter: a filter that forwards outside *and* hides is one finding, worded and ranked for both. Words match **whole words**,
case-insensitively (`ach` matches "ACH payment", not "reach"), exactly as in slice 12 (`internal/idposture`). A filter is not a verdict: the detail says
"worth a question to the owner", filing filters are normal, and the fix text starts with "ask the mailbox owner whether they made this filter".

### Where the judgement calls are

- **Filing is not hiding.** Gmail's "Skip the Inbox" together with a label of the user's own (`Label_17`) is how people file newsletters. DefendSec does
  not read label names (that needs another call), so it cannot tell a label that files from a label that hides. A filter that does *only* that is not
  reported, unless its criteria match finance words, and then at **high**, not critical. Skip-inbox with no label of the user's own, or with a mark-as-read, a
  move to Trash or to Spam, is a hiding action. The category labels (`CATEGORY_UPDATES`) and `STARRED`/`IMPORTANT` are not user labels.
- **Internal domains** are the domains of the *non-guest* users' primary addresses and aliases, plus the operator's trusted domains. A guest's address is
  never internal. A domain on the account that no user has an address in will look "outside" until it is added as trusted.
- **A filter's `query`** is Gmail search syntax over the words of a message; the words in it are what the filter acts on, so they are read as keywords
  (`subject or body keyword`). Operators in it (`from:`, `has:attachment`) are not parsed.
- **Auto-forwarding to the same domain, to an alias domain, or to a trusted domain** is not reported.
- **Gmail's label ids** are `INBOX`, `TRASH`, `SPAM`, `UNREAD`, `STARRED`, `IMPORTANT`, `SENT`, `DRAFT`, `CHAT` and `CATEGORY_*`. "Skip the inbox" is
  `removeLabelIds: INBOX`, "Mark as read" is `removeLabelIds: UNREAD`, "Delete it" is `addLabelIds: TRASH`. These are the documented system label ids; the
  mapping of the Gmail settings screen to them is from the Gmail API's filter guide and **not yet seen on a real mailbox**.

## What is not assessed (said on every screen)

- **The domain's email routing**: Gmail routing and compliance rules, and the Admin console's automatic-forwarding policy. Admin console settings the two
  APIs do not expose. A domain that forwards or copies mail by a routing rule would not show here, and DefendSec cannot say whether the domain allows users
  to set automatic forwarding at all.
- **Mailbox delegation** (another user allowed to read or send as a mailbox). Gmail's delegates list needs the `gmail.settings.sharing` scope, which can also
  grant access, so it is not requested.
- Which 2-Step Verification **methods** a user has, and whether a sign-in is phishing-resistant. The Directory API gives two booleans.
- What a **delegated administrator** may do, and roles held through a group. Only the two flags are read; the role assignments API needs
  `admin.directory.rolemanagement.readonly`, which is not requested.
- **Third-party app access** (OAuth grants), app passwords and sign-in risk: other APIs, further scopes.
- **Users the administrator account used for the read cannot see.** A super administrator sees all of them; a delegated administrator limited to some
  organisational units sees only those. When the list shows **no** super administrator at all, the administrators check says so and is not assessed.
- **Filters and forwarding in mailboxes that cannot be acted as**: suspended or archived users, users without a Gmail licence, collaborative inboxes. Counted.
- Per read: a mailbox Google refused (counted, and its findings are neither confirmed nor cleared), and mailboxes past the per-read limit of 2,000
  (counted as skipped, with the same protection).

## Google endpoints and scopes (verified)

Checked against Google's reference pages on **2026-10-24** (each page's own "last updated" date is given). Every scope is the narrowest one Google lists for
the call that is read-only for the call.

| Read | Endpoint | Scope (one of the listed ones) | Source |
| --- | --- | --- | --- |
| Users, 2-Step Verification state, administrator flags | `GET https://admin.googleapis.com/admin/directory/v1/users` (`customer=my_customer`, `maxResults=500`, `viewType=admin_view`, `projection=basic`, a `fields` mask, `pageToken`) | `admin.directory.user.readonly` (the page lists `admin.directory.user`, `admin.directory.user.readonly` and `cloud-platform`) | https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list (updated 2026-03-10) and https://developers.google.com/workspace/admin/directory/reference/rest/v1/users (updated 2026-06-03): `isAdmin` "super administrator privileges", `isDelegatedAdmin`, `isEnrolledIn2Sv`, `isEnforcedIn2Sv`, `suspended`, `archived`, `isMailboxSetup` "only applicable if the user has been assigned a Gmail licence", `isGuestUser`, `orgUnitPath`, `aliases` |
| Auto-forwarding | `GET https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding` | `gmail.readonly` (the page lists `gmail.settings.basic`, `mail.google.com`, `gmail.modify`, `gmail.readonly`) | https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings/getAutoForwarding (updated 2026-04-15); fields `enabled`, `emailAddress`, `disposition` (`leaveInInbox`, `archive`, `trash`, `markRead`): https://developers.google.com/workspace/gmail/api/reference/rest/v1/AutoForwarding (updated 2025-03-24) |
| Filters | `GET https://gmail.googleapis.com/gmail/v1/users/me/settings/filters` | the same four | https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.filters/list (updated 2026-04-15); criteria `from`, `to`, `subject`, `query`, `negatedQuery`, `hasAttachment`, `excludeChats`, `size`; actions `addLabelIds`, `removeLabelIds`, `forward`: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.filters (updated 2026-05-13) |

**The final minimal set is two scopes** (and a choice for the Gmail one):

1. `https://www.googleapis.com/auth/admin.directory.user.readonly`
2. one of `https://www.googleapis.com/auth/gmail.readonly` (**default**) or `https://www.googleapis.com/auth/gmail.settings.basic`

**Why the Gmail scope is a choice, and why `gmail.readonly` is the default.** Gmail's settings reads accept four scopes. Two are broad (`mail.google.com`,
`gmail.modify`) and are not used. That leaves:

| | can read a message | can change settings (forwarding, filters) |
| --- | --- | --- |
| `gmail.readonly` | **yes** | no |
| `gmail.settings.basic` | no | **yes** |

The brief for this slice is "read-only scopes only", and `gmail.readonly` is the only read-only scope the settings calls accept, so it is the default. It
has a cost that the status page and the setup guide say plainly: a service account key with domain-wide delegation of `gmail.readonly` can read **every
mailbox's mail**, not just settings, if the key leaks. DefendSec has no call that names a message (and a test enforces it), but the *scope* is what a thief
holds. `gmail.settings.basic` cannot read a message, but a thief could add a forwarding address or a filter to a mailbox (the API refuses an external
forwarding address that the owner has not verified, but the thief owns that address). DefendSec only makes `GET` requests either way. **Which risk a client
prefers is Mason's call, not the code's**; the Identity page has the choice (`gmailScope`: `readonly` or `settings.basic`), and whatever is chosen is what must
be delegated. Delegate one, not both.

Sign-in with a service account (https://developers.google.com/identity/protocols/oauth2/service-account, updated 2026-03-23): a JWT with header `alg RS256`,
`typ JWT`, optional `kid`; claims `iss` (the service account's email), `sub` (the user to act as), `scope` (space separated), `aud`
(`https://oauth2.googleapis.com/token`), `iat`, `exp` (at most one hour after `iat`); posted as `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
and `assertion`. DefendSec signs RS256, uses `iat` one minute in the past and `exp` 50 minutes ahead, always posts to Google's token endpoint, and does
**not** use the `token_uri` in the key file (a key file must not be able to point the signed assertion somewhere else). A token is cached per
(user, scope). The token request for the Directory read acts as the administrator; each mailbox read acts as that mailbox's owner, so a read can only
be of that mailbox (`users/me`).

## Throttling, errors and failing closed

`internal/gws/google` classifies every failure and the collector turns each into a stated result, never into "clean":

| Answer | What happens |
| --- | --- |
| Token request refused, `invalid_grant` (a key Google does not know or has deleted, a clock too far off, a deleted account) | Nothing is read. Every check is *not assessed* with Google's code and first line; the run is recorded as `not_assessed`; no finding is resolved. The key never appears in the message. |
| Token request refused, `invalid_grant` "Not a valid email or user ID" for the **administrator** | Same: the administrator address is not a user the service account can act as. |
| `unauthorized_client`, `access_denied`, `admin_policy_enforced`, `invalid_scope` on a token request | Domain-wide delegation is missing for that scope (or was added minutes ago; propagation can take up to 24 hours): the check that needed the scope is *not assessed*, with the hint to use the service account's **numeric client ID**. A missing Gmail delegation stops the mailbox reads at once instead of asking once per user. |
| `invalid_grant` for one **mailbox owner** | That mailbox is unreadable (counted; its findings are neither confirmed nor cleared). The rest are read. |
| `401` from an API | A new token is fetched once and the request retried; a second `401` is fatal like a refused token. |
| `403` `accessNotConfigured` | The API (Admin SDK or Gmail) is not enabled in the service account's Google Cloud project: said as such. For Gmail the whole mailbox read stops; for the Directory read nothing can be assessed. |
| `403` `domainPolicy` | The domain's administrators have disabled the API for apps. |
| Other `403` | Not retried. The check is *not assessed*, with the privilege or scope to check. One mailbox answering `403` leaves the rest assessed and that mailbox unread. |
| `403` `rateLimitExceeded`, `userRateLimitExceeded`, `quotaExceeded`; `429` | Retried with backoff (1, 2, 4, 8 s, up to 5 attempts; Google's advice is up to about 32 s) and `Retry-After` honoured up to 60 s a wait. A longer ask, or a throttle that does not clear, is reported as throttled and the check is *not assessed*. `dailyLimitExceeded` is not retried. Google reports rate limits as 403, which is why a 403 is not simply "forbidden". |
| `400` `failedPrecondition` ("Mail service not enabled"), `404` on a mailbox | The user has no Gmail mailbox: counted as no mailbox, not an error. (**Not verified against a real domain**: the 400 for a user without a Gmail licence is from experience, not from the reference page.) |
| `5xx`, network errors | Retried with backoff, then reported. |
| A redirect | Never followed: the bearer token goes only to Google's hosts. |

A run has a budget of 50,000 requests, 4 mailboxes read at a time, 2,000 mailboxes per run and a 30-minute timeout. A mailbox the loop never reached (the
read ran out of time) is counted as skipped and protected like one past the limit. A read costs 2 requests plus one token request per mailbox, so a
2,000-mailbox domain is about 4,000 API requests per read; the Directory API is read at 500 users a page (the documented maximum). Gmail's per-user rate
limits (its "usage limits" page) were **not** read for this slice, and a read of that size has never been run: the throttling rows above are what protect a
slow or busy domain.

## Credentials: a file, never the API

The service account's key is a JSON file, read through the same mechanism as the other credentials (`internal/secret`): a **file** named in apid's
environment, read each time apid reads the domain, so rotating the key is replacing a file. Nothing secret is typed into the console, stored in a settings
table, logged or returned by the API.

| Environment variable | Content |
| --- | --- |
| `DEFENDSEC_GWS_KEY_FILE` | The service account's JSON key file, as Google issues it (`type: service_account`, an RSA `private_key`). Mode 0600; a group- or world-writable file is refused, a group- or world-readable one is warned about. 16 KB at most. |
| `DEFENDSEC_GWS_SCHEDULE=off` | Switches the automatic reads off. |
| `DEFENDSEC_GWS_INTERVAL` | How often to read: 1h to 24h, default 6h. |

The status page shows the service account's email, its **numeric client ID** (the one the Admin console's delegation entry must carry), the key id and
the project, so an administrator can compare them with the two consoles. It never shows the key. A key file is a standing credential: the status page
says so, and says what to do about it (0600, rotate, delete the key in the Cloud console if the server is ever in doubt).

The administrator's address, the Gmail scope choice, the super administrator limit, the trusted domains and the extra finance words are not secrets and
are saved in the settings (`gws_settings`, migration 031), changed only by an administrator, with an `identity_settings_changed` entry in the hash-chained
audit ledger (same transaction).

## Setting it up, click by click

The same steps are in the console, on **Identity > Google Workspace**, under *Connect a Google Workspace domain*. Steps 1 to 4 are done once per service
account; an MSP can use **one project and one service account for every client**, each client's super administrator doing step 5 for it (the key then
protects every client, so it needs the care of a master credential).

1. Open **console.cloud.google.com**, signed in with a Google account that may create projects, and create a project (*DefendSec read-only*).
2. **APIs & Services > Library:** find **Admin SDK API**, **Enable**. Find **Gmail API**, **Enable**.
3. **IAM & Admin > Service accounts > Create service account.** Name *defendsec-readonly*; skip the optional role and user steps; **Done**. Open it and copy
   its numeric **Unique ID** (the OAuth client ID).
4. On its **Keys** tab: **Add key > Create new key > JSON > Create.** A file downloads once. Put it on the DefendSec server, `chmod 600`, set
   `DEFENDSEC_GWS_KEY_FILE` for apid to its path, restart apid. (If Google refuses to create a key, an organisation policy blocks service account keys.)
5. In **admin.google.com**, as a **super administrator** of the client's domain: **Security > Access and data control > API controls > Manage domain-wide
   delegation > Add new.** Client ID: the numeric ID from step 3 (not the email: Google rejects that, see the table above). OAuth scopes:
   `https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/gmail.readonly` (or `gmail.settings.basic` in place of
   `gmail.readonly`, if you chose it). **Authorize.** (This path is Google's own text on the service account page quoted above. Propagation usually takes
   minutes and can take up to 24 hours.)
6. In the console: **Identity > Google Workspace.** Enter a **super administrator's** email address as the administrator to act as (ideally a dedicated
   super administrator with 2-Step Verification), choose the Gmail scope you delegated, **Connect this domain**, then **Read the domain now**.
7. To revoke: delete the delegation entry in the Admin console (**Manage domain-wide delegation**, the entry, **Delete**), and delete the key or the service
   account in the Cloud console. Deleting the file on the server stops DefendSec from signing in at all.

The Admin console menu paths for turning 2-Step Verification **enforcement** on (named in the fix text of `2sv.not_enforced`: *Security > Authentication >
2-step verification*) and for admin roles (*Account > Admin roles*) are from memory of the current console and **not verified in this slice**; the
fix text names them as places to look, not as exact clicks.

## API (apid admin API)

| Route | Who | |
| --- | --- | --- |
| `GET /v1/identity/google/status` | viewer | settings, credential state (service account, client id, key id, project; no key), summary for Google only, latest run, what is not assessed, the scope list, the check labels |
| `PUT /v1/identity/google/settings` | admin | `adminEmail`, `gmailScope`, `superAdminMax`, `trustedDomains`, `financeTerms`; unknown fields are refused, so a pasted key is a `400` |
| `POST /v1/identity/google/sync` | admin | `{wait?}`: `202` and a background read, or `200` with the run; `409` if one is running |
| `GET /v1/identity/findings?provider=google&resolved=1&check=` | viewer | every provider's findings when `provider` is absent |
| `GET /v1/identity/runs?provider=google&limit=` | viewer | Microsoft 365's when `provider` is absent |
| `GET /v1/exposure/advisory?id=identity:<12 digits>` | viewer | the drawer of an identity row (either provider) |

Every settings change, manual read and recorded run is in the audit ledger (`identity_settings_changed`, `identity_sync`, `identity_run_recorded`); a run
and its ledger entry commit in one transaction. `GET /v1/identity/status` (Microsoft 365) now counts only Microsoft 365's findings; the exposure summary and
the Fleet card count both providers.

## What it does not prove

- Findings are **not yet in the signed evidence export** (`defendsec-verify`); the ledger chains each run, not the findings (slice 7c, as for slice 12).
- "Enrolled" is not "phishing-resistant", and "enforced" is the setting, not the sign-in. "Not found" for a filter means not found in the filters the
  Gmail API returns for the mailboxes that could be read, not that the domain is clean.
- Reachable is not compromised. A finding says a condition is true of the domain's configuration; it is evidence to act on, not proof that anyone abused it.
- **No real Google Workspace domain has been read.** Everything above is tested against a fake Google (token endpoint that verifies the RS256 signature,
  Directory and Gmail routes) whose shapes are the reference pages' field names; see `docs/VERIFIED.md`.
