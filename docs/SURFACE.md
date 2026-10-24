# External surface scanner

What does the internet see of this client? The scanner answers that from DNS, TLS handshakes, one
HTTPS fetch of an MTA-STS policy and TCP connects, without installing anything on any host. It is
slice 7a of the [plan](DIRECTION.md); wiring its findings into the ranked weekly list and the
trendline is slice 7b.

## Rules it keeps

- **Declared assets only.** An operator declares domains, public hostnames and IP addresses on the
  **Assets** page, and each needs an "I am authorised to test this asset" confirmation (who, and
  when, is stored). The scanner refuses an unconfirmed asset, the API refuses to start a scan of one,
  the database refuses to record one, and withdrawing the confirmation stops scanning at once.
  Nothing discovered, resolved-but-undeclared or adjacent is ever scanned.
- **Non-intrusive.** DNS queries, TLS handshakes, one HTTPS GET of `mta-sts.<domain>`, and TCP
  connects. No SYN or raw-socket scanning, no UDP, no banner grabbing beyond the TLS handshake, no
  logins, no exploit or vulnerability probes.
- **Polite.** DNS 3 s, TCP 3 s, TLS 5 s timeouts; at most 8 concurrent connections; DNS and connects
  paced at 25 per second; one scan per asset at a time; at most 400 DNS questions per asset (an SPF
  record is attacker-controlled data and must not fan out); a manual scan of the same asset is
  refused for 15 s after the last one. Scheduled daily plus on demand.
- **Never connects to itself.** A declared IP that is loopback, link-local (which covers cloud
  metadata addresses), unspecified or multicast is refused at declaration. A declared name that
  resolves to such an address is never dialled. Private (RFC 1918) addresses are allowed, because a
  lab host is a legitimate thing to declare, but their results describe the scanner's own network,
  not the internet.
- **Missing evidence is not a result.** A check that could not run (timeout, SERVFAIL, nothing to
  connect to, no DKIM selector found) is stored as **not assessed** with its reason. It is not a
  pass and not a failure, it resolves no open finding, and the Surface page lists it.

## Checks

Severity follows the `defendsec-surface` rules. A finding's identity on an asset is
`(finding id, subject)`; open findings of a check that ran and no longer sees them are resolved,
and a returning finding is reopened with its first-seen date kept, like vulnerability findings.

| Check | Asset | Findings (severity) |
| --- | --- | --- |
| **mx** | domain | no MX (info); null MX (info); MX host with no address (medium); MX host is a CNAME (low) |
| **spf** | domain | missing on a domain with MX (high), without MX (low), MX unknown (medium); several records (high); syntax error (high); include loop or include with no SPF (high); more than 10 DNS-querying terms counted recursively (high); more than 2 void lookups (high); `+all` (critical); `?all` (high); `~all` without DMARC at enforcement (low); no `all` (medium); `ptr` (low) |
| **dmarc** | domain | missing (high); several records (high); invalid (high); `p=none` (medium); `sp` weaker than `p` (low); `pct<100` (low); no `rua` (low). A subdomain with no record uses the organisational domain's, and the evidence says which |
| **dkim** | domain | key under 1024 bits (high); 1024 bits (low); revoked key (info); key cannot be parsed (medium); declared selector with no key (medium). Selectors cannot be listed: declared ones plus `google selector1 selector2 s1 s2 k1 default dkim mail` are tried, and none found is **not assessed** |
| **mta-sts** | domain | missing (low, only if the domain has MX); record present but policy unreachable, redirected, or invalid (medium); `mode: testing` or `none` (low); an MX not covered by the policy's `mx:` patterns (medium) |
| **tls-rpt** | domain | missing (info); no valid `rua` (low) |
| **dnssec** | domain | unsigned (info); DS at the parent but the chain fails on a validating resolver while the data arrives with checking disabled (high). A resolver that never sets AD proves nothing and is **not assessed** |
| **caa** | domain | none at the name or up to the organisational domain (low) |
| **cname** | domain, hostname | CNAME chain ends at a name that does not exist (medium). Worded "target does not exist", never "takeover possible" |
| **tls-cert** | domain (apex), hostname | expired (critical); under 7 days (high); under 30 days (low); hostname mismatch (high); chain does not verify, with the exact reason (medium) |
| **tls-legacy** | domain (apex), hostname | TLS 1.0 or 1.1 accepted (medium). Not assessed under Go FIPS 140 mode |
| **ports** | ip | open ports from a fixed list: 445 critical; 23, 3389, 5900, 1433, 3306, 5432, 6379, 9200, 27017 high; 21 medium; 8080 low; 22 info; 25, 110, 143 info on a host declared as a mail host, otherwise low. Shared-hosting or CDN addresses (flagged by the operator, or in a built-in Cloudflare range) are capped at info and described as the provider's edge |

An open port is evidence that a service is reachable, not that it is vulnerable, and the finding
text says so. If every port times out the result is **not assessed**: a firewalled address and a
dead host look the same from here.

Every finding carries its evidence (the record text or certificate fields actually seen), severity,
control tags from `internal/controls` (new signals `surface.email`, `surface.dns`, `surface.tls`,
`surface.ports`, mapped to NIST 800-53 SC-7, CM-7, SC-17, SC-20, SC-8, SI-8 and CIS v8 3.10, 4.4,
9.5, all marked *partial*) and fix-it text. Provider hints from the MX records (Google Workspace,
Microsoft 365, Cloudflare) change the wording of fix-it text, never the findings.

## Storage (migrations 023 and 025)

`surface_assets`, `surface_scans`, `surface_observations` (the raw material of every check of every
scan, append-only), `surface_findings`, and (025) `surface_finding_intervals` and `surface_scans.changes`. Removing an asset hides it and stops scanning but keeps its
findings and observations. Scan history is not pruned yet.

## In the exposure view (slice 7b, migration 025)

Surface findings are first-class rows of the Fix this week list, the Fleet card, the trend and the evidence export. How they
rank, what the card says and the API additions are in [EXPOSURE.md](EXPOSURE.md#external-surface-findings-slice-7b).

Two storage changes carry it:

- **A finding that closes and comes back restarts `first_seen`.** Until slice 7b a reopened finding kept its first
  `first_seen` and lost the closed days, so the trend counted them as open. Now the interval that ended is copied to
  `surface_finding_intervals` and `first_seen` restarts, as `vuln_finding_intervals` does for vulnerabilities. Rows reopened
  before this slice already lost the closed gap; nothing can recover it.
- **Every scan is attested in the audit chain.** `RecordSurfaceScan` appends a `surface_scan_recorded` entry (scan id, asset id,
  SHA-256 digest, how many findings it opened and closed) in the same transaction that stores the scan, so there is never a
  scan without its attestation or an attestation without its scan. `surface_scans.changes` keeps the findings the scan opened or
  closed, so the digest can be recomputed at export time.

## Evidence export

Every evidence bundle (`GET /v1/audit/evidence`, scoped or not) carries a `surface` section when the instance has declared
an asset: every asset (removed ones too: their findings are evidence), every scan with the raw observation of every check
(record text, certificate fields, "not assessed" and why) and the findings it opened or closed, and every finding with each
interval it was open.

The findings, observations and assets are rows in Postgres, not entries of the hash chain, so on their own they prove nothing.
They are made checkable the way the compliance section's audit counts are, and the bundle says exactly which part is which
(`defendsec-verify` prints it):

- **Attested scan.** The verifier recomputes the scan's digest from the bundle's own copy (asset, times, trigger, every
  observation, every change) and compares it with the chained `surface_scan_recorded` entry. A match means the observations
  and the findings the scan opened or closed are exactly what the control plane stored when it ran, and the chain fixes the
  date. Editing a record text, an observation's "assessed" flag, a change or a scan date in the database or in the bundle
  fails the scan.
- **Open on date A, closed on date B.** A finding's intervals are recomputed from the attested scans that opened and closed it
  and compared with the dates the bundle claims. A match proves the dates under the chain's weight; a moved date fails the
  finding.
- **Unattested** (not failed): a scan with no chained entry (it ran before slice 7b, or lies outside an exported audit range)
  is carried and named, and so are the findings of its asset, because their history cannot be recomputed completely.
- **Failed**: a chained entry whose scan is missing from the bundle, a digest that does not match, or an edited provenance
  sentence. The section is read after the audit range on purpose, so a scan recorded in between is unattested, not "withheld".

What it does not prove: that the scanner's view was the internet's view (one vantage point), the asset list's authorisation
facts (the chain records `surface_asset_add` and `surface_asset_authorise`, which are not cross-checked), or anything about a
scan the chain does not hold. Bundle size grows with the number of scans (observations are never pruned); it has not been
measured at a year of daily scans.

## API (admin API, same auth as the neighbouring routes; viewers read, admins write)

| Route | |
| --- | --- |
| `GET /v1/assets` | declared assets |
| `POST /v1/assets` | `{kind: domain\|hostname\|ip, value, label, dkimSelectors, sharedHosting, mailHost, authorised}`. Unknown fields are rejected |
| `POST /v1/assets/{id}/authorise` | `{authorised: true\|false}` |
| `DELETE /v1/assets/{id}` | stop scanning and hide |
| `GET /v1/surface/findings?assetId=&resolved=1&limit=` | findings, plus per asset: open counts by severity, the latest observation of each check, and the checks that were not assessed |
| `POST /v1/surface/scan` | `{assetId?, wait?}`: one asset or every confirmed one. 202 and a background scan, or 200 with the result when `wait` is set. 409 for an unconfirmed asset |

Declaring, confirming, removing and scanning are written to the audit ledger with the acting
account.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `DEFENDSEC_SURFACE_RESOLVERS` | `/etc/resolv.conf` | comma-separated resolvers for ordinary lookups |
| `DEFENDSEC_SURFACE_VALIDATING_RESOLVERS` | `1.1.1.1,9.9.9.9` | validating resolvers for the DNSSEC check. The observation records which one answered. These resolvers see the names of declared domains |
| `DEFENDSEC_SURFACE_QPS` | `25` | DNS questions and connection attempts per second |
| `DEFENDSEC_SURFACE_SCHEDULE` | on | `off` disables the daily schedule (on-demand scans still work) |

The schedule looks every 30 minutes for confirmed assets not scanned in the last 24 hours.

## Dependencies

`github.com/miekg/dns` v1.1.73 (BSD-3-Clause), for DS records, the AD flag, CAA
and the other record types `net.Resolver` cannot do. The v1 module on GitHub is in
maintenance ("will only see specific fixes"); its v2 lives at `codeberg.org/miekg/dns` and is
still v0.x, so v1.1.73 is pinned. `golang.org/x/net` (already an indirect dependency) supplies the
public suffix list and IDNA. `govulncheck` is clean.

## Known limits

- One vantage point: the scanner's own network connection. A port that is closed from here may be
  open from elsewhere.
- DKIM selectors cannot be enumerated; a selector nobody declared is invisible.
- MX hosts are checked in DNS (they resolve, they are not CNAMEs) and against the MTA-STS policy.
  Their SMTP TLS is **not** tested: that would need a STARTTLS exchange, which goes beyond a TLS
  handshake. TLS checks run on port 443 of declared domains and hostnames only.
- The built-in Cloudflare ranges go stale; the per-asset shared-hosting flag is the reliable control.
- Only the fixed port list is probed, over IPv4/IPv6 TCP.
- apid makes the outbound connections itself, so the host needs outbound DNS (UDP and TCP 53), TCP 443 to
  declared hostnames and TCP to declared IPs. A firewall that blocks them shows up as checks that were not
  assessed, not as clean results.
