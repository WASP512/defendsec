# DefendSec — Strategic Direction and Improvement Roadmap

> Companion to `docs/DEFENDSEC_WHITE_PAPER.html`. This document reviews the white paper's
> positioning against the shipped implementation, recommends a product direction, and lays
> out a phased engineering plan to get there.
>
> Prepared September 2026 against commit `05e84f9`.

---

## 1. Review of the white paper

### What the paper gets right

The paper is a genuinely strong technical document, and unusually honest for its genre:

- **Section 4 (Security and trust model)** is specific and correct. Domain-separated canonical
  signing envelope, device binding, TLS 1.3 floor, TOFU bootstrap explicitly named as the trust
  moment, 90-day agent certs. Most projects at this size hand-wave this section.
- **Section 18 (Limitations and design tradeoffs)** is rare and valuable. Stating plainly that
  you do not do MDM, do not orchestrate patching, and do not run a tuned enterprise FIM engine
  buys credibility that feature lists never do.
- **The Scope page as a product surface** — shipping the boundary *in the UI*, not just in docs —
  is a real differentiator in a market full of overclaiming.
- Operator workflows (Section 14) and troubleshooting (Section 17) read like they were written by
  someone who has actually run the thing.

### The core problem: the paper buries its own lede

The single most differentiated thing DefendSec has built is described in **Section 12** as
"Signed host response," and framed defensively — Section 18 summarizes it as *"Bounded named
commands; no arbitrary remote shell → safer capability surface, **with less general remote
administration power**."*

That is the moat, written as an apology.

No other tool in the free/self-hosted space has this property. Compare:

| Tool | Endpoint action model |
| --- | --- |
| **Wazuh** | Manager triggers an active-response *script* on the agent. No per-command signature, no device binding, no expiry, no capability allowlist. |
| **Fleet** | osquery SQL (broad read surface) + MDM commands delegated to Apple/Microsoft. |
| **Velociraptor** | VQL — extremely powerful, effectively arbitrary execution by design. |
| **Commercial EDR** | Full remote shell, gated only by RBAC in a vendor cloud. |
| **DefendSec** | Closed set of named command types, Ed25519-signed over a canonical envelope, bound to one device ID, 2-minute expiry, parameter allowlists, replay cache, acknowledged back. |

Nobody else can retrofit this cheaply, because their whole value proposition is *unbounded*
capability. DefendSec chose the opposite constraint early, and that constraint is now an asset —
but the paper sells it as a limitation.

### Positioning gap

"Self-hosted security inventory and host detection" is a commoditized claim. Wazuh and Fleet both
own it, both are free, both have 50–100× the engineering behind them. Every sentence of the paper
that competes on that axis is a sentence DefendSec loses.

### Accuracy gap the paper should not have

Section 1 lists **"Inspectable operation — commands, acknowledgements, alerts, inventory, and
relevant operator activity are retained for review."** The implementation retains the *facts* but
not the *proof*:

- `db/migrations/001_init.sql:69` — the `commands` table stores `id, device_id, type, payload,
  status, accepted, message, actor`. **No signature, no issued/expires timestamps, no signing key
  ID.** A `grep` for `signature` across `internal/storepg/`, `internal/cmdlog/`, and
  `db/migrations/` returns nothing.
- `proto/defendsec/v1/agent.proto:78` — `CommandAck` is `{command_id, accepted, message}`. The
  endpoint's claim that it executed something carries no proof of origin beyond the transport.
- `db/migrations/001_init.sql:85` — `audit_log` is a plain `BIGSERIAL` table. Anyone with database
  access can delete or rewrite rows and leave no trace.

So commands are signed **in transit** and then the signature is discarded. After the fact, the
audit trail is an ordinary mutable log that asserts what happened. That is the same guarantee
everyone else offers. The hard cryptographic work is already done — it is simply not being kept.

**This gap is also the opportunity.** Closing it is comparatively cheap and converts the product's
defensive framing into its strongest claim.

---

## 2. Recommended direction

> **Position DefendSec as the verifiable endpoint control plane: the system of record for what was
> done to your hosts, by whom, under what authority — with cryptographic proof.**
>
> *Every action on every host: bounded, signed, provable.*

Detection is table stakes and must improve (Phase 3). The **moat** is provable, policy-governed,
bounded action — including action initiated by automation and AI.

**Go to market through compliance.** This is the architecture thesis; §3 is how it is sold. The
verifiable-control-plane claim has no budget line of its own, while audit evidence for NIST,
CIS and CMMC does — and the controls those frameworks specify are, almost literally, what Phases
1 and 2 build.

### Why this direction, now

Three forces converged in the last eighteen months, and they all point at the same capability:

1. **AI agents now act on infrastructure.** Every vendor is wiring LLMs into SecOps. The unsolved
   problem is not "can a model triage an alert" — it is *"how do I let a non-human actor touch
   production without handing it a root shell, and prove afterward exactly what it did and who
   authorized it."* DefendSec's command model is already the correct substrate: closed capability
   set, signed, device-bound, time-boxed, revocable, acknowledged. Nobody else is starting from
   here.
2. **Compliance now demands evidence, not assertions.** NIS2, DORA, CMMC 2.0, SOC 2 and ISO 27001
   auditors increasingly ask for tamper-evident records of privileged action. A hash-chained,
   independently verifiable action ledger is a feature you can *sell*, and it is a natural
   extension of what exists.
3. **Insider threat and supply-chain pressure.** "Who ran what, on which host, under what
   authority — and prove the log wasn't edited" is a question plain logs cannot answer, including
   the logs of most commercial EDR.

### Directions deliberately rejected

| Direction | Why not |
| --- | --- |
| **Out-feature Wazuh** (log analysis, full rule engine, all platforms) | ~8,300 lines of Go against a project with hundreds of contributor-years. Permanent catch-up; never cutting edge. |
| **Add MDM** (wipe, lock, profiles, DEP, CSP) | The paper already refuses this, correctly. Requires deep Apple/Microsoft/Google ecosystem work, is commoditized, and destroys the clean trust boundary. |
| **Become a SIEM / log lake** | Enormous ingest and storage engineering. Elastic, Loki, and Splunk own it. Be a high-quality *source* for one instead. |
| **Full kernel EDR** | Needs a kernel team, driver signing, and multi-year hardening. eBPF (Phase 3) gets most of the value at a fraction of the cost. |
| **Stay a Proxmox homelab tool** | Where the product currently drifts. Comfortable, well-executed, but not cutting edge and not monetizable. |

### What this direction protects

The existing design principles stay intact — they become the *marketing*, not the caveats:
self-hosted, explicit enrollment, bounded response, operator approval, honest scope. The roadmap
below deepens each one rather than trading any of them away.

---

## 3. Compliance and assurance positioning

> **Short answer: yes — as the compliance *evidence* system, not as another compliance *scanner*.**
>
> Framed that way this is not a departure from §2; it is its go-to-market. "Cryptographically
> bounded action channel" has no budget line. "CMMC Level 2 evidence" does.

### 3.1 The trap: benchmark scanning is the worst available fight

Positioning as a scanner that checks hosts against CIS/NIST benchmarks puts DefendSec against:

| Competitor | Why it is a hard fight |
| --- | --- |
| **CIS-CAT Pro** | Built by CIS themselves. Authoritative by definition. |
| **OpenSCAP + SCAP Security Guide** | Free, NIST-SCAP-validated, government-maintained content. |
| **Wazuh** | Leads its own marketing with PCI DSS / NIST 800-53 / HIPAA / GDPR dashboards. |
| **Tenable, Qualys Policy Compliance, Rapid7** | Certified content, huge platform coverage, entrenched in procurement. |
| **Chef InSpec, Lynis** | Free, mature, large community profile libraries. |
| **Drata, Vanta, Secureframe** | Own the SOC 2 / ISO 27001 evidence-collection workflow end to end. |

Two structural problems make this unwinnable as a primary position:

**Content is the product, and content is a treadmill.** Every OS release and every benchmark
revision obsoletes part of your library. CIS maintains benchmarks for dozens of platforms; each is
150–400 checks. DefendSec ships **15 checks across two Linux packs**. That is not a gap you close
once — it is a permanent staffing commitment.

**The engine cannot express most benchmark checks yet.** `internal/sca/sca.go` implements exactly
two check types: `file_regex` (with drop-in config support — a thoughtful detail) and
`inventory_field`. A representative CIS Linux benchmark also requires file permission and
ownership checks, mount options, sysctl values, package presence and absence, systemd unit state,
and command-output evaluation. The current engine can express roughly a quarter to a third of a
typical benchmark.

**Certification is a procurement gate.** CIS runs a SecureSuite vendor certification programme and
NIST maintains an SCAP-validated products list. Assessors and buyers ask. Uncertified content is a
second-class citizen regardless of quality.

### 3.2 The distinction that decides whether this is winnable

**CIS Controls and CIS Benchmarks are different products, and only one is a viable target.**

| | CIS Benchmarks | CIS Controls v8 |
| --- | --- | --- |
| What it is | Per-platform configuration settings | 18 controls / 153 safeguards (IG1 = 56) |
| Scope | ~150–400 checks × dozens of platforms | Organisation-level, platform-independent |
| Revision rate | Continuous, per-platform | Stable across years |
| DefendSec fit | **Poor** — pure content treadmill | **Good** — already evidences a real slice |

Target the **Controls**. Ship enough Benchmark content to be credible on the platforms you
genuinely support, publish coverage honestly, and never imply completeness. The same logic applies
to NIST: map to **800-53 / 800-171 control families**, not to a promise of full SCAP content.

### 3.3 The opening: everyone is fighting over the wrong half

Compliance work splits into two halves, and the market has piled into one of them.

| | Assessment | Evidence |
| --- | --- | --- |
| Question | "Are we configured correctly?" | "Prove the control operated for the whole audit period, and prove nobody edited the proof." |
| Output | A point-in-time snapshot | A continuous, attributable, tamper-evident record |
| Market | Saturated and commoditised | Thinly served |
| DefendSec today | Weak (15 checks) | **Architecturally ahead of everyone** |

Even the SaaS compliance platforms only partly solve the evidence half: they collect continuously,
but the evidence lands in a mutable vendor database. The assessor is trusting the vendor's word
that nothing was altered. **Nobody in this market chains the evidence cryptographically.**

That is precisely what Phase 1 builds.

### 3.4 The frameworks specify DefendSec's architecture almost literally

This is the strongest argument for the compliance position: several controls that most vendors
satisfy with a shrug are controls DefendSec can satisfy with mathematics.

| Capability | Phase | Controls it evidences |
| --- | --- | --- |
| Hash-chained audit log | 1.2 | **NIST 800-53 AU-9(3)** *Cryptographic Protection*; **800-171 3.3.8**; **PCI DSS 4.0 10.3.2**; **ISO 27001 A.8.15** |
| Signed commands + signed acknowledgements | 1.1, 1.3 | **NIST 800-53 AU-10** *Non-repudiation* |
| Per-user identity | 1.0 | **800-171 3.3.2** *actions uniquely traced to individual users*; **PCI DSS 10.2.1.2**; **ISO 27001 A.8.2** |
| Offline verifier + evidence export | 1.4, 1.5 | **AU-6** *Audit review*; the artifact an assessor actually asks for |
| Transparency anchoring | 1.6 | Exceeds **AU-9(3)**; survives compromise of the system of record itself |
| Policy engine, two-person integrity | 2.1–2.3 | **AC-6(9)** *Log Use of Privileged Functions*; **CM-5** *Access Restrictions for Change*; **CIS Control 5.4**; **ISO 27001 A.8.18** |
| File integrity monitoring | shipped | **SI-7**; **PCI DSS 11.5.2**; **CIS Control 3** |
| Asset and software inventory | shipped | **CM-8**; **CIS Controls 1 and 2** |
| Vulnerability identification | 0.1–0.2 | **RA-5**; **CIS Control 7** |
| Behavioural telemetry | 3.1–3.5 | **SI-4**; **AU-2 / AU-3**; **CIS Control 8.5** |

**AU-9(3) and AU-10 are the headline.** Most products meet "protect audit information" with file
permissions and RBAC, and meet non-repudiation with a policy statement. A hash-chained ledger of
signed, individually attributed privileged actions, verifiable by a tool that does not trust the
server, is a materially stronger answer than any competitor can give — and it is the same Phase 1
work already recommended.

### 3.5 Where this is sharpest: the defence supply chain

If the goal is a commercial wedge rather than broad appeal, defence contracting is the strongest
one available, for a reason specific to DefendSec's architecture.

- **CMMC 2.0 Level 2 is NIST SP 800-171**, required across roughly 80,000 US Defense Industrial
  Base contractors and assessed by third-party C3PAOs. Its audit-and-accountability family
  (3.3.1, 3.3.2, 3.3.8) and privileged-function logging (3.1.7) are exactly Phases 1 and 2.
- **Self-hosting inverts from a disadvantage to a requirement.** Controlled Unclassified Information
  generally cannot be handed to arbitrary SaaS; cloud services need FedRAMP Moderate equivalency.
  Most competitors in the evidence half of the market are SaaS. DefendSec's self-hosted posture —
  currently framed as a preference for homelab users — becomes a procurement prerequisite.
- **Australian DISP** (Defence Industry Security Program) follows the same logic under sovereign
  hosting requirements, mapping to the ACSC **Information Security Manual** and **Essential Eight**.
  Essential Eight is a notably tractable target: eight mitigation strategies with maturity levels
  rather than hundreds of per-platform settings. DefendSec already touches patch applications,
  patch operating systems, and restrict administrative privileges (Phase 2), and can report
  maturity honestly against them.

### 3.6 What this changes in the roadmap

Five concrete adjustments. The first is cheap now and expensive later, so it should not wait.

1. **Control mapping as a data model, not a report.** Every SCA check, alert, policy result and
   signed action carries framework control IDs (`nist-800-53:AU-9(3)`, `cis-v8:5.4`,
   `800-171:3.3.2`) as first-class fields. Retrofitting this after Phases 1–3 means re-tagging
   every record type; doing it during Phase 1 costs a column and a lookup table.
2. **Expand the SCA check types** (§3.1) — file mode and ownership, mount options, sysctl,
   package presence, unit state, command output. This blocks *all* benchmark content, so it
   belongs in Phase 3.7 rather than later.
3. **Introduce an audit period.** Compliance evidence is about a window, not an instant. Retain
   control state over time and render "this control held continuously from A to B, with these
   three documented exceptions" — the sentence an assessor needs.
4. **Per-control evidence packages.** Extend Phase 1.5 so an export can be scoped to a control or
   a framework, not only to a host or incident.
5. **Pick one framework to be excellent at before broadening.** Recommended order: **CIS Controls
   v8 IG1** (breadth, stable, already partly covered) → **NIST 800-171 / CMMC L2** (the commercial
   wedge) → others on demand.

### 3.7 What not to claim

The product's credibility currently rests on the Scope page and the white paper's limitations
table. Compliance marketing is where that credibility is most easily spent.

- Say **"maps to"**, never "compliant with" or "certified". Certification is a process DefendSec
  has not been through, and assessors know the difference.
- **Publish coverage as a fraction, with the denominator.** DefendSec can evidence technical
  controls only. Of 800-171's 110 requirements, a realistic target after Phases 0–3 is roughly a
  quarter to a third; the rest are organisational — policy, training, physical security, incident
  response procedure. Saying so plainly is consistent with how this product already behaves, and
  it is the difference between a tool an assessor trusts and one they discount.
- **Never let a mapping imply the control is met.** DefendSec evidences that a control operated.
  Whether the control is adequate is the assessor's judgement.

---

### 3.8 Why the vulnerability catalog syncs locally rather than querying live

The shipped catalog is inadequate and must be fed from authoritative upstream sources (§0.3). But
"tie it to online databases" and "query those databases at scan time" are different designs, and
only one of them survives this product's own requirements.

Live upstream queries break five things at once:

| Problem | Consequence |
| --- | --- |
| **Air-gapped and CUI networks** | Cannot reach `api.nvd.nist.gov` at all. §3.5 identifies exactly those networks as the sharpest market — a design that requires outbound internet disqualifies the product from it. |
| **Third-party availability** | NVD's 2024 enrichment backlog and repeated API outages are well documented. Fleet security posture should not go blind during someone else's incident. |
| **Rate limits** | NVD allows 5 requests per 30 seconds unauthenticated, 50 with a key. Per-package queries across a fleet exhaust that immediately. |
| **Inventory leakage** | `scripts/ingest-osv.py` currently reads distinct package names from `devices.software` and POSTs them to `api.osv.dev`. That tells a third party precisely what software the fleet runs — in a product self-hosted specifically so that data stays put. |
| **Non-reproducible findings** | If a finding depends on what a remote API returned at query time, there is no way to prove what the catalog said on the day of the scan. This directly undermines §3.3. |

The correct architecture is the one every serious scanner uses — Trivy, Grype, Dependency-Track,
Dependabot all ship a local database that syncs on a schedule. **Local is not the problem;
hand-curated and stale is the problem.** The fix is a continuous, versioned, signed mirror of
authoritative feeds (§0.3–0.6), not runtime API calls.

Done that way, the catalog stops being a liability and becomes part of the evidence story: a
finding cites the snapshot and feed digests that produced it, and an assessor can reproduce it
months later.

---

### 3.9 Should the product *become* an audit tool?

"Position it for audits" and "turn it into an auditing tool" are different proposals, and the
second one hides four quite different products:

| Product | What it is | Verdict |
| --- | --- | --- |
| **Compliance scanner** | Checks hosts against framework technical settings | **No** — §3.1. Content treadmill; CIS-CAT, OpenSCAP and Wazuh own it. |
| **GRC platform** | Policy documents, control ownership, evidence requests, POA&Ms, risk register, questionnaires | **No** — roughly 70% non-technical workflow. Competing with Drata, Vanta and Archer on document management, where the cryptographic moat is irrelevant. |
| **Audit evidence system** | Continuously collects technical evidence that controls operated, mapped to control IDs, exported for an assessor | **Yes** — already §3.3, already Phases 1.5 and 1.7. |
| **Audit readiness assistant** | Per-control status, gap tracking, and the self-assessment an agency completes before the auditor arrives | **Yes** — a thin, high-value layer on the above. |

**Recommendation: add an audit layer, do not pivot the application.** The layer maps what
DefendSec already observes to control IDs, shows per-control status with the underlying evidence,
produces the signed package, and — in keeping with how this product already behaves — marks
plainly what it *cannot* evidence and hands that back to the agency. On top of Phases 0–2 that is
roughly 6–10 weeks, not a rewrite.

The moment it becomes a checklist-and-document application, the signed action channel stops being
the product and becomes a vestigial feature, and the only defensible thing DefendSec owns is
gone.

**A note on sequencing.** The direction has now been framed four ways — verifiable control plane,
compliance evidence, live vulnerability intelligence, audit assistance. Usefully, they do not
compete: the engineering spine underneath is identical every time.

> Fix the findings → prove the actions → govern the actions → give it real eyes.

Choosing a vertical changes the *wrapper* and the order of the control-mapping work. It does not
change that spine, and no vertical is worth pursuing before Phase 0 lands — a tool that reports
patched hosts as vulnerable fails an audit conversation faster than one with no compliance
features at all.

### 3.10 CJIS is the strongest vertical named so far

Stronger than generic NIST or CIS, and arguably stronger than CMMC, for four specific reasons:

1. **CJIS Security Policy v6.0 is explicitly mapped to NIST SP 800-53 Rev 5.** The restructure away
   from bespoke policy language means the control-mapping data model in Phase 1.7 covers CJIS
   largely for free — one mapping table, several frameworks. CJIS is not additional architecture;
   it is an additional column.
2. **Policy Area 4 — Auditing and Accountability — is Phase 1 almost line for line.** It requires
   specific events be logged, retained, protected from modification, and reviewable. A hash-chained
   ledger of signed, individually attributed actions is a materially better answer than any
   competitor gives, and it is work already on the roadmap.
3. **The buyers are underserved in a way the CMMC market is not.** Roughly 18,000 US law
   enforcement agencies, most of them small, most with no dedicated security staff, facing a
   triennial audit they dread. Existing options are enterprise-priced platforms or a consultant
   with a spreadsheet. CMMC, by contrast, already has a crowded vendor field.
4. **The audit is a dated, recurring event** — a natural sales trigger and a natural renewal cycle.

Self-hosting inverts here exactly as it does for CUI: criminal justice information has strict
handling requirements, and a self-hosted posture is a prerequisite rather than a preference.

**Honest coverage.** Of the 13 CJIS policy areas, DefendSec can substantially evidence **three**
— Auditing and Accountability (4), Configuration Management (7), and System and Communications
Protection / Information Integrity (10) — and partially evidence **three** more: Incident Response
(3), Access Control (5), and Identification and Authentication (6). It can evidence **none** of
Information Exchange Agreements (1), Security Awareness Training (2), Media Protection (8),
Physical Protection (9), Personnel Security (12), or Mobile Devices (13) — the last being MDM,
which §2 declines on purpose. Publish that breakdown rather than a coverage percentage.

### 3.11 Three hard blockers CJIS imposes, all verifiable in the tree today

These are not roadmap preferences. Each one is disqualifying on its own in a CJIS environment, and
each is cheaper to address now than after a deal is in progress.

**1. FIPS 140-3 validated cryptography.** CJIS requires FIPS-validated cryptographic modules for
protecting CJI. The tree uses Go's standard library throughout — `ed25519` (19 call sites),
`ecdsa` / P-256 (18), `sha256` (38) — and contains no reference to `boring` or `fips` anywhere.
Go's default crypto is *not* a validated module. Options are Go 1.24+'s native FIPS 140-3 mode
(the Go Cryptographic Module), BoringCrypto, or an external validated module. **Check this before
Phase 1 hardens the signing path**: Ed25519 is permitted under FIPS 186-5, but the implementation
must sit inside the validated boundary, and discovering otherwise later would mean revisiting the
one component the whole strategy rests on.

**2. Multi-factor authentication.** CJIS has required advanced authentication for CJI access since
October 2024. DefendSec has no user accounts, no passwords, and no MFA of any kind — a grep for
`mfa`, `totp`, `webauthn`, `oidc` and `password` across `internal/`, `app/` and `lib/` returns
nothing but a demo-data string. Authentication is a single shared bearer token. This is not merely
the attribution weakness noted in Phase 1.0; in a CJIS context it is a direct policy violation.
**Phases 1.0 and 5.4 become mandatory rather than sequenced.**

**3. Audit record retention.** CJIS sets a minimum retention of one year for audit records.
DefendSec ships below that on two paths: resolved alerts default to **90 days**
(`DEFENDSEC_ALERT_RETENTION_DAYS`) and live-query results to **30 days**, while `internal/cmdlog`
keeps a **500-record ring buffer** that silently discards the oldest command history regardless of
age. Command history is precisely the privileged-action record Policy Area 4 cares about. Raise
the defaults, and replace the ring buffer with age-based retention on the Postgres path (§5.5).

**What not to claim.** There is no FBI certification programme for products, and the *agency* is
compliant, not the tool. Say "supports CJIS Policy Area 4 evidence," never "CJIS compliant" —
auditors and CSA coordinators know the difference, and overclaiming here costs more credibility
than it buys.

---

## 4. Roadmap

Six phases. Each is independently shippable. Effort estimates assume one experienced engineer.

| Phase | Theme | Effort | Why now |
| --- | --- | --- | --- |
| **0** | Trustworthy findings + real feeds | 6–9 weeks | A scanner that cries wolf gets switched off. Blocks everything. |
| **1** | Provable action ledger | 6–10 weeks | Builds the moat. Cheap — the crypto already exists. |
| **2** | Policy-governed response | 6–8 weeks | Makes automation safe. Prerequisite for Phase 4. |
| **3** | Behavioral detection | 4–6 months | Largest capability gap. Earns the right to act. |
| **4** | AI-era control plane | 2–3 months | The cutting-edge story. Only credible after 1–2. |
| **5** | Reach and durability | Ongoing | Platform parity, scale, enterprise identity. |

---

### Phase 0 — Make findings trustworthy (6–9 weeks) · *blocks everything else*

The vulnerability matcher currently produces confidently wrong answers. Fix this first; nothing
else matters if operators learn to ignore the output.

**0.1 — Replace the version comparator.** `internal/vuln/vuln.go:44` strips every non-digit and
compares integer segments:

```go
for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
```

This cannot represent the version semantics of any real package ecosystem. `1.1.1g` and `1.1.1a`
both parse to `[1,1,1]` and compare equal. `2.0~rc1` compares equal to `2.0` when it must sort
*lower*. Alphanumeric and pre-release ordering is simply lost.

- Implement real **dpkg** comparison (`epoch:upstream-version-revision`, with `~` sorting before
  everything including end-of-string, and the digit/non-digit alternating-chunk algorithm).
- Implement real **rpm** `rpmvercmp` (epoch/version/release, `~` and `^` handling).
- Keep them behind one `Comparer` interface selected by the host's package manager, which the
  agent already knows (`internal/hostinv/collect.go:322 rpmBased()`).
- Port the upstream test vectors from dpkg and rpm — both projects publish extensive ones.

**0.2 — Stop reporting backported fixes as vulnerable.** This is the dominant false-positive
source on Linux, and the current test suite *enshrines* it. `internal/vuln/vuln_test.go:11`
asserts:

```go
{"1:8.9p1-3ubuntu0.11", "9.8p1", true}   // "vulnerable"
```

That is Ubuntu 22.04's OpenSSH. Canonical fixed CVE-2024-6387 (regreSSHion) in
`1:8.9p1-3ubuntu0.10` — without bumping upstream to 9.8p1. The installed package is **patched**,
and DefendSec calls it vulnerable. Comparing distro-packaged versions against upstream floors is
structurally incapable of being correct.

- Ingest **distro security trackers**, which publish the fixed *distro* version per CVE:
  Ubuntu OVAL / USN, Debian Security Tracker JSON, RHEL/Alma/Rocky OVAL, SUSE OVAL.
- Match `(distro, release, source package, CVE) → fixed-in version`, falling back to upstream
  floors only for software installed outside the package manager.
- Record which feed produced each match and surface it in the UI. An operator must be able to see
  *why* something was flagged.
- Fix the test vector above and add regression cases for backports across all supported distros.

**0.3 — Replace the hand-curated catalog with a real feed pipeline.** The shipped local catalog is
the weakest input in the product. It should be continuously synced from authoritative upstream
sources — but **synced into a local mirror, not queried live.** See §3.8 for why that distinction
decides whether DefendSec can serve its best market at all.

*Tier 1 — what is actually fixed. Without these, everything else produces backport false positives.*

| Source | Provides |
| --- | --- |
| Ubuntu OVAL / USN, Debian Security Tracker, RHEL & Alma & Rocky OVAL, SUSE OVAL | The fixed **distro** version per CVE per release, plus fix state — the only correct answer for a packaged install |
| OSV.dev **bulk export** (per-ecosystem zip, not the per-package query API) | Well-structured ranges across language ecosystems and several distros |
| MITRE **CVE List V5** (bulk, from GitHub) | The CVE record of authority |

*Tier 2 — prioritisation. This is where the largest product win is, and it is cheap.*

| Source | Provides |
| --- | --- |
| **CISA KEV** | ~1,200 CVEs known to be *actively exploited*. A single small file, updated continuously. Turns "you have 400 open advisories" into "three of these are being exploited in the wild." Federal remediation deadlines under **BOD 22-01** attach to it, which ties straight back to §3. |
| **EPSS** (FIRST.org) | Daily exploitation-probability score for ~250k CVEs. CVSS is a severity score and a famously poor prioritisation signal; KEV + EPSS is a defensible one. |
| **NVD** | CVSS vectors, CPE, CWE — for enrichment, not as the source of truth about what is fixed. |

*Tier 3 — enrichment.*

- **GitHub Advisory Database** for language ecosystems.
- **MITRE CVE-to-ATT&CK mappings**, and the CWE → CAPEC → ATT&CK chain, to answer "if this is
  exploited, what does the attacker gain" in ATT&CK terms. This is the legitimate way to tie
  advisories to ATT&CK; ATT&CK itself is an adversary-behaviour knowledge base and contains no
  CVEs, versions or package names, so it cannot feed advisories directly. Detection-side ATT&CK
  tagging stays in Phase 3.4.
- Public exploit presence (Exploit-DB, Metasploit module) as a boolean.

**0.4 — Rebuild the advisory data model.** The current schema cannot hold any of the above.
`advisories (id, cve, package, below, severity, summary, source)` carries exactly one version
floor per row, and `scripts/ingest-osv.py` fills it by keeping the **last** `fixed` event it
encounters across all ranges — so a CVE fixed in both `1.1.1k` and `3.0.2` silently loses one.
Severity is derived by string-prefix matching on the score (`startswith("9")`, `startswith("7")`),
which misreads CVSS vectors. The script also defaults to ecosystem `Debian` and four packages.

Required shape:

- Multiple affected **ranges** per advisory, not a single `below`.
- A `(distro, release)` dimension — the same CVE has different fixed versions per release.
- **Fix state**: affected / fixed / will-not-fix / not-affected. Distros publish this, and
  "not-affected" and "will-not-fix" eliminate a large class of false positives on their own.
- `kev` flag, `epss` score, full CVSS vector, CWE.
- `source` and `snapshot_version` per record, for the reproducibility requirement in 0.6.

**0.5 — Offline and air-gapped sync is mandatory, not optional.** Publish signed catalog bundles
that an operator downloads on a connected machine and imports on the isolated one. A CUI or
classified network cannot reach `api.nvd.nist.gov`, and §3.5 identifies exactly those networks as
the sharpest market. A scanner that still works in a SCIF is a differentiator, not a fallback.

**0.6 — Pin findings to a catalog snapshot.** Every finding records the catalog snapshot and feed
digests it was produced against, and the snapshot is recorded in the Phase 1 ledger. This makes a
finding reproducible months later and provable to an assessor — *"this host was flagged against
snapshot `2026-09-15T06:00Z`, feed digests as follows"* — which no other scanner can currently
demonstrate. It is also the only way the evidence thesis in §3.3 survives contact with a
vulnerability catalog that changes daily.

**0.7 — Make feed freshness visible and honest.** The paper says catalog freshness "is an operator
responsibility," which is fair, but the console gives no signal today. Show per-feed age on
Advisories and Fleet, and raise a system alert when a feed exceeds its threshold. Stale intel
presented as current is worse than no intel.

**0.8 — Ship ingest as a first-class service.** `scripts/ingest-osv.py` (201 lines, with only a
`.timer.md` *sketch*) becomes a supported unit in `packaging/systemd/` with sync status, last
success, and per-feed digest reported in the console — not a script an operator has to find and
wire up.

**Acceptance:** dpkg/rpm comparators pass the upstream vector suites; a fully-patched Ubuntu 22.04
and Rocky 9 host produce **zero** advisory findings; the Advisories page can be sorted by
KEV-then-EPSS rather than CVSS alone; a catalog imports and verifies on a host with no outbound
network; and every finding names its feed, feed date, and catalog snapshot.

---

### Phase 1 — The provable action ledger (6–10 weeks) · *the moat*

Convert "we log what happened" into "we can prove what happened, and prove the log wasn't edited."
The signing primitives in `internal/sign/` are already correct; this phase keeps and chains their
output.

**1.0 — Per-user identity and MFA (prerequisite).** Non-repudiable attribution is impossible when
every administrator shares one bearer token — and under CJIS (§3.11) a shared token with no MFA is
a direct policy violation, not merely a weakness. Today `actor` defaults to the literal string `'admin'`
(`001_init.sql:78`). Everything else in this phase is undermined without this, so it comes first:

- Local user accounts with per-user API credentials as the minimum viable step.
- OIDC / OAuth2 (Authelia, Keycloak, Entra, Okta) as the production path — see 5.5.
- Keep the shared-token path for bootstrap only, and mark sessions created that way as
  `unattributed` in the ledger so their weaker provenance is explicit rather than hidden.

**1.1 — Persist the full signed envelope.** Extend the `commands` table and `cmdlog.Record`:
`signature`, `canonical_bytes` (or a deterministic re-derivation), `signing_key_id`,
`issued_unix`, `expires_unix`, `actor_identity`, `approval_refs[]`. Migration `005_command_proof.sql`.

**1.2 — Hash-chain the audit log.** Add `prev_hash` and `entry_hash` to `audit_log`, where
`entry_hash = SHA256(prev_hash || canonical(entry))`. Any deletion, edit, or reorder breaks the
chain at that point and every point after it. Write a periodic **checkpoint** row signed by the
control key, so a verifier only needs the checkpoint signature to validate a whole range.

**1.3 — Sign acknowledgements.** Extend `CommandAck` in `proto/defendsec/v1/agent.proto` with a
signature over `(command_id, device_id, result_hash, executed_unix)`. The agent already holds a
private key and certificate (`/var/lib/defendsec-agent`); either sign with it or derive a
dedicated Ed25519 key at enrollment. This closes the loop: today the server can prove it
*authorized* an action, but the endpoint's claim to have *executed* it is unauthenticated once it
leaves the mTLS channel. Directly addresses the paper's own warning in Section 12 that
"sent" is not proof of effect.

**1.4 — `defendsec verify` (offline verifier).** A standalone binary that takes an exported bundle
plus public keys and verifies, with no access to the running server or database:
every command signature, every acknowledgement signature, the audit hash chain, and the
checkpoint signatures. Independence is the entire point — a verifier that trusts the server proves
nothing.

*This is the demo that sells the product.* Tamper with one row in Postgres, run `defendsec verify`,
watch it name the exact entry, timestamp, and actor where the chain broke.

**1.5 — Evidence export.** One console action producing a signed, timestamped bundle scoped to a
host, an incident, a date range — or a framework control (§3.6): actions taken, who authorized
them, endpoint acknowledgements, alert lifecycle, and the verification manifest. This is the
artifact an auditor or an incident responder actually asks for, and today it has to be assembled
by hand from four pages.

**1.7 — Control mapping as a data model.** Carry framework control IDs (`nist-800-53:AU-9(3)`,
`800-171:3.3.2`, `cis-v8:5.4`) as first-class fields on every check, alert, policy result and
signed action, plus an audit-period model so control state can be rendered over a window rather
than an instant. Cheap here — a column and a lookup table. Expensive after Phase 3, when it means
re-tagging every record type. See §3.6.

**1.8 — Settle the FIPS question before the signing path hardens.** CJIS and several federal
regimes require FIPS 140-3 validated cryptographic modules. The tree uses Go's standard library
throughout and references no validated module (§3.11). Evaluate Go 1.24+ native FIPS 140-3 mode
against BoringCrypto now, while the signing path is still being changed — Ed25519 is permitted
under FIPS 186-5, but only from inside a validated boundary, and finding that out later means
revisiting the component the entire strategy rests on.

*Resolved.* Probed rather than assumed, because the difference matters: `GODEBUG=fips140=on`
routes standard-library cryptography through the validated module but **rejects nothing** —
Argon2id kept working under it, because its Blake2b comes from `golang.org/x/crypto` and never
enters the boundary. A deployment can therefore believe it is in FIPS mode while hashing
passwords with an algorithm SP 800-132 does not approve, with nothing reporting a problem. Under
`fips140=only` the entire signing surface passed unchanged — Ed25519 command signatures, ECDSA
P-256 acknowledgements, SHA-256, the audit chain and its checkpoints. Only two things needed
handling, and neither was the signing path: password hashing (Argon2id stays the default;
PBKDF2-HMAC-SHA256 at 600k iterations is selected by `DEFENDSEC_FIPS_MODE=1`, both formats verify
in either mode, and an account is re-hashed on its next login) and TOTP's HMAC-SHA1, which is
approved under SP 800-131A but which Go's only-mode *panics* on — computed inside
`fips140.WithoutEnforcement` so the deviation is marked rather than hidden. BoringCrypto was not
needed. `GET /v1/crypto-posture` reports the live posture and names the deviations; see
[OPERATIONS.md](./OPERATIONS.md#fips-140-3-mode).

**1.9 — The audit layer.** Per-control status with the evidence behind it, gap tracking, and the
self-assessment view an agency completes before an assessor arrives — built on the control mapping
from 1.7 and the evidence export from 1.5. Roughly 6–10 weeks on top of Phases 0–2. It must mark
plainly what DefendSec *cannot* evidence (§3.10) rather than leaving a control silently blank.
See §3.9: this is a layer, not a pivot.

*Delivered.* The status set turns on one distinction that every compliance dashboard collapses:
**no evidence recorded** (DefendSec can evidence this control and saw nothing — usually a check
that never ran) is not the same fact as **outside DefendSec** (it cannot evidence this at all),
and neither is ever rendered as a pass. An accepted deficiency is its own status, never a
satisfied control, and its exception must carry an expiry — DefendSec refuses to store a
permanent excuse. No coverage percentage is produced anywhere. A period still running is judged
as of today rather than a date in the future. Whether a finding was open *at the close of the
window* — not today — is what a period is judged on; DefendSec stores current status rather than
a transition history, so that number is reconstructed, and the assessment says so rather than
presenting it as exact. Evidence export is scoped to a framework and period without narrowing
the audit range, because a hash chain filtered by content is not a chain; the assessment's
audit-entry counts are recomputed from the bundle's own chain and verified, its alert and command
counts are marked as unverifiable from the bundle alone, and the provenance line saying so is
itself checked for edits.

**1.6 — Transparency anchoring (optional, high-leverage).** Periodically publish signed checkpoint
hashes somewhere the server cannot retroactively control: an RFC 3161 timestamp authority, a
transparency log, a peer DefendSec instance, or a git repository. This defeats an attacker who
fully compromises the server *and* the database — they can stop new entries but cannot rewrite
anchored history. Very few products at any price can make this claim.

*Delivered.* Three targets: an RFC 3161 timestamp authority, an append-only file directory meant
to be pointed at a git worktree, and a peer DefendSec instance. Only the hash leaves the machine,
so a timestamp authority learns nothing about what the ledger contains. For RFC 3161 DefendSec
builds the request with a nonce and verifies the returned token covers *that hash* with *that
nonce* — which is what stops a compromised server replaying a token captured before it rewrote the
entry — and then stores the token verbatim. It deliberately does **not** validate the authority's
signature chain: that needs full CMS and a TSA trust store, and a half-done version would report
"verified" on the strength of checks it never made, so the token is stored whole for tooling that
can do it properly, and the limitation is reported next to every anchor. Writing the parser caught
a bug worth recording: an optional `asn1.RawValue` for TSTInfo's Accuracy field silently consumed
the nonce that follows it, so every genuine token looked like a replay. Anchoring failures are
stored rather than dropped — a run of them is the interesting signal. Building this also revealed
that `AppendCheckpoint` had no caller at all, so a deployment had no checkpoints to anchor;
checkpointing now runs on a timer alongside anchoring. Most importantly the console and the API
show the *comparison* against the live chain, not a count of anchors written: anchors nobody
checks detect nothing, and a valid signature over a rebuilt chain does not clear a mismatch,
because that signature is exactly what an attacker holding the key would produce.

**Acceptance:** every command row carries a signature verifiable by `defendsec verify` with the
server offline; a row edited directly in Postgres is detected and localized; an evidence bundle
verifies on a machine that has never contacted the server.

---

### Phase 2 — Policy-governed response (6–8 weeks)

Today authorization is binary: an admin token can issue any command to any host. That is
sufficient for a homelab and insufficient for anything else — and it is the blocker for safe
automation.

Insert a **deny-by-default policy engine between the API and the signer**. If policy does not
permit it, it is never signed, so the constraint is enforced cryptographically rather than by UI.

**2.1 — Policy engine.** Rules over `(actor, role, command type, host class, time window,
blast radius)`. Declarative and version-controlled — reuse the existing YAML conventions from
`packs/sca/`. Evaluation is logged to the Phase 1 ledger whether it permits or denies, so denials
are themselves evidence.

*Delivered.* The engine sits immediately before `signer.Sign`, so a refused command never becomes
a signed envelope and is inert even if everything above that line is bypassed — the agent checks
a signature that was never produced. Nothing is permitted unless a rule permits it, and an
explicit deny wins regardless of file order, because order-dependent policy is policy nobody can
reason about. Where two rules both permit, the stricter wins: adding a permissive rule must never
silently remove an approval requirement. A deployment with no policy file denies everything and
says so loudly at startup, and a policy file that fails to parse refuses to start rather than
half-loading — the rules that failed to parse are exactly the ones nobody notices are missing.
A misspelled key is an error, since silently dropping `host_clases` turns a narrow rule into a
fleet-wide one. Every decision carries the SHA-256 of the document that made it, so "what did the
policy say at the time" is answerable from the ledger rather than from what is on disk today, and
refusals return the rule id and reason to the caller — a refusal that says only "forbidden"
produces a ticket and then a request for a bypass.

**2.2 — Host classes and blast-radius limits.** Tag hosts (`production`, `critical`,
`domain-controller`). Express limits like *"at most 3 isolates fleet-wide per hour"* and *"never
`kill_process` on a host tagged `critical` without a second approver."* Rate limits and blast
radius are what separate a response tool from an outage generator.

*Delivered.* Classes live on the device rather than in the policy file, so a rule reads "hosts
classed production" and stays correct as the estate changes; reclassifying a host is an
authorisation change and is recorded in the ledger. Limits default to fleet scope, because a
per-host default would happily isolate the whole estate one host at a time. A limit that cannot be
evaluated — an unreadable usage count — denies rather than passing, since reporting "under the
limit" would disable the control exactly when the database is struggling. Limits count commands
actually issued, not evaluations, so a caller cannot exhaust one with requests that were all
denied anyway.

**2.3 — Two-person integrity.** Destructive commands require a second administrator's signature.
Both signatures are stored in the ledger and both are checked by `defendsec verify`. This is a
standing request in regulated environments and nothing free offers it.

*Delivered.* A command awaiting approval is stored **unsigned** — deliberately not a signed
command with a pending flag, so an attacker who flips a status column still has nothing an agent
will execute. Approvals are rows keyed on (request, actor), so one administrator clicking twice is
one approval. On the final approval the command is re-evaluated against policy before signing
rather than trusting the earlier decision: minutes have passed, a limit may now be exhausted, a
window may have closed, the host may have been reclassified. The request is claimed before signing
and the status moves only from pending, so two approvers racing cannot both issue. Requests expire
after thirty minutes — one that never expires is a way to get a command signed weeks later under
conditions nobody re-examined.

**2.4 — Break-glass.** A time-boxed bypass requiring written justification, which fires a
high-severity alert, notifies every admin, and is recorded with maximum prominence. Emergencies
are real; unlogged emergencies are how audits fail.

*Delivered.* A bypass requires a written justification of at least twenty characters and is capped
at four hours — an emergency lasting longer is a situation, and a situation should have a rule.
Two things it deliberately does **not** override: an explicit deny, because a bypass is for
reaching what policy never anticipated rather than doing the one thing it went out of its way to
forbid; and a two-person requirement, because the whole point of that control is that one person
cannot act alone, and a bypass one person can open would remove it. It is surfaced as a
console-wide banner rather than an alert row: alerts are per-host by construction, so a fleet-wide
bypass would have to be attached to an arbitrary host and would read as a finding about that host.

**2.5 — Response playbooks.** Named, versioned, signed sequences of bounded commands — e.g. *on
confirmed FIM drift under `/etc/ssh`: collect journal tail → quarantine the file → isolate*. Every
step is still individually signed and individually policy-checked. This turns the existing
`run_script` / `quarantine_path` primitives (which the paper notes have no UI at all today) into
an operator-visible capability.

*Delivered.* A playbook is not an authority: each step is signed and policy-checked individually
at the moment it runs, against the host it targets, because a sequence executing three commands on
one decision would be a way to smuggle past the engine. A step that is refused or needs a second
approver halts the run rather than being skipped — skipping quietly turns a four-step response
into a three-step one, and the missing step is usually the dangerous one. Binding the triggering
finding into a payload is done on decoded values, never on serialised text: these paths come from
files on a possibly-compromised host, so a crafted filename interpolated into JSON would rewrite
the rest of the command, and that command would then be correctly signed. A placeholder must be
the whole value; embedded ones are refused rather than interpolated.

**2.6 — Opt-in automatic response.** Only now is this safe: playbooks may fire without human
confirmation *when policy allows it*, bounded by blast radius, fully attributed in the ledger.
Preserves the paper's "default is human-approved" principle while removing the ceiling on it.

*Delivered.* Three independent gates must agree: the playbook opts in, its trigger matches, and
policy permits every step. Any one refusing stops it, which is what makes the feature safe to
offer — the human confirmation is replaced by policy rather than removed. A second brake,
independent of policy's limits, suppresses repeat automatic runs of the same playbook on the same
host for an hour: it stops the loop where a playbook triggers on a finding it caused (FIM detects
a change, the playbook quarantines the file, quarantining changes the filesystem, FIM detects
that). Policy limits would eventually stop that too, but only after spending the fleet-wide budget
a real incident needs. Suppression is recorded rather than silent. The one shipped automatic
playbook only reads, and a test enforces that nothing shipped with `automatic: true` changes
state.

**Acceptance:** a policy denial is impossible to bypass through the API; a two-person command
cannot be signed with one approval; blast-radius limits demonstrably stop a runaway playbook;
every decision, including denials, appears in the verifiable ledger.

---

### Phase 3 — Detection worth acting on (4–6 months)

**This is the largest real capability gap.** DefendSec's detection today is entirely *state-based*:
what is installed, what changed on disk between hashes, what is configured. It has no visibility
into *behavior*. `InventoryReport` in the proto carries software, updates, FIM files, and SCA
results — there is no process, network, or authentication telemetry anywhere in the system.

Consequence: DefendSec cannot detect an attack in progress. It can tell you a file changed up to
60 seconds later; it cannot tell you what process changed it, what that process's parent was,
whether it opened a network connection, or whether it is still running. The response capability —
the best part of the product — is currently driven by the weakest possible signal.

**3.1 — eBPF sensor (Linux).** CO-RE + libbpf, shipped inside `defendsec-agentd`:
process execution (`execve` with argv and full parent chain), network connect/accept, file
open/write on watched paths, privilege transitions (setuid/setgid/capability changes), and module
loads. Ring buffer with explicit backpressure and sampling — a sensor that destabilizes the host
under load will be uninstalled.

*Delivered for process execution; network, file, privilege and module events still have no sensor.*

The eBPF sensor is written and runs. It hooks two tracepoints — `syscalls/sys_enter_execve` for
the argument vector and `sched/sched_process_exec` for the resolved path — and emits through a BPF
ring buffer. Every successful exec is seen, with argv as the caller passed it rather than as the
process later rewrote it, which is precisely what the poller could not do.

Three decisions differ from the plan above, each for a reason worth recording.

**cilium/ebpf, not libbpf.** The objection to eBPF was cgo, a kernel matrix, and a build needing
kernel headers. A pure-Go loader that performs CO-RE relocations itself removes all three:
`defendsec-agentd` still cross-compiles to a static binary with `CGO_ENABLED=0`. The compiled BPF
object is committed and embedded, so building the agent needs no clang, no kernel headers and no
libbpf — `make bpf` is the only thing that asks for them.

**Tracepoints, not kprobes.** Tracepoints are a stable kernel ABI. A kprobe on a function whose
signature shifts between releases yields silently wrong fields, and a sensor that is confidently
wrong is worse than one that is absent. Only a single field needs CO-RE at all
(`task->real_parent->tgid` for the parent pid), declared as a minimal relocatable struct rather
than via a generated `vmlinux.h`, so one object works across kernel versions.

**Two tracepoints, not one.** `sys_enter_execve` is the only place argv is reachable, but it also
fires for execs that then fail — a mistyped command, a missing interpreter. Emitting those would
put processes in the console that never ran, and a rule matching `CommandLine` would fire on
something that never executed. So argv is stashed at entry in an LRU hash and claimed at the
success tracepoint; a failed exec leaves its stash to be evicted rather than leaking. There is a
test that runs a deliberately failing exec and requires that nothing is reported for it.

The poller remains, and the agent falls back to it when the kernel lacks a ring buffer (pre-5.8)
or BTF, or when the agent cannot load a program. The fallback is logged at warning level with the
specific reason and the coverage view shows the poller's capability, not the eBPF one: the two have
genuinely different coverage, and an operator who believes they have the first while running the
second has been misled about what their fleet can see. Bounds truncate rather than drop — the
first 16 arguments, 128 bytes each — and truncation is flagged in the event so nothing downstream
presents a clipped command line as the whole thing. Ring-buffer overflow is counted on the kernel
side and reported, because a pipeline that drops silently produces a clean console during exactly
the burst that overwhelmed it.

Still missing, and listed as unobserved in the coverage matrix rather than implied: network
connect/accept, file writes on watched paths, privilege transitions, and module loads. Rules
depending on those kinds cannot fire, and the matrix says so.

**3.2 — Event stream in the protocol.** Add a batched, backpressured event stream to
`AgentToServer`, separate from the 60-second inventory report. Different volume profile
(thousands/sec vs one/minute) and it must degrade by dropping events with an explicit counted gap,
never by blocking inventory or the command channel.

*Delivered.* `EventBatch` on the existing stream, with the buffer dropping rather than blocking:
if it applied backpressure a slow server would become a slow host, and a sensor that destabilises
the host gets uninstalled — at which point coverage is zero rather than degraded. The oldest event
goes first, because an intrusion is a sequence and the recent events are the ones closest to what
is happening now. Gaps are counted per batch and for the lifetime of the agent, logged, written to
the ledger and shown in the coverage view. A pipeline that drops silently produces a clean console
during exactly the incident that overwhelmed it. One detail worth recording: gRPC allows a single
concurrent sender per stream and the command loop already sends acknowledgements, so the shipper
serialises through a mutex — concurrent `Send` corrupts the stream rather than returning an error.
The device id is taken from the mTLS identity, never from the message, or an agent could attribute
its events to another host.

**3.3 — Sigma rule engine.** Adopt **Sigma** rather than inventing a DSL. Thousands of
community-maintained rules exist, operators already know the format, and it gives instant
credibility and coverage. Write a Go evaluator over the event stream; ship a curated starter pack;
let operators drop rules into a directory, signed and versioned like SCA packs.

**3.4 — MITRE ATT&CK mapping and honest coverage matrix.** Tag every rule and alert with technique
IDs, and ship a console page showing coverage — *including what DefendSec cannot see.* An honest
coverage map is rare, extremely well received, and entirely consistent with the Scope page
philosophy the product already has. This is where ATT&CK belongs: it describes adversary
behaviour, so it maps to *detections*. The advisory-side tie-in is the separate CVE-to-ATT&CK
enrichment in §0.3 Tier 3, which answers what an attacker gains by exploiting a given CVE.

*Delivered.* Rules carry ATT&CK tags, matches carry the techniques, and alerts carry them into the
ledger. `GET /v1/detection/coverage` reports the matrix with its blind spots first: the event kinds
no agent has actually reported — a rule for a kind nothing produces can never fire, whatever the
technique list says — the rules that failed to load with their reasons, and the hosts that have
dropped events, named by hostname rather than device id. It states plainly that a technique having
a rule does not mean every way of performing that technique is detected, because ATT&CK techniques
are broad and a rule covers a behaviour.

The console page at **Detection** renders that matrix in the same order, so the first thing on the
screen is what the fleet cannot see: the caveats, then the event kinds that have rules but no
sensor reporting them, then the rules that failed to load, then the hosts losing events, and only
then the techniques that are covered. There is no coverage percentage anywhere on the page, for the
same reason the compliance page carries no score — ATT&CK has no denominator that would make one
honest, and a percentage is where a blind spot disappears into a rounding error. Viewers can read
it; the forwarding section is admin-only, because destination addresses are part of the operator's
infrastructure map.

**3.5 — Process-tree context on alerts.** When an alert fires, attach the process ancestry,
command line, user, and network activity. This is the single thing analysts need most and the
thing state-based tools cannot provide.

*Delivered for process ancestry.* Lineage is recorded for every process event, not only matching
ones, because the parent of a process that alerts later is usually itself unremarkable. Exited
processes are kept for ten minutes: the parent of a suspicious process has very often already
gone, and a lineage that stops at "no longer exists" is the one that matters least. A pid whose
start time changed is treated as a different process, or a reused number would attribute one
process's children to another. The walk is bounded and cycle-safe — a real process table cannot
contain a cycle, but a pid-reuse race in a remembered snapshot can, and an unbounded walk would
hang the alerting path. Network activity on the alert waits on a network sensor.

**3.6 — Retention and forwarding, not a SIEM.** Short server-side window plus a host-side ring
buffer for pre-alert context. Forward everything to the customer's real log platform over
syslog / OTel / webhook. Stay explicitly out of the log-lake business, consistent with §2.

*Delivered, except OTLP.* A few hundred events per host are kept — enough to answer "what else was
this host doing just before" on an alert, which is the first question an analyst asks and the one
a state-based tool cannot answer at all — and everything is forwarded onward. Syslog is RFC 5424
over TCP, TLS or UDP with a JSON payload and RFC 6587 octet framing, because newline framing
breaks on any message containing a newline and JSON payloads routinely do; TCP is the default
because UDP discards silently under load, which is the wrong property for the record of a security
event. Webhook posts batches with a bearer token, and a file destination writes JSON lines for
proving the pipeline or for an air-gapped host. Forwarding is asynchronous and lossy for the same
reason the agent buffer is: a collector that stops accepting connections must not stop DefendSec
matching rules, because a tool that stops defending when its log shipper is unhappy has its
priorities backwards. Drops and delivery failures are counted and reported. OTLP is deliberately
absent and configuring it is an error rather than a silent no-op — a real exporter needs a
substantial dependency and a semantic-convention mapping worth doing properly, and an almost-OTLP
exporter a collector rejects is worse than none.

**3.7 — Grow the SCA engine, then its content.** `internal/sca/sca.go` implements only two check
types — `file_regex` and `inventory_field` — which can express roughly a quarter to a third of a
real benchmark. Add file mode and ownership, mount options, sysctl values, package presence and
absence, systemd unit state, and command-output evaluation. **This blocks all benchmark content,
so the engine work comes first.** Then grow content: `packs/sca/` holds **15 checks across 2 Linux
packs** against roughly 200 for CIS Ubuntu L1. Distribute as signed, versioned packs, tagged with
control IDs per 1.7, and publish coverage as a fraction with its denominator (§3.7).

*Engine delivered; content started.* All six new types are in: file mode and ownership, mount
options, sysctl, package presence and absence, systemd unit state, and command output. The
important decision was scope. A `command` check makes a data file executable, and the same item
wants packs distributed as signed artifacts — at which point "run whatever this YAML says" is
remote code execution with a signature check in front of it, and a signature is a supply-chain
control, not a sandbox. So five of the six were implemented natively and cannot run anything a
pack chooses: file mode uses stat, sysctl reads `/proc/sys`, mount options parse `/proc/mounts`,
and package and unit state call one fixed binary with a fixed argument shape. `command` is the
only general one and is argv-only with an allowlist of read-only tools, fixed resolution
directories, a timeout and an output cap — a reduction in blast radius, stated as such rather than
as a guarantee. `file_mode` compares as a maximum rather than an equality, because benchmarks say
"no more permissive than" and an exact match fails a correctly-hardened host. Packs are refused at
load on an unknown type, a duplicate id, missing fields, a bad regular expression, a
non-allowlisted command — and on a control identifier that is not in the catalog, which caught a
real mistake in the first shipped pack. A new CIS Controls v8 IG1 pack takes the shipped set from
15 checks to 30 across three packs and exercises every type;
`GET /v1/controls/check-coverage` publishes that with its denominator and an explicit disclaimer
that it is not a benchmark and DefendSec is not a certified benchmark scanner. The agent now loads
every pack in the directory rather than two named in code.

**Acceptance:** a reverse shell, a `curl | sh` execution, and an SSH key added to
`authorized_keys` are each detected within seconds, with full process ancestry, mapped to ATT&CK
techniques, and able to trigger a Phase 2 playbook.

---

### Phase 4 — The AI-era control plane (2–3 months) · *the differentiator*

Only credible once Phases 1–2 exist. The pitch is not "AI-powered security" — everyone claims
that and nobody means anything by it. The pitch is:

> **DefendSec is the enforcement layer that makes AI-initiated response safe and provable.**

An AI agent connected to DefendSec *cannot* exceed the bounded command set, *cannot* bypass the
policy engine, *cannot* sign its own authority, and *cannot* act without leaving a cryptographic
record. That is a claim no EDR with a remote shell can make, at any price.

**4.1 — MCP server.** Expose fleet state, alerts, advisories, host detail, and allowlisted live
queries as read operations, plus the ability to *propose* actions. Proposals enter the same policy
engine as human requests. The AI never holds signing authority.

*Delivered.* `internal/mcp` implements MCP revision `2026-07-28` — the stateless one: no
`initialize` handshake, no session id, no server-initiated requests, with version, client identity
and capabilities carried per request. That statelessness is the property worth having here, because
it means an agent's authority comes from the credential on each request and from nothing it
established earlier. The server is dual-era and also answers the handshake most clients in the
field still speak; a spec-pure server nobody can connect to has shipped nothing.

The protocol layer knows nothing about DefendSec. It has no access to the signer and no ability to
issue a command, so a protocol bug cannot become an authority bug. Origin is validated before the
credential is read, header/body agreement is enforced (an intermediary may route on the header
while the server acts on the body, and a disagreement means one of them is being lied to), and a
missing authorization hook denies everything rather than allowing it.

**An agent is a principal, not a user, and that is the whole design.** The alternative was a third
role on the users table, which would have been less code and a worse guarantee: a role is a string
compared at every call site, and "an agent cannot sign its own authority" would then rest on every
one of those comparisons being written correctly, forever. Agent principals live in their own
table, and the admin API resolves callers only against users and sessions. An agent token presented
to the command endpoint is not an under-privileged caller — it is not a caller the admin API can
see at all, and there is a test that asserts exactly that.

**DefendSec does not call a model.** This is a server; an agent runs wherever its operator runs it
and connects inward. There is no API key, no outbound dependency on any AI service, and no path by
which fleet data leaves the box to a model provider. For self-hosted security software that is not
a limitation but the only defensible design.

The endpoint is off unless `DEFENDSEC_MCP_ADDR` is set, on its own listener rather than a path on
the admin mux, so it can be bound and firewalled separately.

**4.2 — Propose-and-sign workflow.** Console surface for AI-proposed actions showing the model's
reasoning, the evidence cited, and the exact bounded command proposed. A human reviews and signs.
Model identity and prompt provenance are recorded in the ledger alongside the human approver, so
an auditor can reconstruct not just what was done but what recommended it.

*Delivered, except the console surface.* A proposal is written to `pending_commands` — the same
table a human request awaiting approval goes into, which is the point: an AI proposal and an
unsigned human request are structurally the same object, and neither carries a signature. The
columns added are the part an auditor needs that a human request does not have: the proposing
agent, its declared model, the reasoning verbatim, the DefendSec record ids it cited, and the
prompt it says it was given.

Four things are enforced rather than intended, each with a test:

- **The agent's own approval does not count.** A human requester self-approves, because they asked
  for it. An agent does not — if it did, a one-approval rule would let an AI act unsupervised. The
  asymmetry lives on the write path in `CreatePendingCommand`, not in whoever assembles the
  request.
- **A permit-outright policy still needs a human.** Where policy would have let a human act with no
  approval at all, an agent proposal still lands unsigned with one approval required. Collapsing
  those two cases is how a product ends up with an AI that acts on its own.
- **A human approval cannot launder a proposal past an agent rule.** An approved proposal is
  re-evaluated as role `agent`, not promoted to `admin`. Otherwise an operator clicking approve
  would walk the proposal past the very rule written to bound agents, and the bound would hold only
  until somebody was busy. The rule binds at signing time or it does not bind at all.
- **Deny-by-default extends to the AI.** A policy that permits humans and says nothing about agents
  permits an agent nothing.

The proposable command set is narrower than the human one. `run_script` and `agent_update` are
absent: the first is arbitrary code and the second replaces the agent enforcing everything else. A
bounded command set that includes "run this script" is not bounded, whatever policy would say
afterwards. Break-glass is deliberately not consulted on the proposal path either — an emergency is
a human declaring an emergency, and letting it widen what an AI may propose would turn the worst
moment to be careful into the moment the bounds came off.

Writing this caught one real defect. `Propose` originally checked the principal it was handed,
which made "a revoked agent cannot propose" depend on every caller having refreshed its copy first
— an obligation that holds until somebody writes a new caller. It now re-reads the principal, so a
revocation that lands mid-conversation bites on the next call.

*The console surface is now delivered too.* A **Proposals** page shows each unsigned proposal with
the model's reasoning, the evidence it cited, the prompt it says it was given, the declared model
marked self-reported, the policy rule that let it through, and the exact command and payload — with
approve and reject controls placed *after* the case rather than before it, so an operator who has
reached the button has at least been shown the argument.

The Response page no longer lists proposals in its generic approvals queue. They are the same
object in storage, which is deliberate, but they are not the same thing to review: a proposal shown
as a bare pending command invites approving it without the reasoning that is the only thing making
it reviewable. The two are partitioned, and the Response page links across.

Approval itself was API-only before this and is now wired through the console. The route forwards
the operator's own token and relays the control plane's answer verbatim, including a refusal —
rewriting it locally would give the operator a friendlier second account of something the ledger
records differently. The page states that policy is re-evaluated at signing time, so an approval is
not a guarantee the command will issue.

The partition predicate lives in a module with no server-only imports, both so it can be tested and
because a client component reaching it through the server-side policy client pulled `next/headers`
into the browser bundle — a constraint neither `tsc` nor the linter catches, only `next build`.

**4.3 — Triage assistance.** Alert summarization; FIM drift explanation (diff the file, identify
its owning package, correlate against the pending-update list — *"this changed because
`openssh-server` was upgraded 4 minutes earlier"* is both an excellent auto-resolve signal and an
excellent demo); suggested follow-up queries drawn only from the existing allowlist.

*Delivered, and deliberately not as a prompt.* This is filed under the AI control plane and it
would have been easy to make it a model call. It is deterministic correlation instead, for two
reasons: "was this file rewritten by a package upgrade?" has a factual answer in stored data, and a
self-hosted security product that needs an outbound API call to triage an alert is one that stops
triaging when the network is the thing under attack. The same explanation is served to the console
and to an agent over MCP, so the operator and the model read the same analysis rather than two that
can disagree.

**The example in the paragraph above was not answerable when it was written.** Software inventory
was a JSONB snapshot overwritten on every heartbeat, so there was no record that a package had ever
changed version — only what was installed now. Migration 014 adds `package_changes`, recording
transitions as they are observed, which also answers a compliance question that was previously
unanswerable: when was this host actually patched, as opposed to when did it last report updates
available. The first inventory from a host records nothing rather than reporting every installed
package as newly appeared.

**It explains; it does not resolve.** The roadmap calls a package-upgrade correlation "an excellent
auto-resolve signal" and this stops deliberately short of that. A package upgrade immediately
before a security-relevant configuration file changes is both the most common innocent explanation
and exactly the cover an attacker would choose — an upgrade of `openssh-server` does not stop a
`PermitRootLogin` line from having been added by hand in the same window. So every explanation
carries the timeline it rests on, a caveat saying what it does not establish, and the specific
checks that would settle it. `AutoResolvable` exists as a field that is always false, so nothing
downstream can mistake a confident verdict for permission to close the alert.

Five verdicts, and the useful one is negative: `unexplained` means nothing on the host accounts for
the change, which is what makes `package-upgrade` mean anything. `package-activity` is the case a
naive implementation gets wrong — packages changed nearby but none of them owns the file, which is
not an explanation and would have resolved an intrusion. `local-change` is stronger than
unexplained: the path belongs to no package, so an upgrade *cannot* be the cause.
`unknown-ownership` refuses to draw a conclusion at all, because the absence of a correlation means
nothing when ownership was never resolved.

Path ownership comes from a curated map covering the paths DefendSec watches by default, with
drop-in files inheriting their directory's owner. The authoritative answer is the package manager's
own (`dpkg -S`, `rpm -qf`), which would need a new agent capability and is worth doing later; until
then anything outside the map returns no owner rather than a guess, because a wrong owner produces
a confident explanation of the wrong thing.

Summarisation is grouping and counting rather than prose: clustering is on (kind, title), which is
crude on purpose — a cleverer similarity measure would group things that merely look alike, and an
operator who trusts a cluster that silently swallowed an unrelated alert is worse off than one
reading a longer list. Alerts that group with nothing else are called out separately, because on a
busy fleet the lone alert is usually the one worth reading and a queue sorted by time buries it.

Follow-up suggestions are drawn only from the operator's own saved queries and never generated. The
live-query surface is an allowlist precisely so arbitrary queries cannot be run; suggesting one
DefendSec invented would route around that allowlist using the operator's credentials.

**4.4 — Bounded autonomy.** Optional per-policy autonomous execution, constrained by Phase 2 blast
radius, with every action attributed to the model in the signed ledger and trivially revocable.
The operator sets the ceiling; the cryptography enforces it.

**Acceptance:** an AI agent can triage an alert, gather evidence via allowlisted queries, and
propose a bounded response; the proposal is unsignable without a human approver; the ledger
records model identity, reasoning, and the approving human, and `defendsec verify` validates the
whole chain.

---

### Phase 5 — Reach and durability (ongoing)

**5.1 — Windows, properly.** The paper concedes packaging "remains a placeholder rather than a
complete supported service installer." Ship a real service, MSI packaging, and **ETW**-based
telemetry as the eBPF analogue, plus BitLocker / Defender / firewall posture. Windows is where the
endpoints are.

**5.2 — macOS.** EndpointSecurity framework for process and file events (requires an Apple
developer account and entitlement — start the request early, it is slow), with FileVault, XProtect
and firewall posture.

**5.3 — HTTPS by default.** Port 47261 shipping plain HTTP by default is a credibility problem for
a security product, and the paper has to caveat it in four separate places. Generate a self-signed
certificate at install, support ACME/Let's Encrypt, and make plain HTTP an explicit opt-out for
isolated labs. Then delete the caveats.

*Delivered.* Next.js does not serve HTTPS in production and the documented answer is a reverse
proxy, so DefendSec ships one — `defendsec-web` — rather than asking every operator to install and
configure their own, which most single-container deployments will not do. It takes port 47261, the
port operators and the agent installer already use, and the console moves behind it on a
loopback-only port: the plain-HTTP surface is not reachable off the box at all. Three certificate
modes: self-signed generated on first start (works on a LAN with no DNS and no internet; the
browser warns, which is honest, and it is still strictly better than plain HTTP where the admin
token is readable by anything on the path), ACME with an allowlist of names the operator actually
configured, and a file from an internal CA. Plain HTTP remains available as `DEFENDSEC_TLS=off`,
logged loudly at every start; an *unrecognised* value refuses to start rather than falling back,
since silently serving plain HTTP because somebody typed `tls` instead of `on` would undo the
point. The generated certificate is reused across restarts — a new fingerprint every restart
trains operators to click through the warning — always covers loopback so the console is reachable
when DNS is wrong, and is regenerated on approaching expiry or when a hostname is added. The
startup log prints its SHA-256 so the browser's warning can be verified rather than dismissed.
Cookies now default to Secure. Writing the proxy caught a real bug: `SetXForwarded` derives the
proto from the inbound connection and overwrites whatever was set before it, so setting the
headers first silently lost them — and the console would have dropped the Secure cookie flag
exactly when TLS was on. The caveats in README.md and INSTALL.md are gone.

**5.4 — Enterprise identity (SSO/OIDC).** Completes Phase 1.0. Group-to-role mapping, session
management, and per-user attribution throughout the ledger.

**5.5 — Scale past the homelab, and meet retention minimums.** Two hard caps today:
`internal/cmdlog` keeps a **500-record ring buffer** — silently discarding privileged-action
history regardless of age, which is exactly the record CJIS Policy Area 4 requires kept for a year
— and JSON files back much of the state. Alert retention also defaults to 90 days against a CJIS
minimum of one year (§3.11). Replace the ring buffer with age-based retention and raise the
defaults. Move to Postgres-primary with JSON as an export
format, add pagination and server-side filtering across the console, and load-test to 10k hosts.
Until this is done, fleet size is bounded by a Go slice.

*Partly delivered — the retention half.* The ring buffer is gone: privileged-action history is now
kept by age, defaulting to one year, and the remaining count cap is a size safety valve that logs
at error level when crossed rather than discarding silently. Alert retention was raised from 90
days to the same one-year minimum. This was not cosmetic — Phase 1.9's compliance view claims to
evidence CJIS Policy Area 4, and a 500-record cap could push a month of signed actions out of the
file in an afternoon while the console reported the control as satisfied. `GET /v1/retention`
reports the windows in force *and how much history is actually held*, because retention
configuration does not create history that was never recorded: a one-year policy on a system
installed last month evidences one month, and an assessor will ask. The Postgres-primary move,
pagination and the 10k-host load test remain.

**5.6 — Integrations.** Prometheus metrics, OTel traces, syslog/CEF export, webhook and Slack/Teams
alerting, and Terraform/Ansible modules for provisioning. Be the best-behaved citizen in someone
else's stack.

**5.7 — Supply-chain hardening for DefendSec itself.** A tool making provenance claims must hold
itself to them: reproducible builds, SLSA provenance attestations, signed releases (cosign),
published SBOMs. CI already runs TruffleHog secret scanning and govulncheck — extend that to
release artifacts. This is also a natural marketing artifact: *verify our binaries with the same
tooling we give you for your fleet.*

---

## 5. Recommended sequence

Ordered by (impact × credibility) ÷ effort:

1. **Phase 0.1–0.4** — fix the comparator and backport handling, then replace the hand-curated
   catalog with synced feeds and a data model that can hold them. *Nothing else matters while the
   tool reports patched hosts as vulnerable.* Add **CISA KEV and EPSS** early: they are small,
   cheap feeds and they change the Advisories page from a list into a priority queue.
2. **Phase 1.0** — per-user identity. Small, and everything downstream depends on it.
3. **Phase 1.1–1.4** — persist signatures, chain the audit log, sign acks, ship `defendsec verify`.
   *This is the moat, and it is mostly plumbing around crypto that already works.*
4. **Phase 1.7 – 1.8** — control mapping and the audit-period model, plus the FIPS decision.
   Retrofitting the mapping later means re-tagging every record type; discovering a FIPS
   constraint later means reworking the signing path.
5. **Phase 2.1–2.3** — policy engine, blast radius, two-person integrity.
6. **Phase 5.3** — HTTPS by default. Cheap; removes a standing credibility objection.
7. **Phase 3.7 engine work, then one framework** — CIS Controls v8 IG1 first, then 800-171/CMMC.
   Enough coverage to be credible, published as a fraction, never as completeness.
8. **Phase 3** — eBPF and Sigma. The long pole; start it in parallel once 1–2 are underway.
9. **Phase 4** — the AI layer, on top of the guarantees built in 1–2.

Phases 0, 1, and 2 are roughly four to six months of focused work and are enough to change what
the product *is*. Phase 3 is the largest investment and can proceed in parallel with 4.

---

## 6. White paper revisions to make alongside this work

- **Lead with the differentiator.** Move signed, bounded, provable response from Section 12 into
  the executive overview. Open the paper with the comparison table from §1 of this document.
- **Reframe Section 18.** "Bounded named commands; no arbitrary remote shell" belongs under design
  strengths, not limitations. The current phrasing — *"with less general remote administration
  power"* — concedes an argument that should be won.
- **Correct the inspectability claim** in Section 1 until Phase 1 ships, or ship Phase 1 first and
  strengthen the claim to something no competitor can match.
- **Add a threat model section.** What DefendSec defends against, what it does not, and explicitly:
  what remains true when the server itself is compromised. After Phase 1.6, that answer becomes
  genuinely interesting.
- **Publish the coverage matrix** (Phase 3.4) as an appendix. Honest coverage maps build more trust
  than feature lists, and this product has already demonstrated it understands that.

---

## 7. Success metrics

| Dimension | Today | Target after Phases 0–2 |
| --- | --- | --- |
| Advisory false-positive rate on a fully-patched host | Unmeasured; structurally high | Zero on supported distros |
| Vulnerability intelligence | Hand-curated local catalog, no sync | Synced distro/OSV/CVE feeds, KEV + EPSS prioritised |
| Finding reproducibility | None — catalog state not recorded | Pinned to a signed catalog snapshot |
| Works on an air-gapped network | Catalog goes stale silently | Signed offline bundles, verified on import |
| Time to produce audit evidence for an incident | Manual assembly across 4 console pages | One signed export, verifiable offline |
| Detectable tampering with the action record | None — plain mutable table | Any edit detected and localized |
| Actions attributable to a specific human | No — shared admin token | Every action, cryptographically |
| Destructive action safeguards | UI confirmation dialog | Policy engine + blast radius + two-person integrity |
| Mean time to detect an active intrusion | Not possible — no behavioral telemetry | Seconds, with process ancestry *(Phase 3)* |
| Evidence that a control operated across an audit period | Not representable — no history model | Signed per-control export over any window |
| NIST 800-171 technical requirements evidenced | Unmapped | Mapped, with the denominator published |

---

## 8. The one-line summary

DefendSec has quietly built the hardest part of a category-defining product — a cryptographically
bounded action channel — and is currently describing it as a limitation while competing on an axis
it cannot win. Keep the signatures, chain the log, govern the actions by policy, give it real
behavioral eyes, and let AI drive it through a path it can never escape.

Then sell it as what the frameworks have been asking for all along: not another scanner that
asserts your hosts were configured correctly, but a system that *proves* your controls operated,
to an assessor who does not have to trust you.

That is a product nobody else is selling.
