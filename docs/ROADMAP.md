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

## 4. Roadmap

Six phases. Each is independently shippable. Effort estimates assume one experienced engineer.

| Phase | Theme | Effort | Why now |
| --- | --- | --- | --- |
| **0** | Trustworthy findings | 3–5 weeks | A scanner that cries wolf gets switched off. Blocks everything. |
| **1** | Provable action ledger | 6–10 weeks | Builds the moat. Cheap — the crypto already exists. |
| **2** | Policy-governed response | 6–8 weeks | Makes automation safe. Prerequisite for Phase 4. |
| **3** | Behavioral detection | 4–6 months | Largest capability gap. Earns the right to act. |
| **4** | AI-era control plane | 2–3 months | The cutting-edge story. Only credible after 1–2. |
| **5** | Reach and durability | Ongoing | Platform parity, scale, enterprise identity. |

---

### Phase 0 — Make findings trustworthy (3–5 weeks) · *blocks everything else*

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

**0.3 — Make feed freshness visible and honest.** The paper says catalog freshness "is an operator
responsibility," which is fair, but the console currently gives no signal. Add feed age to the
Advisories page and to the Fleet dashboard, and raise a system alert when any feed exceeds a
threshold. Stale intel presented as current is worse than no intel.

**0.4 — Ship the OSV/distro ingest as a first-class service.** `scripts/ingest-osv.py` (201 lines,
with a `.timer.md` *sketch*) should become a supported unit in `packaging/systemd/` with status
reported in the console, not a script an operator is expected to find and wire up.

**Acceptance:** dpkg/rpm comparator passes upstream vector suites; a fully-patched Ubuntu 22.04
and Rocky 9 host produce **zero** advisory findings; every finding names its source feed and feed
date; feed staleness raises an alert.

---

### Phase 1 — The provable action ledger (6–10 weeks) · *the moat*

Convert "we log what happened" into "we can prove what happened, and prove the log wasn't edited."
The signing primitives in `internal/sign/` are already correct; this phase keeps and chains their
output.

**1.0 — Per-user identity (prerequisite).** Non-repudiable attribution is impossible when every
administrator shares one bearer token. Today `actor` defaults to the literal string `'admin'`
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

**1.6 — Transparency anchoring (optional, high-leverage).** Periodically publish signed checkpoint
hashes somewhere the server cannot retroactively control: an RFC 3161 timestamp authority, a
transparency log, a peer DefendSec instance, or a git repository. This defeats an attacker who
fully compromises the server *and* the database — they can stop new entries but cannot rewrite
anchored history. Very few products at any price can make this claim.

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

**2.2 — Host classes and blast-radius limits.** Tag hosts (`production`, `critical`,
`domain-controller`). Express limits like *"at most 3 isolates fleet-wide per hour"* and *"never
`kill_process` on a host tagged `critical` without a second approver."* Rate limits and blast
radius are what separate a response tool from an outage generator.

**2.3 — Two-person integrity.** Destructive commands require a second administrator's signature.
Both signatures are stored in the ledger and both are checked by `defendsec verify`. This is a
standing request in regulated environments and nothing free offers it.

**2.4 — Break-glass.** A time-boxed bypass requiring written justification, which fires a
high-severity alert, notifies every admin, and is recorded with maximum prominence. Emergencies
are real; unlogged emergencies are how audits fail.

**2.5 — Response playbooks.** Named, versioned, signed sequences of bounded commands — e.g. *on
confirmed FIM drift under `/etc/ssh`: collect journal tail → quarantine the file → isolate*. Every
step is still individually signed and individually policy-checked. This turns the existing
`run_script` / `quarantine_path` primitives (which the paper notes have no UI at all today) into
an operator-visible capability.

**2.6 — Opt-in automatic response.** Only now is this safe: playbooks may fire without human
confirmation *when policy allows it*, bounded by blast radius, fully attributed in the ledger.
Preserves the paper's "default is human-approved" principle while removing the ceiling on it.

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

**3.2 — Event stream in the protocol.** Add a batched, backpressured event stream to
`AgentToServer`, separate from the 60-second inventory report. Different volume profile
(thousands/sec vs one/minute) and it must degrade by dropping events with an explicit counted gap,
never by blocking inventory or the command channel.

**3.3 — Sigma rule engine.** Adopt **Sigma** rather than inventing a DSL. Thousands of
community-maintained rules exist, operators already know the format, and it gives instant
credibility and coverage. Write a Go evaluator over the event stream; ship a curated starter pack;
let operators drop rules into a directory, signed and versioned like SCA packs.

**3.4 — MITRE ATT&CK mapping and honest coverage matrix.** Tag every rule and alert with technique
IDs, and ship a console page showing coverage — *including what DefendSec cannot see.* An honest
coverage map is rare, extremely well received, and entirely consistent with the Scope page
philosophy the product already has.

**3.5 — Process-tree context on alerts.** When an alert fires, attach the process ancestry,
command line, user, and network activity. This is the single thing analysts need most and the
thing state-based tools cannot provide.

**3.6 — Retention and forwarding, not a SIEM.** Short server-side window plus a host-side ring
buffer for pre-alert context. Forward everything to the customer's real log platform over
syslog / OTel / webhook. Stay explicitly out of the log-lake business, consistent with §2.

**3.7 — Grow the SCA engine, then its content.** `internal/sca/sca.go` implements only two check
types — `file_regex` and `inventory_field` — which can express roughly a quarter to a third of a
real benchmark. Add file mode and ownership, mount options, sysctl values, package presence and
absence, systemd unit state, and command-output evaluation. **This blocks all benchmark content,
so the engine work comes first.** Then grow content: `packs/sca/` holds **15 checks across 2 Linux
packs** against roughly 200 for CIS Ubuntu L1. Distribute as signed, versioned packs, tagged with
control IDs per 1.7, and publish coverage as a fraction with its denominator (§3.7).

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

**4.2 — Propose-and-sign workflow.** Console surface for AI-proposed actions showing the model's
reasoning, the evidence cited, and the exact bounded command proposed. A human reviews and signs.
Model identity and prompt provenance are recorded in the ledger alongside the human approver, so
an auditor can reconstruct not just what was done but what recommended it.

**4.3 — Triage assistance.** Alert summarization; FIM drift explanation (diff the file, identify
its owning package, correlate against the pending-update list — *"this changed because
`openssh-server` was upgraded 4 minutes earlier"* is both an excellent auto-resolve signal and an
excellent demo); suggested follow-up queries drawn only from the existing allowlist.

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

**5.4 — Enterprise identity (SSO/OIDC).** Completes Phase 1.0. Group-to-role mapping, session
management, and per-user attribution throughout the ledger.

**5.5 — Scale past the homelab.** Two hard caps today: `internal/cmdlog` keeps a **500-record ring
buffer** and JSON files back much of the state. Move to Postgres-primary with JSON as an export
format, add pagination and server-side filtering across the console, and load-test to 10k hosts.
Until this is done, fleet size is bounded by a Go slice.

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

1. **Phase 0.1–0.2** — fix the version comparator and backport handling. *Nothing else matters
   while the tool reports patched hosts as vulnerable.*
2. **Phase 1.0** — per-user identity. Small, and everything downstream depends on it.
3. **Phase 1.1–1.4** — persist signatures, chain the audit log, sign acks, ship `defendsec verify`.
   *This is the moat, and it is mostly plumbing around crypto that already works.*
4. **Phase 1.7** — control mapping and the audit-period model. Do it here; retrofitting it later
   means re-tagging every record type.
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
