import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CHECK_ORDER,
  certDaysLeft,
  CHECK_ORDER_GOOGLE,
  checkLabel,
  identityUnconfirmedNote,
  identityWhere,
  isIdentityResponse,
  looksLikeEmail,
  looksLikeGuid,
  looksLikeTenant,
  parseList,
  providerLabel,
  runResultLabel,
} from "./identity-model.ts";
import { identityCard, identityTotal, identityTrendSummary, providerNames } from "./identity-exposure.ts";
import { fixDescription, fixEmptyText, fixTotal } from "./surface-exposure.ts";
import {
  compareRank,
  isIdentityRow,
  isRanked,
  rankBand,
  rankReason,
  type ExposureGroup,
  type IdentitySummary,
  type Rankable,
  type TrendPoint,
} from "./exposure-model.ts";

const NOW = Date.parse("2026-10-24T12:00:00Z");

function summary(over: Partial<IdentitySummary> = {}): IdentitySummary {
  return {
    configured: true,
    provider: "m365",
    findings: 6,
    bySeverity: { critical: 2, high: 1, medium: 2, low: 1 },
    lastRunAt: "2026-10-24T10:00:00Z",
    lastStatus: "ok",
    lastReason: "",
    checksNotAssessed: 0,
    checksTotal: 4,
    ...over,
  };
}

// ---- the Fleet card -----------------------------------------------------------------------------

test("the card reads: N findings (x critical, y high), last read <time>", () => {
  const c = identityCard(summary(), NOW);
  assert.equal(c.state, "read");
  assert.equal(c.tone, "critical");
  assert.equal(c.headline, "Identity (Microsoft 365): 6 findings (2 critical, 1 high), last read 2 hours ago");
  assert.deepEqual(c.lines, []);
});

test("a tenant that was never connected or read is not a clean result", () => {
  assert.equal(identityCard(undefined, NOW).state, "unavailable");
  assert.match(identityCard(undefined, NOW).lines[0], /Nothing here says the accounts are in good order/);
  const none = identityCard(summary({ configured: false, findings: 0, lastStatus: "" }), NOW);
  assert.equal(none.state, "not-configured");
  assert.equal(none.tone, "neutral");
  assert.match(none.headline, /no Microsoft 365 tenant or Google Workspace domain connected/);
  const unread = identityCard(summary({ findings: 0, lastStatus: "", lastRunAt: null }), NOW);
  assert.equal(unread.state, "unread");
  assert.match(unread.lines[0], /not a clean result/);
});

test("zero findings is good only when the read assessed every check", () => {
  const good = identityCard(summary({ findings: 0, bySeverity: {} }), NOW);
  assert.equal(good.tone, "good");
  assert.match(good.headline, /0 findings \(none high or critical\)/);

  const partial = identityCard(summary({ findings: 0, bySeverity: {}, lastStatus: "partial", checksNotAssessed: 1 }), NOW);
  assert.equal(partial.tone, "neutral");
  assert.match(partial.lines[0], /1 of 4 checks could not run.*missing evidence, not counted as passing/);

  const mailboxes = identityCard(summary({ findings: 0, bySeverity: {}, lastStatus: "partial", checksNotAssessed: 0 }), NOW);
  assert.match(mailboxes.lines[0], /Some mailboxes could not be read/);

  const nothing = identityCard(summary({ findings: 0, bySeverity: {}, lastStatus: "not_assessed", checksNotAssessed: 4, lastReason: "Microsoft refused the application's credentials" }), NOW);
  assert.equal(nothing.tone, "neutral");
  assert.match(nothing.lines[0], /could not assess anything \(Microsoft refused/);
  assert.match(nothing.lines[0], /not a clean result/);
});

test("findings without a critical or high one are a warning, not an alarm", () => {
  const c = identityCard(summary({ findings: 2, bySeverity: { medium: 2 } }), NOW);
  assert.equal(c.tone, "warning");
  assert.match(c.headline, /2 findings \(none high or critical\)/);
});

// ---- ranking: identity rows rank by severity under the surface rules ----------------------------

function idRow(key: string, severity: "critical" | "high" | "medium" | "low"): Rankable {
  return { advisoryId: `identity:${key}`, severity, kev: false, kevAdded: null, epss: null, cvss: null, source: "identity" };
}

function vuln(id: string, over: Partial<Rankable> = {}): Rankable {
  return { advisoryId: id, severity: "medium", kev: false, kevAdded: null, epss: null, cvss: null, ...over };
}

test("identity rows join the order like surface findings do", () => {
  const want: Rankable[] = [
    vuln("kev", { kev: true, kevAdded: "2021-01-01", epss: 0.001, cvss: 1 }),
    idRow("000000000005", "critical"),
    idRow("000000000009", "critical"),
    { advisoryId: "surface:000000000002", severity: "critical", kev: false, kevAdded: null, epss: null, cvss: null, source: "surface" },
    idRow("000000000001", "high"),
    vuln("epss-0.9", { epss: 0.9, cvss: 2 }),
    vuln("cvss-only-9.8", { cvss: 9.8, severity: "critical" }),
    idRow("000000000003", "medium"),
    vuln("cvss-only-4.3", { cvss: 4.3 }),
    idRow("000000000004", "low"),
    vuln("cvss-only-1.0", { cvss: 1.0, severity: "low" }),
  ];
  const shuffled = [...want];
  for (let i = 0; i < shuffled.length; i++) {
    const j = (i * 5 + 2) % shuffled.length;
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  shuffled.sort(compareRank);
  assert.deepEqual(shuffled.map((r) => r.advisoryId), want.map((r) => r.advisoryId));
  assert.equal(isRanked(want), true);
});

test("an identity row reads nothing but its severity", () => {
  const odd: Rankable = { ...idRow("000000000001", "medium"), kev: true, epss: 0.99, cvss: 10, kevAdded: "2026-01-01" };
  assert.ok(compareRank(odd, vuln("v", { epss: 0.01, cvss: 1 })) > 0);
  assert.equal(rankBand(odd), 2);
  assert.equal(rankBand(idRow("1", "critical")), 1);
  assert.equal(rankBand(idRow("1", "high")), 1);
  assert.equal(rankBand(idRow("1", "low")), 2);
  assert.ok(compareRank(vuln("z", { kev: true, kevAdded: "2019-01-01", epss: 0.001, cvss: 1 }), idRow("000000000001", "critical")) < 0);
  assert.equal(isIdentityRow(idRow("1", "low")), true);
  assert.equal(isIdentityRow(vuln("x")), false);
});

test("why an identity row ranks where it does", () => {
  const urgent = rankReason(idRow("000000000001", "critical"));
  assert.match(urgent.headline, /In effect now in the client's tenant/);
  assert.match(urgent.text, /no exploit/);
  assert.match(urgent.text, /critical severity/);
  assert.match(urgent.text, /after exploited vulnerabilities and before every other vulnerability/);
  const rest = rankReason(idRow("000000000001", "medium"));
  assert.match(rest.headline, /No exploitation signal \(identity finding\)/);
  assert.match(rest.text, /ranked by severity medium/);
});

// ---- the Fix this week totals --------------------------------------------------------------------

const fixable = (over: object = {}) => ({
  findings: 4,
  advisories: 3,
  hosts: 2,
  kev: { findings: 1, advisories: 1 },
  surface: 2,
  identity: 5,
  ...over,
});

test("the list total counts identity findings; an older control plane's total still works", () => {
  assert.equal(fixTotal(fixable({ total: 10 })), 10);
  assert.equal(fixTotal(fixable()), 3 + 2 + 5);
  assert.equal(fixTotal({ findings: 1, advisories: 1, hosts: 1, kev: { findings: 0, advisories: 0 } }), 1);
  assert.equal(identityTotal(fixable()), 5);
  assert.equal(identityTotal({ findings: 0, advisories: 0, hosts: 0, kev: { findings: 0, advisories: 0 } }), 0);
});

test("the description names identity findings beside the others", () => {
  const d = fixDescription({ fixable: fixable() }, 5);
  assert.match(d, /3 vulnerabilities with a fix to install/);
  assert.match(d, /2 external surface findings/);
  assert.match(d, /5 identity findings/);
  assert.match(fixDescription({ fixable: fixable({ advisories: 0, surface: 0, identity: 1 }) }, 1), /1 identity finding\./);
  assert.match(fixDescription({ fixable: fixable({ advisories: 0, surface: 0, identity: 0 }) }, 0), /no external or identity finding open/);
});

test("an empty list is good news only about what was actually read", () => {
  const hosts = { total: 4, assessed: 4, notAssessed: 0, silent: 0, silentList: [] };
  const surface = { assets: 1, unauthorised: 0, scanned: 1, findings: 0, bySeverity: {}, info: 0, assetsAffected: 0, lastScanAt: null, checksNotAssessed: 0 };
  assert.match(fixEmptyText({ hosts, surface, identity: summary({ findings: 0 }) }), /No identity finding is open\.$/);
  assert.match(fixEmptyText({ hosts, surface, identity: summary({ configured: false, lastStatus: "" }) }), /No Microsoft 365 tenant or Google Workspace domain is connected, so that says nothing about the accounts/);
  assert.match(fixEmptyText({ hosts, surface, identity: summary({ lastStatus: "" }) }), /has not been read yet/);
  assert.match(fixEmptyText({ hosts, surface, identity: summary({ lastStatus: "not_assessed", findings: 0 }) }), /could not assess anything/);
  assert.doesNotMatch(fixEmptyText({ hosts, surface }), /identity|Microsoft 365/);
});

// ---- the trend sentence --------------------------------------------------------------------------

function pt(day: string, identity: number, known: boolean): TrendPoint {
  return { day, known: true, open: 0, kev: 0, watch: 0, identity, identityHigh: 0, identityKnown: known };
}

test("the identity trend sentence is checkable, or says why there is none", () => {
  assert.match(identityTrendSummary([pt("2026-10-22", 0, false)], null), /No identity read has run yet/);
  assert.match(identityTrendSummary([pt("2026-10-22", 0, false)], "2026-10-24T00:00:00Z"), /No identity read in this window/);
  assert.equal(
    identityTrendSummary([pt("2026-10-20", 0, false), pt("2026-10-21", 6, true), pt("2026-10-24", 4, true)], "x"),
    "4 open identity findings on 2026-10-24, down 2 since 2026-10-21 (6).",
  );
  assert.match(identityTrendSummary([pt("2026-10-21", 1, true), pt("2026-10-22", 1, true)], "x"), /unchanged/);
  assert.match(identityTrendSummary([pt("2026-10-21", 1, true), pt("2026-10-22", 3, true)], "x"), /up 2/);
});

// ---- rows and labels ------------------------------------------------------------------------------

function group(over: Partial<NonNullable<ExposureGroup["identity"]>> = {}): Pick<ExposureGroup, "identity"> {
  return {
    identity: {
      findingId: 1, provider: "m365", subject: "casey@example.com · Intuit stuff", check: "inbox-rules", id: "inbox_rule.hides_mail", key: "u/r",
      detail: "d", fix: "f", lastSeen: "2026-10-23T08:00:00Z", unconfirmed: false, ...over,
    },
  };
}

test("a row says where it is: provider, check, account or rule", () => {
  assert.equal(identityWhere(group()), "Microsoft 365 · Inbox rules · casey@example.com · Intuit stuff");
  assert.equal(identityWhere({}), "");
  assert.equal(providerLabel("google"), "Google Workspace");
  assert.equal(providerLabel("m365"), "Microsoft 365");
  assert.equal(checkLabel("mfa"), "MFA registration");
  assert.equal(checkLabel("something-new"), "something-new");
  assert.deepEqual([...CHECK_ORDER], ["mfa", "legacy-auth", "admin-roles", "inbox-rules"]);
});

test("a row whose check could not run says it is shown from the last confirmation", () => {
  assert.equal(identityUnconfirmedNote(group()), "");
  assert.equal(identityUnconfirmedNote({}), "");
  assert.match(identityUnconfirmedNote(group({ unconfirmed: true })), /Inbox rules check could not cover this: shown from the last confirmation on 2026-10-23/);
});

test("the drawer answer is told apart by its source", () => {
  assert.equal(isIdentityResponse({ source: "identity" }), true);
  assert.equal(isIdentityResponse({ source: "surface" }), false);
  assert.equal(isIdentityResponse({}), false);
  assert.equal(isIdentityResponse(null), false);
});

test("run results use the page's words", () => {
  assert.equal(runResultLabel("ok"), "read");
  assert.equal(runResultLabel("partial"), "partly read");
  assert.equal(runResultLabel("not_assessed"), "not assessed");
});

test("the settings form checks IDs before it asks", () => {
  assert.equal(looksLikeGuid("aaaaaaaa-1111-4222-8333-444444444444"), true);
  assert.equal(looksLikeGuid(" aaaaaaaa-1111-4222-8333-444444444444 "), true);
  assert.equal(looksLikeGuid("nope"), false);
  assert.equal(looksLikeTenant("contoso.onmicrosoft.com"), true);
  assert.equal(looksLikeTenant("aaaaaaaa-1111-4222-8333-444444444444"), true);
  assert.equal(looksLikeTenant("common"), false);
  assert.equal(looksLikeTenant("a/b.com"), false);
  assert.equal(looksLikeTenant(""), false);
});

test("lists are one per line or comma, lower case, without blanks or repeats", () => {
  assert.deepEqual(parseList(" Partner.Example.org\n\npartner.example.org, Other.Example.com "), ["partner.example.org", "other.example.com"]);
  assert.deepEqual(parseList(""), []);
});

test("certificate days left", () => {
  assert.equal(certDaysLeft("2026-11-03T12:00:00Z", NOW), 10);
  assert.equal(certDaysLeft("2026-10-23T12:00:00Z", NOW), -1);
  assert.equal(certDaysLeft(undefined, NOW), null);
  assert.equal(certDaysLeft("not a date", NOW), null);
});

// ---- Google Workspace (slice 13) --------------------------------------------------------------

test("a check group is named in the words of its provider", () => {
  assert.equal(checkLabel("mfa"), "MFA registration");
  assert.equal(checkLabel("mfa", "m365"), "MFA registration");
  assert.equal(checkLabel("mfa", "google"), "2-Step Verification");
  assert.equal(checkLabel("admin-roles", "google"), "Super administrators");
  assert.equal(checkLabel("inbox-rules", "google"), "Gmail forwarding and filters");
  // A group Google does not have falls back to the shared name, and an unknown one to itself.
  assert.equal(checkLabel("legacy-auth", "google"), "Legacy authentication");
  assert.equal(checkLabel("nope", "google"), "nope");
  assert.deepEqual([...CHECK_ORDER_GOOGLE], ["mfa", "admin-roles", "inbox-rules"]);
});

test("a Google row says where it is in Google's words", () => {
  const g = {
    identity: {
      findingId: 7,
      provider: "google",
      subject: "casey@example.com · filter on mail from “noreply@intuit.com”",
      check: "inbox-rules",
      id: "gmail.filter_hides_mail",
      fix: "x",
      unconfirmed: false,
      lastSeen: "2026-10-24T10:00:00Z",
    },
  } as unknown as ExposureGroup;
  assert.equal(identityWhere(g), "Google Workspace · Gmail forwarding and filters · casey@example.com · filter on mail from “noreply@intuit.com”");
  const u = { identity: { ...g.identity!, unconfirmed: true } } as unknown as ExposureGroup;
  assert.match(identityUnconfirmedNote(u), /The latest Gmail forwarding and filters check could not cover this: shown from the last confirmation on 2026-10-24/);
  assert.equal(providerLabel("google"), "Google Workspace");
});

test("the card names the providers it covers", () => {
  assert.equal(providerNames(summary()), "Microsoft 365");
  assert.equal(providerNames(summary({ provider: "google", providers: ["google"] })), "Google Workspace");
  assert.equal(providerNames(summary({ provider: "m365,google", providers: ["m365", "google"] })), "Microsoft 365 and Google Workspace");
  const c = identityCard(summary({ provider: "google", providers: ["google"] }), NOW);
  assert.equal(c.headline, "Identity (Google Workspace): 6 findings (2 critical, 1 high), last read 2 hours ago");
  const both = identityCard(summary({ provider: "m365,google", providers: ["m365", "google"], checksNotAssessed: 1, checksTotal: 7 }), NOW);
  assert.match(both.headline, /^Identity \(Microsoft 365 and Google Workspace\): 6 findings/);
  assert.match(both.lines[0], /1 of 7 checks could not run/);
});

test("an empty Fix this week list names the provider whose read it is talking about", () => {
  const hosts = { assessed: 3, notAssessed: 0, total: 3 } as Parameters<typeof fixEmptyText>[0]["hosts"];
  const surface = { assets: 1, unauthorised: 0, scanned: 1, findings: 0, bySeverity: {}, info: 0, assetsAffected: 0, lastScanAt: null, checksNotAssessed: 0 };
  const g = (over: Partial<IdentitySummary>) => fixEmptyText({ hosts, surface, identity: summary({ provider: "google", providers: ["google"], ...over }) });
  assert.match(g({ lastStatus: "" }), /The Google Workspace domain has not been read yet/);
  assert.match(g({ lastStatus: "not_assessed" }), /The last Google Workspace read could not assess anything/);
  assert.match(g({ lastStatus: "ok", findings: 0 }), /No identity finding is open/);
  assert.match(
    fixEmptyText({ hosts, surface, identity: summary({ provider: "m365,google", providers: ["m365", "google"], lastStatus: "not_assessed" }) }),
    /The last Microsoft 365 and Google Workspace read could not assess anything/,
  );
  assert.match(fixEmptyText({ hosts, surface, identity: summary({ lastStatus: "" }) }), /The Microsoft 365 tenant has not been read yet/);
});

test("an administrator address is checked before the page asks", () => {
  for (const ok of ["alex@example.com", " a.b+c@sub.example.co ", "admin@client-domain.example"]) assert.ok(looksLikeEmail(ok), ok);
  for (const bad of ["", "alex", "alex@example", "@example.com", "a@@example.com", "a b@example.com", "a@example..com", "a@.example.com", "a@example.com.", "a@x.com,b@y.com"]) {
    assert.ok(!looksLikeEmail(bad), `${JSON.stringify(bad)} was accepted`);
  }
});
