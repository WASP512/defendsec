import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { windowsBuild, windowsEdition, windowsSupport, type OsRelease } from "./os-lifecycle.ts";

// A real fetch of endoflife.date's `windows` and `windows-server` products on
// 2026-10-24 (schema 1.2.1), in the shape GET /v1/lifecycle/os returns.
const calendar = (JSON.parse(readFileSync(new URL("./testdata/os-calendar.json", import.meta.url), "utf8")) as { releases: OsRelease[] }).releases;

const TODAY = new Date("2026-10-24T12:00:00Z");

const host = (osName: string, build: number, osEdition = "", major = "10.0") => ({ osName, osVersion: `${major}.${build}`, osEdition });
const at = (d: Parameters<typeof windowsSupport>[0], date: string) => windowsSupport(d, calendar, new Date(`${date}T12:00:00Z`));

test("the calendar fixture is the real feed: Server 2016 ends 2027-01-12, Server 2019 2029-01-09", () => {
  const find = (p: string, c: string) => calendar.find((r) => r.product === p && r.cycle === c);
  assert.equal(find("windows-server", "2016")?.eolFrom, "2027-01-12");
  assert.equal(find("windows-server", "2019")?.eolFrom, "2029-01-09");
  assert.equal(find("windows", "10-22h2")?.eolFrom, "2025-10-14");
  assert.equal(find("windows", "10-21h2-e-lts")?.eolFrom, "2027-01-12");
  assert.equal(find("windows", "10-1607-e-lts")?.eolFrom, "2026-10-13");
});

// The cases from the defect report, judged on 2026-10-24.
test("Windows Server 2016 (14393) is supported until 2027-01-12", () => {
  const r = windowsSupport(host("Microsoft Windows Server 2016 Standard", 14393, "ServerStandard"), calendar, TODAY);
  assert.equal(r.state, true);
  assert.match(r.reason, /Windows Server 2016: security updates until 2027-01-12/);
});

test("Windows Server 2019 (17763) is supported until 2029-01-09", () => {
  const r = windowsSupport(host("Microsoft Windows Server 2019 Datacenter", 17763, "ServerDatacenter"), calendar, TODAY);
  assert.equal(r.state, true);
  assert.match(r.reason, /Windows Server 2019: security updates until 2029-01-09/);
});

test("Windows 10 LTSB 2016 (14393, EnterpriseS) ended 2026-10-13: the same build as Server 2016, the opposite answer", () => {
  const r = windowsSupport(host("Microsoft Windows 10 Enterprise 2016 LTSB", 14393, "EnterpriseS"), calendar, TODAY);
  assert.equal(r.state, false);
  assert.match(r.reason, /Windows 10-1607-e-lts: security updates ended 2026-10-13/);
});

test("Windows 10 LTSC 2019 (17763, EnterpriseS) is supported with Server 2019, Windows 10 1809 Enterprise is not", () => {
  assert.equal(windowsSupport(host("Microsoft Windows 10 Enterprise LTSC", 17763, "EnterpriseS"), calendar, TODAY).state, true);
  assert.equal(windowsSupport(host("Microsoft Windows 10 Enterprise", 17763, "Enterprise"), calendar, TODAY).state, false);
});

test("Windows 10 LTSC 2021 (19044) is supported until 2027-01-12; 19044 Pro is not; 22H2 (19045) is not", () => {
  assert.equal(windowsSupport(host("Microsoft Windows 10 Enterprise LTSC", 19044, "EnterpriseS"), calendar, TODAY).state, true);
  assert.equal(windowsSupport(host("Microsoft Windows 10 IoT Enterprise LTSC", 19044, "IoTEnterpriseS"), calendar, TODAY).state, true);
  assert.equal(windowsSupport(host("Microsoft Windows 10 Pro", 19044, "Professional"), calendar, TODAY).state, false);
  const r = windowsSupport(host("Microsoft Windows 10 Pro", 19045, "Professional"), calendar, TODAY);
  assert.equal(r.state, false); // consumer ESU does not count as vendor security updates
  assert.match(r.reason, /Windows 10-22h2: security updates ended 2025-10-14/);
});

test("Windows 11 and Server 2022/2025: edition decides where the calendar has one date per edition", () => {
  // 11 23H2: Home/Pro ended 2025-11-11, Enterprise/Education run to 2026-11-10
  assert.equal(windowsSupport(host("Microsoft Windows 11 Pro", 22631, "Professional"), calendar, TODAY).state, false);
  assert.equal(windowsSupport(host("Microsoft Windows 11 Enterprise", 22631, "Enterprise"), calendar, TODAY).state, true);
  // 11 24H2 Home/Pro ended 2026-10-13; Enterprise to 2027-10-12; Enterprise LTSC to 2029-10-09
  assert.equal(windowsSupport(host("Microsoft Windows 11 Pro", 26100, "Professional"), calendar, TODAY).state, false);
  assert.equal(windowsSupport(host("Microsoft Windows 11 Enterprise", 26100, "Enterprise"), calendar, TODAY).state, true);
  assert.equal(windowsSupport(host("Microsoft Windows 11 Enterprise LTSC", 26100, "EnterpriseS"), calendar, TODAY).state, true);
  // Server 2025 and 2022 share nothing with the client rows of the same build
  assert.equal(windowsSupport(host("Microsoft Windows Server 2025 Standard", 26100, "ServerStandard"), calendar, TODAY).state, true);
  assert.equal(windowsSupport(host("Microsoft Windows Server 2022 Standard", 20348, "ServerStandard"), calendar, TODAY).state, true);
  // Server 2012 R2 reports 6.3.9600; its extended updates (to 2026-10-13) are not counted
  assert.equal(windowsSupport(host("Microsoft Windows Server 2012 R2 Standard", 9600, "ServerStandard", "6.3"), calendar, TODAY).state, false);
});

test("the verdict changes on the real end-of-life date, not the day before or after", () => {
  const s2016 = host("Microsoft Windows Server 2016 Standard", 14393, "ServerStandard");
  assert.equal(at(s2016, "2027-01-11").state, true);
  assert.equal(at(s2016, "2027-01-12").state, false);
  assert.equal(at(s2016, "2027-01-13").state, false);

  const s2019 = host("Microsoft Windows Server 2019 Standard", 17763, "ServerStandard");
  assert.equal(at(s2019, "2029-01-08").state, true);
  assert.equal(at(s2019, "2029-01-09").state, false);

  const ltsb = host("Microsoft Windows 10 Enterprise 2016 LTSB", 14393, "EnterpriseS");
  assert.equal(at(ltsb, "2026-10-12").state, true);
  assert.equal(at(ltsb, "2026-10-13").state, false);

  const w10 = host("Microsoft Windows 10 Pro", 19045, "Professional");
  assert.equal(at(w10, "2025-10-13").state, true);
  assert.equal(at(w10, "2025-10-14").state, false);

  const ltsc21 = host("Microsoft Windows 10 Enterprise LTSC", 19044, "EnterpriseS");
  assert.equal(at(ltsc21, "2027-01-11").state, true);
  assert.equal(at(ltsc21, "2027-01-12").state, false);
});

test("an unknown edition is unknown when the build is shared across support dates, never unsupported", () => {
  // 14393 with no edition and a caption that does not say: Server 2016 (supported) vs Win10 1607 (ended)
  const r = windowsSupport({ osName: "Microsoft Windows", osVersion: "10.0.14393", osEdition: "" }, calendar, TODAY);
  assert.equal(r.state, null);
  assert.match(r.reason, /Edition not reported, and build 14393 is both supported \(Windows Server 2016\) and past support/);
  assert.equal(windowsSupport({ osName: "Windows", osVersion: "10.0.17763" }, calendar, TODAY).state, null);
  // an EditionID the table does not know is the same as none
  assert.equal(windowsSupport(host("Windows", 17763, "SomeNewEdition"), calendar, TODAY).state, null);
  // where every possible cycle agrees the answer stands without an edition: 22H2 is over for everyone
  assert.equal(windowsSupport({ osName: "Windows", osVersion: "10.0.19045" }, calendar, TODAY).state, false);
});

test("an old agent's OS caption stands in for a missing EditionID, and says so", () => {
  const r = windowsSupport({ osName: "Microsoft Windows Server 2016 Standard", osVersion: "10.0.14393" }, calendar, TODAY);
  assert.equal(r.state, true);
  assert.match(r.reason, /edition read from the OS caption/);
  assert.equal(windowsSupport({ osName: "Microsoft Windows 10 Enterprise LTSC", osVersion: "10.0.17763" }, calendar, TODAY).state, true);
});

test("no calendar, no build, an unlisted build: unknown", () => {
  const s2016 = host("Microsoft Windows Server 2016 Standard", 14393, "ServerStandard");
  assert.equal(windowsSupport(s2016, [], TODAY).state, null);
  assert.match(windowsSupport(s2016, [], TODAY).reason, /calendar has not been loaded/);
  assert.equal(windowsSupport({ osName: "Windows", osVersion: "", osEdition: "ServerStandard" }, calendar, TODAY).state, null);
  assert.equal(windowsSupport(host("Windows", 99999, "ServerStandard"), calendar, TODAY).state, null);
  // a calendar row with no end date is not a verdict
  const noDate = calendar.map((r) => (r.product === "windows-server" && r.cycle === "2016" ? { ...r, eolFrom: "" } : r));
  assert.equal(windowsSupport(s2016, noDate, TODAY).state, null);
});

test("EditionID and caption parsing", () => {
  const e = (id: string, caption = "") => windowsEdition(id, caption);
  assert.deepEqual(e("ServerStandard"), { kind: "server", track: null, source: "edition" });
  assert.deepEqual(e("ServerDatacenterCor"), { kind: "server", track: null, source: "edition" });
  assert.equal(e("ServerStandardACor").kind, "server-sac");
  assert.equal(e("Core").track, "w");
  assert.equal(e("CoreSingleLanguage").track, "w");
  assert.equal(e("ProfessionalWorkstation").track, "w");
  assert.equal(e("Enterprise").track, "e");
  assert.equal(e("Education").track, "e");
  assert.equal(e("IoTEnterprise").track, "e");
  assert.equal(e("EnterpriseS").track, "ltsc");
  assert.equal(e("IoTEnterpriseS").track, "iot-ltsc");
  assert.equal(e("Surprise").kind, null);
  assert.equal(windowsEdition("", "Microsoft Windows 11 Pro").track, "w");
  assert.equal(windowsEdition("", "Microsoft Windows 10 Enterprise 2016 LTSB").track, "ltsc");
  assert.equal(windowsEdition(undefined, "Windows").kind, null);
});

test("windowsBuild reads the third part", () => {
  assert.equal(windowsBuild("10.0.17763"), 17763);
  assert.equal(windowsBuild("6.3.9600"), 9600);
  assert.equal(windowsBuild("10.0"), null);
  assert.equal(windowsBuild(""), null);
  assert.equal(windowsBuild("10.0.0"), null);
});
