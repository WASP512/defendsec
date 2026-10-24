package autotask

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func f64(v float64) *float64 { return &v }

func vf(host, family, adv, fixed string, mod func(*Finding)) Finding {
	f := Finding{Source: SourceVuln, MemberKey: "dev-" + host, MemberLabel: host, Family: family, Package: family, Installed: "1.0", Fixed: fixed,
		AdvisoryID: adv, CVE: adv, Severity: "high", PackageManager: "dpkg", Distro: "ubuntu"}
	if mod != nil {
		mod(&f)
	}
	return f
}

func TestOneGroupPerRemediationActionNotPerCVEAndHost(t *testing.T) {
	var fs []Finding
	for _, h := range []string{"web-01", "web-02", "db-01", "app-01"} {
		for _, adv := range []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"} {
			fs = append(fs, vf(h, "openssl", adv, "1.1", nil))
		}
	}
	fs = append(fs, vf("web-01", "nginx", "CVE-2026-0100", "2.0", nil), vf("web-02", "nginx", "CVE-2026-0100", "2.0", nil))
	gs := BuildGroups(fs, DefaultSettings())
	if len(gs) != 2 {
		t.Fatalf("%d groups from 14 findings, want 2: %+v", len(gs), gs)
	}
	var ossl Group
	for _, g := range gs {
		if g.Key == "vuln|openssl" {
			ossl = g
		}
	}
	if len(ossl.Members) != 4 || ossl.Advisories != 3 {
		t.Fatalf("openssl group: %d members, %d advisories", len(ossl.Members), ossl.Advisories)
	}
	if ossl.Title != "Update openssl on 4 hosts" {
		t.Errorf("title = %q", ossl.Title)
	}
	if ossl.Members[0].Label != "app-01" || ossl.Members[3].Label != "web-02" {
		t.Errorf("members are not in hostname order: %+v", ossl.Members)
	}
	if !strings.Contains(ossl.Members[0].Line, "3 advisories") || !strings.Contains(ossl.Members[0].Line, "fixed in 1.1") {
		t.Errorf("member line = %q", ossl.Members[0].Line)
	}
	one := BuildGroups([]Finding{vf("web-01", "curl", "CVE-1", "8", nil)}, DefaultSettings())[0]
	if one.Title != "Update curl on web-01" {
		t.Errorf("single-host title = %q", one.Title)
	}
}

func TestVulnUrgencyRules(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Finding)
		want string
	}{
		{"KEV", func(f *Finding) { f.KEV = true; f.Severity = "low" }, UrgencyCritical},
		{"EPSS 0.10", func(f *Finding) { f.Severity = "low"; f.EPSS = f64(0.10) }, UrgencyHigh},
		{"EPSS 0.099", func(f *Finding) { f.Severity = "low"; f.EPSS = f64(0.099) }, UrgencyLow},
		{"CVSS 7.0", func(f *Finding) { f.Severity = "unknown"; f.CVSS = f64(7.0) }, UrgencyHigh},
		{"CVSS 6.9", func(f *Finding) { f.Severity = "unknown"; f.CVSS = f64(6.9) }, UrgencyMedium},
		{"CVSS 4.0", func(f *Finding) { f.Severity = "unknown"; f.CVSS = f64(4.0) }, UrgencyMedium},
		{"CVSS 3.9", func(f *Finding) { f.Severity = "unknown"; f.CVSS = f64(3.9) }, UrgencyLow},
		{"vendor critical", func(f *Finding) { f.Severity = "critical" }, UrgencyHigh},
		{"vendor medium", func(f *Finding) { f.Severity = "medium" }, UrgencyMedium},
		{"vendor low, no score", func(f *Finding) { f.Severity = "low" }, UrgencyLow},
		{"unknown, no score", func(f *Finding) { f.Severity = "unknown" }, UrgencyLow},
	}
	for _, c := range cases {
		g := BuildGroups([]Finding{vf("h", "pkg", "CVE-1", "2", c.mod)}, DefaultSettings())[0]
		if g.Urgency != c.want {
			t.Errorf("%s: urgency %s, want %s", c.name, g.Urgency, c.want)
		}
	}
	// The group takes its most urgent member.
	g := BuildGroups([]Finding{
		vf("a", "pkg", "CVE-1", "2", func(f *Finding) { f.Severity = "low" }),
		vf("b", "pkg", "CVE-2", "2", func(f *Finding) { f.KEV = true }),
	}, DefaultSettings())[0]
	if g.Urgency != UrgencyCritical || !strings.Contains(g.Why, "1 of them is on the CISA KEV list") {
		t.Errorf("group = %s / %s", g.Urgency, g.Why)
	}
}

func TestWhyNeverClaimsAScoreThatIsNotThere(t *testing.T) {
	g := BuildGroups([]Finding{vf("h", "pkg", "CVE-1", "2", func(f *Finding) { f.Severity = "high" })}, DefaultSettings())[0]
	if strings.Contains(g.Why, "EPSS") || strings.Contains(g.Why, "CVSS") {
		t.Errorf("a finding with no EPSS and no CVSS reads %q", g.Why)
	}
	if !strings.Contains(g.Why, "None of them is on the CISA KEV list") {
		t.Errorf("why = %q", g.Why)
	}
	g = BuildGroups([]Finding{vf("h", "pkg", "CVE-1", "2", func(f *Finding) { f.EPSS = f64(0.71); f.CVSS = f64(9.8) })}, DefaultSettings())[0]
	if !strings.Contains(g.Why, "Highest EPSS 0.71, highest CVSS 9.8") {
		t.Errorf("why = %q", g.Why)
	}
}

func TestVulnFixTextFollowsThePackageManager(t *testing.T) {
	g := BuildGroups([]Finding{
		vf("u", "openssl", "CVE-1", "2", func(f *Finding) { f.Package = "libssl3" }),
		vf("u", "openssl", "CVE-2", "2", func(f *Finding) { f.Package = "openssl" }),
		vf("r", "openssl", "CVE-1", "2", func(f *Finding) { f.PackageManager = "rpm"; f.Package = "openssl-libs" }),
	}, DefaultSettings())[0]
	for _, want := range []string{"sudo apt-get install --only-upgrade libssl3 openssl openssl-libs", "sudo dnf upgrade libssl3 openssl openssl-libs"} {
		if !strings.Contains(g.Fix, want) {
			t.Errorf("fix text lacks %q:\n%s", want, g.Fix)
		}
	}
	w := BuildGroups([]Finding{vf("w", "kb5001", "KB5001", "", func(f *Finding) { f.PackageManager = "" })}, DefaultSettings())[0]
	if !strings.HasPrefix(w.Fix, "Install the vendor's update for kb5001") {
		t.Errorf("fix for a host with no known package manager = %q", w.Fix)
	}
}

func TestEOLGroupsByReleaseAndRanksByStage(t *testing.T) {
	mk := func(host, stage string) Finding {
		return Finding{Source: SourceEOL, MemberKey: "dev-" + host, MemberLabel: host, EOLProduct: "php", EOLCycle: "8.0", EOLStage: stage,
			EOLLabel: "PHP 8.0", EOLUpgrade: "PHP 8.3", EOLDate: "2023-11-26", Package: "php8.0-cli", Installed: "8.0.30"}
	}
	g := BuildGroups([]Finding{mk("a", "eol"), mk("b", "eol")}, DefaultSettings())
	if len(g) != 1 || g[0].Urgency != UrgencyHigh || g[0].Title != "Upgrade PHP 8.0, past end of security support, on 2 hosts" {
		t.Fatalf("groups = %+v", g)
	}
	if !strings.Contains(g[0].Fix, "Upgrade to PHP 8.3") || !strings.Contains(g[0].Why, "since 2023-11-26") {
		t.Errorf("fix/why = %q / %q", g[0].Fix, g[0].Why)
	}
	if low := BuildGroups([]Finding{mk("a", "eoas")}, DefaultSettings()); low[0].Urgency != UrgencyLow {
		t.Errorf("end of active support only = %s, want low (never ticketed)", low[0].Urgency)
	}
}

func TestSurfaceAndIdentityGrouping(t *testing.T) {
	sf := func(asset, id, subject, sev string) Finding {
		return Finding{Source: SourceSurface, MemberKey: asset + "|" + id + "|" + subject, MemberLabel: asset, CheckID: id, Subject: subject, Severity: sev,
			Title: "Finding " + id, Detail: "Detail.", Fix: "Fix it."}
	}
	gs := BuildGroups([]Finding{
		sf("a.example.com", "dmarc.p_none", "", "medium"), sf("b.example.com", "dmarc.p_none", "", "medium"),
		sf("203.0.113.5", "ports.open", "445", "critical"), sf("203.0.113.5", "ports.open", "3389", "high"),
		sf("203.0.113.6", "ports.open", "3389", "high"),
	}, DefaultSettings())
	keys := map[string]Group{}
	for _, g := range gs {
		keys[g.Key] = g
	}
	if len(gs) != 3 || len(keys["surface|dmarc.p_none"].Members) != 2 || len(keys["surface|ports.open|3389"].Members) != 2 || len(keys["surface|ports.open|445"].Members) != 1 {
		t.Fatalf("surface groups = %v", gs)
	}
	if gs[0].Key != "surface|ports.open|445" || gs[0].Urgency != UrgencyCritical {
		t.Errorf("the critical group is not first: %s", gs[0].Key)
	}
	if got := keys["surface|dmarc.p_none"].Title; got != "Finding dmarc.p_none (and 1 other asset)" {
		t.Errorf("title = %q", got)
	}

	idf := func(user, id, sev string) Finding {
		return Finding{Source: SourceIdentity, MemberKey: "m365|" + id + "|" + user, MemberLabel: user + "@example.com", Provider: "m365", CheckID: id, Subject: user,
			Severity: sev, Title: "Title " + id, Detail: "Detail.", Fix: "Fix."}
	}
	gs = BuildGroups([]Finding{
		idf("u1", "mfa.not_registered", "critical"), idf("u2", "mfa.not_registered", "medium"), idf("u3", "mfa.not_registered", "medium"),
		idf("u4", "inbox_rule.hides_mail", "critical"), idf("u5", "inbox_rule.hides_mail", "medium"),
	}, DefaultSettings())
	if len(gs) != 3 {
		t.Fatalf("identity groups = %d: the MFA gap is one ticket, every inbox rule its own", len(gs))
	}
	for _, g := range gs {
		if strings.HasSuffix(g.Key, "mfa.not_registered") && (len(g.Members) != 3 || g.Urgency != UrgencyCritical || g.Title != "Register MFA for 3 accounts") {
			t.Errorf("mfa group = %+v", g)
		}
	}
}

func TestSettingsValidation(t *testing.T) {
	ok := DefaultSettings()
	ok.APIUser = "api-user@example.com"
	ok.ConsoleURL = "https://defendsec.example.net/"
	ok.ZoneURL = "https://webservices3.autotask.net/atservicesrest/"
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.ConsoleURL != "https://defendsec.example.net" || ok.ZoneURL != "https://webservices3.autotask.net/atservicesrest" {
		t.Errorf("not cleaned: %q %q", ok.ConsoleURL, ok.ZoneURL)
	}
	bad := map[string]func(*Settings){
		"zone off autotask.net":  func(s *Settings) { s.ZoneURL = "https://evil.example.com/atservicesrest" },
		"queue not a number":     func(s *Settings) { s.QueueID = "Service Desk" },
		"mode":                   func(s *Settings) { s.Mode = "yolo" },
		"sub without issue":      func(s *Settings) { s.SubIssueType = "200" },
		"autocomplete no status": func(s *Settings) { s.AutoComplete = true },
		"min urgency low":        func(s *Settings) { s.MinUrgency = "low" },
		"due days 0":             func(s *Settings) { s.DueDaysHigh = 0 },
		"due days 91":            func(s *Settings) { s.DueDaysMedium = 91 },
		"max creates 51":         func(s *Settings) { s.MaxCreates = 51 },
		"console with creds":     func(s *Settings) { s.ConsoleURL = "https://u:p@defendsec.example.net" },
		"console not http":       func(s *Settings) { s.ConsoleURL = "ftp://x.example.net" },
		"user with spaces":       func(s *Settings) { s.APIUser = "a b" },
		"negative company":       func(s *Settings) { s.CompanyID = -1 },
	}
	for name, mod := range bad {
		s := DefaultSettings()
		mod(&s)
		if err := s.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := DefaultSettings()
	if d.Mode != ModeDryRun || d.AutoComplete {
		t.Errorf("defaults must be dry run with auto-complete off: %+v", d)
	}
	if len(d.Missing()) < 4 {
		t.Errorf("defaults must leave the taxonomy unchosen: %v", d.Missing())
	}
}

func TestFingerprintCoversWhatATicketDependsOn(t *testing.T) {
	base := fullSettings()
	fp := base.Fingerprint()
	for name, mod := range map[string]func(*Settings){
		"company":  func(s *Settings) { s.CompanyID++ },
		"queue":    func(s *Settings) { s.QueueID = "100" },
		"priority": func(s *Settings) { s.PriorityHigh = "1" },
		"min":      func(s *Settings) { s.MinUrgency = UrgencyMedium },
		"complete": func(s *Settings) { s.AutoComplete = true },
		"console":  func(s *Settings) { s.ConsoleURL = "https://other.example.net" },
		"due":      func(s *Settings) { s.DueDaysHigh++ },
	} {
		s := base
		mod(&s)
		if s.Fingerprint() == fp {
			t.Errorf("changing the %s does not change the fingerprint", name)
		}
	}
	s := base
	s.Mode, s.MaxCreates = ModeLive, 3
	if s.Fingerprint() != fp {
		t.Error("the mode and the per-run limit must not change the fingerprint: going live is the point")
	}
}

func TestTagAndTitle(t *testing.T) {
	a, b := Tag("vuln|openssl", 1), Tag("vuln|openssl", 2)
	if a == b || !strings.HasPrefix(a, "DS-") || len(a) != 13 || a != Tag("vuln|openssl", 1) {
		t.Errorf("tags: %q %q", a, b)
	}
	long := strings.Repeat("é", 400)
	title := TitleWithTag(long, a, 255)
	if utf8.RuneCountInString(title) != 255 || !strings.HasSuffix(title, "["+a+"]") {
		t.Errorf("title is %d runes: %q", utf8.RuneCountInString(title), title[len(title)-30:])
	}
	if got := TitleWithTag("Update  openssl\non 4 hosts", a, 255); got != "Update openssl on 4 hosts ["+a+"]" {
		t.Errorf("title = %q", got)
	}
}

func TestDescriptionHasEverythingAndStaysUnderTheLimit(t *testing.T) {
	var fs []Finding
	for i := 0; i < 300; i++ {
		fs = append(fs, vf(fmt.Sprintf("host-%03d", i), "openssl", "CVE-2026-0001", "3.0.2-0ubuntu1.19", func(f *Finding) { f.KEV = true }))
	}
	set := DefaultSettings()
	set.ConsoleURL = "https://defendsec.example.net"
	g := BuildGroups(fs, set)[0]
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	tag := Tag(g.Key, 1)
	d := Description(g, tag, 1, now, 8000)
	if n := utf8.RuneCountInString(d); n > 8000 {
		t.Fatalf("description is %d characters, the field takes 8000", n)
	}
	for _, want := range []string{"Why it ranks:", "Urgency: critical", "Affected (300):", "host-000", "How to fix:", "sudo apt-get install --only-upgrade openssl",
		"In DefendSec: https://defendsec.example.net/advisories", "DefendSec key: " + tag, "action: vuln|openssl", "and "} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q", want)
		}
	}
	if !strings.Contains(d, "more; DefendSec has the full list") {
		t.Error("a truncated list must say how many are left out")
	}
	if !strings.HasSuffix(d, "when it sees them fixed.") {
		t.Errorf("the footer was cut: %q", d[len(d)-80:])
	}
	// A short list is complete.
	small := BuildGroups(fs[:3], set)[0]
	sd := Description(small, tag, 1, now, 8000)
	if strings.Contains(sd, "more; DefendSec") || strings.Count(sd, "\n- ") != 3 {
		t.Errorf("short description:\n%s", sd)
	}
	// A tiny limit still keeps the key.
	tiny := Description(g, tag, 1, now, 700)
	if utf8.RuneCountInString(tiny) > 700 || !strings.Contains(tiny, "DefendSec key: "+tag) {
		t.Errorf("tiny description is %d runes and lost its key", utf8.RuneCountInString(tiny))
	}
}

func TestNoteText(t *testing.T) {
	d := Delta{
		Joined:   []Member{{Line: "web-09: openssl 1 -> fixed in 2 (1 advisory: CVE-1)"}},
		Resolved: []string{"web-01: openssl 3.0.2 observed at or above the fixed version at 2026-10-25 10:00 UTC"},
		Open:     3,
	}
	n := NoteText(d, 32000)
	for _, want := range []string{"New since this ticket was opened (1):", "web-09", "No longer open (1):", "web-01: openssl 3.0.2 observed", "Still open in DefendSec: 3."} {
		if !strings.Contains(n, want) {
			t.Errorf("note lacks %q:\n%s", want, n)
		}
	}
	all := NoteText(Delta{AllResolved: true, Resolved: []string{"x"}}, 32000)
	if !strings.Contains(all, "The ticket is left open: close it when you have checked.") {
		t.Errorf("note = %s", all)
	}
	all = NoteText(Delta{AllResolved: true, Completing: true, Resolved: []string{"x"}}, 32000)
	if !strings.Contains(all, "Auto-complete is on") {
		t.Errorf("note = %s", all)
	}
	if !(Delta{}).Empty() || (Delta{UrgencyFrom: "high", UrgencyTo: "critical"}).Empty() {
		t.Error("Empty is wrong")
	}
	ev := ResolvedLine("web-02", Evidence{})
	if !strings.Contains(ev, "how it closed is not on record") {
		t.Errorf("missing evidence reads %q", ev)
	}
}
