package autotask

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// What is one ticket? One remediation action: the thing a technician does in one
// sitting, whatever number of CVEs and hosts it closes.
//
//   - Vulnerabilities: one action per package family (the source package, as the
//     matcher groups them): "update openssl", on every host that has an open fix
//     for it. Seven CVEs on four hosts is one ticket with four members.
//   - End-of-life software: one action per release of a product ("upgrade PHP 8.0"),
//     on every host that runs it.
//   - External surface: one action per finding id (every asset with an SPF problem
//     is one ticket), except an open port, a dangling name and a DKIM selector,
//     which are per subject: closing port 445 and closing port 3389 are not the
//     same job.
//   - Identity: "register MFA" covers every account without it, in one ticket.
//     Every other identity finding is its own ticket: an inbox rule that hides
//     payment mail is not something to bury in a list.
//
// The urgency of an action is that of its most urgent member.

// Group keys: the first part says the source, so a key is readable in a ledger.
func vulnKey(family string) string { return "vuln|" + family }
func eolKey(product, cycle string) string {
	return "eol|" + product + "|" + cycle
}

func surfaceKey(f Finding) string {
	switch {
	case f.CheckID == "ports.open", f.CheckID == "cname.dangling", strings.HasPrefix(f.CheckID, "dkim."):
		return "surface|" + f.CheckID + "|" + f.Subject
	}
	return "surface|" + f.CheckID
}

func identityKey(f Finding) string {
	if f.CheckID == "mfa.not_registered" {
		return "identity|" + f.Provider + "|" + f.CheckID
	}
	return "identity|" + f.Provider + "|" + f.CheckID + "|" + f.Subject
}

func shortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:12]
}

// vulnUrgency: critical if any advisory is on the CISA KEV list (exploited in
// the wild); high if any has an EPSS of 0.10 or more, a CVSS of 7.0 or more, or a
// vendor severity of high or critical; medium if any is medium or has a CVSS of 4.0
// or more; low otherwise. The first two lines are the product's ranking idea
// (KEV, then EPSS, then CVSS); the cut-offs are a judgement, listed in
// docs/AUTOTASK.md, not measured against a real client.
func vulnUrgency(fs []Finding) string {
	u := UrgencyLow
	raise := func(to string) {
		if UrgencyRank(to) > UrgencyRank(u) {
			u = to
		}
	}
	for _, f := range fs {
		switch {
		case f.KEV:
			raise(UrgencyCritical)
		case f.EPSS != nil && *f.EPSS >= 0.10, f.CVSS != nil && *f.CVSS >= 7.0, f.Severity == "critical", f.Severity == "high":
			raise(UrgencyHigh)
		case f.Severity == "medium", f.CVSS != nil && *f.CVSS >= 4.0:
			raise(UrgencyMedium)
		}
	}
	return u
}

// severityUrgency maps a surface or identity severity; info never reaches here.
func severityUrgency(s string) string {
	switch s {
	case "critical":
		return UrgencyCritical
	case "high":
		return UrgencyHigh
	case "medium":
		return UrgencyMedium
	}
	return UrgencyLow
}

func maxUrgency(a, b string) string {
	if UrgencyRank(b) > UrgencyRank(a) {
		return b
	}
	return a
}

// BuildGroups turns the open Fix-this-week findings into remediation actions,
// most urgent first, then by key so the order is total.
func BuildGroups(all []Finding, set Settings) []Group {
	type bucket struct {
		key string
		fs  []Finding
	}
	order := []string{}
	buckets := map[string]*bucket{}
	add := func(key string, f Finding) {
		b := buckets[key]
		if b == nil {
			b = &bucket{key: key}
			buckets[key] = b
			order = append(order, key)
		}
		b.fs = append(b.fs, f)
	}
	for _, f := range all {
		switch f.Source {
		case SourceVuln:
			add(vulnKey(f.Family), f)
		case SourceEOL:
			add(eolKey(f.EOLProduct, f.EOLCycle), f)
		case SourceSurface:
			add(surfaceKey(f), f)
		case SourceIdentity:
			add(identityKey(f), f)
		}
	}
	out := make([]Group, 0, len(buckets))
	for _, key := range order {
		b := buckets[key]
		var g Group
		switch b.fs[0].Source {
		case SourceVuln:
			g = vulnGroup(b.key, b.fs)
		case SourceEOL:
			g = eolGroup(b.key, b.fs)
		case SourceSurface:
			g = surfaceGroup(b.key, b.fs)
		case SourceIdentity:
			g = identityGroup(b.key, b.fs)
		}
		g.Link = linkFor(set.ConsoleURL, g)
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := UrgencyRank(out[i].Urgency), UrgencyRank(out[j].Urgency); ri != rj {
			return ri > rj
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func linkFor(console string, g Group) string {
	if console == "" {
		return ""
	}
	return console + "/advisories"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func capList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" and %d more", len(items)-max)
}

// ---- vulnerabilities ---------------------------------------------------------------------

func vulnGroup(key string, fs []Finding) Group {
	family := fs[0].Family
	byHost := map[string][]Finding{}
	labels := map[string]string{}
	advisories := map[string]bool{}
	kevAdvisories := map[string]bool{}
	pkgs := map[string]bool{}
	managers := map[string]bool{}
	var topEPSS, topCVSS *float64
	for _, f := range fs {
		byHost[f.MemberKey] = append(byHost[f.MemberKey], f)
		labels[f.MemberKey] = f.MemberLabel
		advisories[f.AdvisoryID] = true
		if f.KEV {
			kevAdvisories[f.AdvisoryID] = true
		}
		pkgs[f.Package] = true
		managers[pmFamily(f.PackageManager)] = true
		if f.EPSS != nil && (topEPSS == nil || *f.EPSS > *topEPSS) {
			v := *f.EPSS
			topEPSS = &v
		}
		if f.CVSS != nil && (topCVSS == nil || *f.CVSS > *topCVSS) {
			v := *f.CVSS
			topCVSS = &v
		}
	}
	g := Group{Key: key, Source: SourceVuln, Urgency: vulnUrgency(fs), Advisories: len(advisories)}
	hosts := sortedKeysByLabel(byHost, labels)
	for _, k := range hosts {
		hf := byHost[k]
		sort.Slice(hf, func(i, j int) bool { return hf[i].AdvisoryID < hf[j].AdvisoryID })
		g.Members = append(g.Members, Member{Key: k, Label: labels[k], Line: vulnLine(labels[k], hf), Digest: vulnDigest(hf)})
	}
	if len(hosts) == 1 {
		g.Title = fmt.Sprintf("Update %s on %s", family, labels[hosts[0]])
	} else {
		g.Title = fmt.Sprintf("Update %s on %d hosts", family, len(hosts))
	}
	g.Why = vulnWhy(len(advisories), len(kevAdvisories), len(hosts), topEPSS, topCVSS)
	g.Fix = vulnFix(family, sortedKeys(pkgs), sortedKeys(managers))
	return g
}

func pmFamily(pm string) string {
	switch strings.ToLower(pm) {
	case "dpkg", "apt":
		return "apt"
	case "rpm", "dnf", "yum":
		return "dnf"
	case "zypper":
		return "zypper"
	}
	return ""
}

func sortedKeysByLabel[V any](m map[string]V, labels map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		li, lj := strings.ToLower(labels[ks[i]]), strings.ToLower(labels[ks[j]])
		if li != lj {
			return li < lj
		}
		return ks[i] < ks[j]
	})
	return ks
}

func vulnLine(label string, fs []Finding) string {
	type pv struct{ pkg, installed, fixed string }
	seen := map[pv]bool{}
	var versions []pv
	var cves []string
	kev := 0
	adv := map[string]bool{}
	for _, f := range fs {
		k := pv{f.Package, f.Installed, f.Fixed}
		if !seen[k] {
			seen[k] = true
			versions = append(versions, k)
		}
		if !adv[f.AdvisoryID] {
			adv[f.AdvisoryID] = true
			id := f.CVE
			if id == "" {
				id = f.AdvisoryID
			}
			cves = append(cves, id)
			if f.KEV {
				kev++
			}
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].pkg < versions[j].pkg })
	var parts []string
	for _, v := range versions {
		switch {
		case v.fixed != "":
			parts = append(parts, fmt.Sprintf("%s %s -> fixed in %s", v.pkg, v.installed, v.fixed))
		default:
			parts = append(parts, fmt.Sprintf("%s %s", v.pkg, v.installed))
		}
	}
	sort.Strings(cves)
	tail := fmt.Sprintf("%s: %s", plural(len(cves), "advisory", "advisories"), capList(cves, 4))
	if kev > 0 {
		tail += fmt.Sprintf("; %d exploited in the wild", kev)
	}
	return fmt.Sprintf("%s: %s (%s)", label, capList(parts, 3), tail)
}

func vulnDigest(fs []Finding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, f.AdvisoryID+"@"+f.Fixed)
	}
	sort.Strings(parts)
	return shortHash(parts...)
}

func vulnWhy(advisories, kev, hosts int, epss, cvss *float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s open on %s. ", plural(advisories, "advisory", "advisories"), plural(hosts, "host", "hosts"))
	switch {
	case kev > 0:
		fmt.Fprintf(&b, "%d of them %s on the CISA KEV list (exploited in the wild). ", kev, map[bool]string{true: "is", false: "are"}[kev == 1])
	default:
		b.WriteString("None of them is on the CISA KEV list. ")
	}
	var sig []string
	if epss != nil {
		sig = append(sig, fmt.Sprintf("highest EPSS %.2f", *epss))
	}
	if cvss != nil {
		sig = append(sig, fmt.Sprintf("highest CVSS %.1f", *cvss))
	}
	if len(sig) > 0 {
		b.WriteString(strings.ToUpper(sig[0][:1]) + sig[0][1:])
		if len(sig) > 1 {
			b.WriteString(", " + sig[1])
		}
		b.WriteString(". ")
	}
	b.WriteString("Every host listed has an update from its own distribution that closes these.")
	return b.String()
}

func vulnFix(family string, pkgs, managers []string) string {
	list := strings.Join(pkgs, " ")
	var cmds []string
	for _, m := range managers {
		switch m {
		case "apt":
			cmds = append(cmds, fmt.Sprintf("Debian/Ubuntu: sudo apt-get update && sudo apt-get install --only-upgrade %s", list))
		case "dnf":
			cmds = append(cmds, fmt.Sprintf("RHEL family: sudo dnf upgrade %s", list))
		case "zypper":
			cmds = append(cmds, fmt.Sprintf("SUSE: sudo zypper update %s", list))
		}
	}
	if len(cmds) == 0 {
		return fmt.Sprintf("Install the vendor's update for %s on every host listed.", family)
	}
	return strings.Join(cmds, "\n") + "\nRestart the services that use the package afterwards (needrestart or a reboot), then DefendSec confirms the new version on its next check-in."
}

// ---- end-of-life -------------------------------------------------------------------------

func eolGroup(key string, fs []Finding) Group {
	byHost := map[string][]Finding{}
	labels := map[string]string{}
	for _, f := range fs {
		byHost[f.MemberKey] = append(byHost[f.MemberKey], f)
		labels[f.MemberKey] = f.MemberLabel
	}
	first := fs[0]
	label := first.EOLLabel
	if label == "" {
		label = strings.TrimSpace(first.EOLProduct + " " + first.EOLCycle)
	}
	urgency := UrgencyLow
	if first.EOLStage == "eol" {
		urgency = UrgencyHigh
	}
	g := Group{Key: key, Source: SourceEOL, Urgency: urgency, Advisories: 1}
	for _, k := range sortedKeysByLabel(byHost, labels) {
		hf := byHost[k]
		var pk []string
		for _, f := range hf {
			if f.Package != "" {
				pk = append(pk, f.Package+" "+f.Installed)
			}
		}
		sort.Strings(pk)
		line := labels[k] + ": " + label
		if len(pk) > 0 {
			line += " (" + capList(pk, 3) + ")"
		}
		g.Members = append(g.Members, Member{Key: k, Label: labels[k], Line: line, Digest: shortHash(first.EOLStage, strings.Join(pk, ","))})
	}
	where := plural(len(g.Members), "host", "hosts")
	if len(g.Members) == 1 {
		where = g.Members[0].Label
	}
	if first.EOLStage == "eol" {
		g.Title = fmt.Sprintf("Upgrade %s, past end of security support, on %s", label, where)
		g.Why = fmt.Sprintf("%s no longer receives security fixes (support ended %s), so every future flaw stays open. No exploitation score applies: nothing will ever patch it.", label, orUnknown(first.EOLDate))
	} else {
		g.Title = fmt.Sprintf("Upgrade %s, past end of active support, on %s", label, where)
		g.Why = fmt.Sprintf("%s is past its end of active support (%s); security fixes still arrive for now.", label, orUnknown(first.EOLDate))
	}
	if first.EOLUpgrade != "" {
		g.Fix = "Upgrade to " + first.EOLUpgrade + " (or another supported release) and remove the old packages."
	} else {
		g.Fix = "Upgrade to a release that still receives security fixes and remove the old packages."
	}
	return g
}

func orUnknown(s string) string {
	if s == "" {
		return "on a date its vendor gave"
	}
	return "since " + s
}

// ---- surface -----------------------------------------------------------------------------

func surfaceGroup(key string, fs []Finding) Group {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].MemberLabel != fs[j].MemberLabel {
			return fs[i].MemberLabel < fs[j].MemberLabel
		}
		return fs[i].Subject < fs[j].Subject
	})
	first := fs[0]
	urgency := UrgencyLow
	for _, f := range fs {
		urgency = maxUrgency(urgency, severityUrgency(f.Severity))
	}
	g := Group{Key: key, Source: SourceSurface, Urgency: urgency, Advisories: len(fs)}
	assets := map[string]bool{}
	for _, f := range fs {
		label := f.MemberLabel
		if f.Subject != "" {
			label += " (" + f.Subject + ")"
		}
		assets[f.MemberLabel] = true
		g.Members = append(g.Members, Member{Key: f.MemberKey, Label: label,
			Line:   label + ": " + f.Title,
			Digest: shortHash(f.CheckID, f.Subject, f.Severity, f.Title)})
	}
	if len(g.Members) == 1 {
		g.Title = first.Title
		if !strings.Contains(first.Title, first.MemberLabel) {
			g.Title += " on " + first.MemberLabel
		}
	} else {
		g.Title = fmt.Sprintf("%s (and %s)", first.Title, plural(len(g.Members)-1, "other asset", "other assets"))
	}
	g.Why = fmt.Sprintf("External surface finding, %s: %s What the internet can see needs no foothold and no exploit. %s", first.Severity+" severity", strings.TrimSpace(first.Detail), "Reachable is not the same as compromised.")
	g.Fix = first.Fix
	return g
}

// ---- identity ----------------------------------------------------------------------------

func identityGroup(key string, fs []Finding) Group {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].MemberLabel != fs[j].MemberLabel {
			return fs[i].MemberLabel < fs[j].MemberLabel
		}
		return fs[i].MemberKey < fs[j].MemberKey
	})
	first := fs[0]
	urgency := UrgencyLow
	for _, f := range fs {
		urgency = maxUrgency(urgency, severityUrgency(f.Severity))
	}
	g := Group{Key: key, Source: SourceIdentity, Urgency: urgency, Advisories: len(fs)}
	for _, f := range fs {
		g.Members = append(g.Members, Member{Key: f.MemberKey, Label: f.MemberLabel,
			Line:   f.MemberLabel + ": " + f.Title + " (" + f.Severity + ")",
			Digest: shortHash(f.CheckID, f.Subject, f.Severity, f.Title)})
	}
	if first.CheckID == "mfa.not_registered" && len(fs) > 1 {
		g.Title = fmt.Sprintf("Register MFA for %d accounts", len(fs))
	} else {
		g.Title = first.Title
		if len(fs) == 1 && first.MemberLabel != "" && !strings.Contains(first.Title, first.MemberLabel) {
			g.Title += " (" + first.MemberLabel + ")"
		}
	}
	g.Why = fmt.Sprintf("Identity finding, %s severity: %s A stolen password or a hidden rule needs no exploit. Worth a question to the account's owner before any change.", first.Severity, strings.TrimSpace(first.Detail))
	g.Fix = first.Fix
	return g
}
