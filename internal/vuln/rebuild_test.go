package vuln

import (
	"strings"
	"testing"
)

// The case this file exists for, measured on a patched Rocky 9.8 host
// (2026-10-24): Red Hat's feed said the kernel was fixed in
// 5.14.0-687.60.1.el9_8, Rocky's newest published kernel was 687.59.1, and the
// host (on 687.59.1) was reported as eight fixable findings it could not act on.
// Rebuild lag is not a vulnerability to schedule.

const (
	kernelCVE      = "CVE-2026-68202"
	kernel59       = "0:5.14.0-687.59.1.el9_8"
	kernel60       = "0:5.14.0-687.60.1.el9_8"
	kernelUpstream = "2026-10-20"
)

func rhelKernel(cve string, kev bool) Candidate {
	return rng(Candidate{CVE: cve, Ecosystem: "Red Hat", Distro: "rhel", Release: "9", Package: "kernel",
		Fixed: kernel60, State: StateFixed, Feed: "rhel-9", Issued: kernelUpstream, KEV: kev})
}

func rebuildKernel(distro, cve, fixed string) Candidate {
	eco := map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[distro]
	return rng(Candidate{CVE: cve, Ecosystem: eco, Distro: distro, Release: "9", Package: "kernel",
		Fixed: fixed, State: StateFixed, Feed: distro + "-9", Issued: "2026-10-22"})
}

// otherErratum gives the rebuild feed something to say about another CVE, so
// the feed is loaded and the host is covered, as it is in production.
func otherErratum(distro string) Candidate {
	return rebuildKernel(distro, "CVE-2026-00001", kernel59)
}

func kernelHost(distro string) Host {
	return Host{Distro: distro, Release: "9.8", PackageManager: "rpm", Packages: []Package{
		{Name: "kernel", Version: kernel59, SourcePackage: "kernel", SourceVersion: "5.14.0-687.59.1.el9_8"},
		{Name: "kernel-core", Version: kernel59, SourcePackage: "kernel", SourceVersion: "5.14.0-687.59.1.el9_8"},
	}}
}

func TestRebuildLagIsAwaitingVendorNotFixable(t *testing.T) {
	for _, distro := range []string{"rocky", "almalinux"} {
		src := &fakeSource{ranges: []Candidate{rhelKernel(kernelCVE, false), otherErratum(distro)}}
		res := openFindings(t, src, kernelHost(distro))
		if res.Coverage != CoverageFull {
			t.Fatalf("%s: coverage %s", distro, res.Coverage)
		}
		if n := len(res.Open()); n != 0 {
			t.Fatalf("%s: %d fixable findings on a host that has every fix its distribution released: %+v", distro, n, res.Findings)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("%s: findings = %+v, want one awaiting_vendor (two kernel packages are one family)", distro, res.Findings)
		}
		f := res.Findings[0]
		if f.Kind != KindAwaitingVendor || f.CVE != kernelCVE || f.Fixed != kernel60 || f.Installed != kernel59 {
			t.Errorf("%s: finding = %+v", distro, f)
		}
		vendor := map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[distro]
		for _, want := range []string{"fixed upstream by Red Hat", kernel60, kernelUpstream, "not yet released by " + vendor} {
			if !strings.Contains(f.Reason, want) {
				t.Errorf("%s: reason %q lacks %q", distro, f.Reason, want)
			}
		}
		if f.UpstreamFixedOn != kernelUpstream {
			t.Errorf("%s: UpstreamFixedOn = %q, want the Red Hat erratum date %s", distro, f.UpstreamFixedOn, kernelUpstream)
		}
		if f.Feed != "rhel-9" || f.SnapshotID == nil || f.RangeID == 0 {
			t.Errorf("%s: an awaiting_vendor finding keeps its evidence (upstream feed, snapshot, range): %+v", distro, f)
		}
		if res.Stats.AwaitingVendor != 1 || res.Stats.Unfixed != 0 || res.Stats.Informational != 0 {
			t.Errorf("%s: stats = %+v", distro, res.Stats)
		}
	}
}

func TestRebuildReleaseFlipsAwaitingToFixable(t *testing.T) {
	for _, distro := range []string{"rocky", "almalinux"} {
		src := &fakeSource{ranges: []Candidate{
			rhelKernel(kernelCVE, false), otherErratum(distro), rebuildKernel(distro, kernelCVE, kernel60),
		}}
		// The rebuild has shipped it: now it is something to install, and the
		// version to install is the rebuild's.
		res := openFindings(t, src, kernelHost(distro))
		if len(res.Open()) != 1 || res.Findings[0].Kind != KindFinding || res.Findings[0].Fixed != kernel60 || res.Findings[0].Feed != distro+"-9" {
			t.Fatalf("%s: after the rebuild shipped: %+v", distro, res.Findings)
		}
		if res.Stats.AwaitingVendor != 0 {
			t.Errorf("%s: awaiting_vendor = %d after the rebuild shipped", distro, res.Stats.AwaitingVendor)
		}
		// Installed: clean.
		h := kernelHost(distro)
		for i := range h.Packages {
			h.Packages[i].Version = kernel60
			h.Packages[i].SourceVersion = "5.14.0-687.60.1.el9_8"
		}
		if res := openFindings(t, src, h); len(res.Findings) != 0 {
			t.Errorf("%s: host on the shipped fix still has findings: %+v", distro, res.Findings)
		}
	}
}

// The rebuild's own errata are authoritative where they cover the CVE: if the
// rebuild's fixed version is above what the host runs, that is the fix to
// install, even when Red Hat's version string is lower.
func TestRebuildErrataVersionWinsOverRedHats(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2026-0002", Ecosystem: "Red Hat", Distro: "rhel", Release: "9", Package: "openssl-libs",
			Fixed: "1:3.5.1-4.el9_8", State: StateFixed, Feed: "rhel-9", Issued: "2026-10-01"}),
		rng(Candidate{CVE: "CVE-2026-0002", Ecosystem: "AlmaLinux", Distro: "almalinux", Release: "9", Package: "openssl-libs",
			Fixed: "1:3.5.1-4.el9_8.alma.1", State: StateFixed, Feed: "almalinux-9", Issued: "2026-10-02"}),
	}}
	h := Host{Distro: "almalinux", Release: "9.8", PackageManager: "rpm", Packages: []Package{
		{Name: "openssl-libs", Version: "1:3.5.1-3.el9_8"}}}
	res := openFindings(t, src, h)
	if len(res.Open()) != 1 || res.Findings[0].Fixed != "1:3.5.1-4.el9_8.alma.1" {
		t.Fatalf("findings = %+v, want the Alma fix to install", res.Findings)
	}
	// Reaching Red Hat's version (not Alma's) already means patched: the point of
	// the matcher is never to flag a host that is at or above a published fix.
	h.Packages[0].Version = "1:3.5.1-4.el9_8"
	if res := openFindings(t, src, h); len(res.Findings) != 0 {
		t.Errorf("host at Red Hat's fixed version: %+v", res.Findings)
	}
}

func TestRHELAndCentOSKeepUsingRHELDirectly(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{rhelKernel(kernelCVE, false)}}
	for _, distro := range []string{"rhel", "centos"} {
		res := openFindings(t, src, kernelHost(distro))
		if res.Coverage != CoverageFull || len(res.Open()) != 1 || res.Findings[0].Kind != KindFinding || res.Findings[0].Fixed != kernel60 {
			t.Errorf("%s: %+v (coverage %s)", distro, res.Findings, res.Coverage)
		}
		if res.Stats.AwaitingVendor != 0 {
			t.Errorf("%s: awaiting_vendor must only exist for rebuilds", distro)
		}
	}
}

// A KEV entry that cannot be installed yet is still exploited: the flag, the
// severity and the EPSS travel with an awaiting_vendor finding so the exposure
// view can raise its callout.
func TestAwaitingVendorKeepsKEV(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{rhelKernel(kernelCVE, true), otherErratum("rocky")}}
	res := openFindings(t, src, kernelHost("rocky"))
	if len(res.Findings) != 1 || !res.Findings[0].KEV || res.Findings[0].Kind != KindAwaitingVendor || res.Findings[0].Severity != "high" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// With Red Hat's feed alone, nothing says whether the rebuild shipped the fix.
// Calling that "fixable" is the bug; calling it "clean" would be worse. The host
// is not assessed until its own distribution's errata are loaded.
func TestRebuildHostWithoutItsOwnFeedIsNotAssessed(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{rhelKernel(kernelCVE, false)}}
	res := openFindings(t, src, kernelHost("rocky"))
	if res.Coverage != CoverageNoFeed || len(res.Findings) != 0 {
		t.Errorf("coverage %s findings %+v, want no_feed and nothing invented", res.Coverage, res.Findings)
	}
}

// Rocky's errata never apply to an Alma host, and the reverse.
func TestRebuildFeedsAreNotInterchangeable(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rhelKernel(kernelCVE, false), otherErratum("almalinux"), otherErratum("rocky"),
		rebuildKernel("rocky", kernelCVE, kernel60),
	}}
	res := openFindings(t, src, kernelHost("almalinux"))
	if len(res.Open()) != 0 || res.Stats.AwaitingVendor != 1 {
		t.Errorf("Alma host must not see Rocky's release: %+v", res.Findings)
	}
}

// What the operator reads first: fixable, then awaiting, then no fix.
func TestFindingOrderPutsFixableBeforeAwaitingBeforeUnfixed(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		otherErratum("rocky"),
		rhelKernel(kernelCVE, false),
		rng(Candidate{CVE: "CVE-2026-0003", Ecosystem: "Rocky Linux", Distro: "rocky", Release: "9", Package: "bash",
			State: StateAffected, Feed: "rocky-9"}),
		rng(Candidate{CVE: "CVE-2026-0004", Ecosystem: "Rocky Linux", Distro: "rocky", Release: "9", Package: "tzdata",
			Fixed: "0:2026b-1.el9", State: StateFixed, Feed: "rocky-9"}),
	}}
	h := kernelHost("rocky")
	h.Packages = append(h.Packages,
		Package{Name: "bash", Version: "0:5.1.8-9.el9"},
		Package{Name: "tzdata", Version: "0:2026a-1.el9"})
	res := openFindings(t, src, h)
	var kinds []Kind
	for _, f := range res.Findings {
		kinds = append(kinds, f.Kind)
	}
	want := []Kind{KindFinding, KindAwaitingVendor, KindUnfixed}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
}

func TestAwaitingReasonWithoutADate(t *testing.T) {
	got := awaitingReason(Candidate{Fixed: kernel60}, "almalinux")
	if got != "fixed upstream by Red Hat in "+kernel60+"; not yet released by AlmaLinux" {
		t.Errorf("reason = %q", got)
	}
}
