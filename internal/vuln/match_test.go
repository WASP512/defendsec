package vuln

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeSource is an in-memory advisory store.
type fakeSource struct {
	ranges  []Candidate
	covered map[[2]string]bool
	err     error
}

func (f *fakeSource) DistroRanges(_ context.Context, distro, release string, names []string) ([]Candidate, error) {
	if f.err != nil {
		return nil, f.err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []Candidate
	for _, c := range f.ranges {
		if c.Distro != distro || (c.Release != "" && c.Release != release) {
			continue
		}
		if want[c.Package] || want[c.SourcePackage] {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeSource) UpstreamRanges(_ context.Context, _ []string) ([]Candidate, error) {
	var out []Candidate
	for _, c := range f.ranges {
		if c.Distro == "" {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeSource) DistroCovered(_ context.Context, distro, release string) (bool, error) {
	if f.covered != nil {
		return f.covered[[2]string{distro, release}], nil
	}
	for _, c := range f.ranges {
		if c.Distro == distro && (c.Release == release || c.Release == "") {
			return true, nil
		}
	}
	return false, nil
}

var nextID int64

func rng(c Candidate) Candidate {
	nextID++
	c.RangeID = nextID
	if c.AdvisoryID == "" {
		c.AdvisoryID = c.CVE
	}
	if c.Severity == "" {
		c.Severity = "high"
	}
	snap := int64(7)
	c.SnapshotID = &snap
	return c
}

func openFindings(t *testing.T, src RangeSource, h Host) Result {
	t.Helper()
	res, err := Match(context.Background(), src, h)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// The failure this slice exists for. The upstream floor says 9.8p1; Ubuntu
// 22.04 fixed CVE-2024-6387 in 1:8.9p1-3ubuntu0.10. A fully patched host must
// produce nothing, and the same host one update behind must produce a finding
// that names the version to install.
func TestUbuntuBackportIsNotAFinding(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "openssh-server", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", State: StateFixed,
			Feed: "ubuntu-jammy"}),
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "openssh-client", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", State: StateFixed,
			Feed: "ubuntu-jammy"}),
		// The upstream floor that used to flag every patched Ubuntu host.
		rng(Candidate{AdvisoryID: "DEFENDSEC-OPENSSH", CVE: "CVE-2024-6387", Ecosystem: "legacy",
			Package: "openssh-server", Fixed: "9.8p1", State: StateFixed}),
	}}
	patched := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
		{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.11", SourcePackage: "openssh"},
		{Name: "openssh-client", Version: "1:8.9p1-3ubuntu0.11", SourcePackage: "openssh"},
	}}
	res := openFindings(t, src, patched)
	if len(res.Findings) != 0 {
		t.Fatalf("patched Ubuntu 22.04 host: %d findings, want 0: %+v", len(res.Findings), res.Findings)
	}
	if res.Coverage != CoverageFull || res.Stats.DistroMapped != 2 || res.Stats.Upstream != 0 {
		t.Errorf("coverage=%s stats=%+v, want full coverage, 2 distro-mapped, 0 upstream", res.Coverage, res.Stats)
	}

	behind := patched
	behind.Packages = []Package{
		{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.9", SourcePackage: "openssh"},
		{Name: "openssh-client", Version: "1:8.9p1-3ubuntu0.9", SourcePackage: "openssh"},
	}
	res = openFindings(t, src, behind)
	if len(res.Findings) != 1 {
		t.Fatalf("host one update behind: %d findings, want 1 (two binaries of one source are one finding): %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != KindFinding || f.Basis != BasisDistro || f.Fixed != "1:8.9p1-3ubuntu0.10" || f.Installed != "1:8.9p1-3ubuntu0.9" {
		t.Errorf("finding = %+v", f)
	}
	if f.AdvisoryID != "CVE-2024-6387" || f.RangeID == 0 || f.SnapshotID == nil || *f.SnapshotID != 7 || f.Feed != "ubuntu-jammy" {
		t.Errorf("finding must carry advisory, range, snapshot and feed: %+v", f)
	}
}

// Debian's tracker keys ranges on the source package; the installed binary
// maps to it through the dpkg Source: field.
func TestDebianBackport(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "openssh", SourcePackage: "openssh", Fixed: "1:9.2p1-2+deb12u3", State: StateFixed, Feed: "debian"}),
	}}
	h := func(ver string) Host {
		return Host{Distro: "debian", Release: "12", PackageManager: "dpkg", Packages: []Package{
			{Name: "openssh-server", Version: ver, SourcePackage: "openssh"},
		}}
	}
	if res := openFindings(t, src, h("1:9.2p1-2+deb12u3")); len(res.Findings) != 0 {
		t.Errorf("patched Debian 12: %+v", res.Findings)
	}
	if res := openFindings(t, src, h("1:9.2p1-2+deb12u4")); len(res.Findings) != 0 {
		t.Errorf("newer than the fix: %+v", res.Findings)
	}
	res := openFindings(t, src, h("1:9.2p1-2+deb12u2"))
	if len(res.Findings) != 1 || res.Findings[0].Fixed != "1:9.2p1-2+deb12u3" {
		t.Errorf("one update behind: %+v", res.Findings)
	}
	// os-release on Debian reports a point release for some images.
	hh := h("1:9.2p1-2+deb12u3")
	hh.Release = "12.5"
	if res := openFindings(t, src, hh); res.Coverage != CoverageFull || len(res.Findings) != 0 {
		t.Errorf("VERSION_ID 12.5 must match the 12 feed: coverage %s %+v", res.Coverage, res.Findings)
	}
}

// RHEL ranges are per binary RPM and carry an epoch. Rocky and Alma are matched
// against the RHEL feed by major release.
func TestRHELFamilyBackport(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Red Hat", Distro: "rhel", Release: "9",
			Package: "openssh-server", Fixed: "0:8.7p1-38.el9_4.1", State: StateFixed, Feed: "rhel-9"}),
		rng(Candidate{CVE: "CVE-2024-5535", Ecosystem: "Red Hat", Distro: "rhel", Release: "9",
			Package: "openssl-libs", Fixed: "1:3.0.7-28.el9_4", State: StateFixed, Feed: "rhel-9"}),
	}}
	for _, distro := range []string{"rhel", "rocky", "almalinux"} {
		h := Host{Distro: distro, Release: "9.4", PackageManager: "rpm", Packages: []Package{
			{Name: "openssh-server", Version: "0:8.7p1-38.el9_4.4", SourcePackage: "openssh"},
			{Name: "openssl-libs", Version: "1:3.0.7-28.el9_4", SourcePackage: "openssl"},
		}}
		res := openFindings(t, src, h)
		if len(res.Findings) != 0 {
			t.Errorf("patched %s 9.4: %+v", distro, res.Findings)
		}
		if res.Distro != "rhel" || res.Release != "9" || res.Coverage != CoverageFull {
			t.Errorf("%s normalised to %s %s (%s)", distro, res.Distro, res.Release, res.Coverage)
		}
	}
	behind := Host{Distro: "rocky", Release: "9.4", PackageManager: "rpm", Packages: []Package{
		{Name: "openssl-libs", Version: "1:3.0.7-27.el9", SourcePackage: "openssl"},
	}}
	res := openFindings(t, src, behind)
	if len(res.Findings) != 1 || res.Findings[0].CVE != "CVE-2024-5535" {
		t.Errorf("Rocky one update behind: %+v", res.Findings)
	}
	// The epoch is part of the version: an inventory that drops it compares
	// "3.0.7-28.el9_4" with "1:3.0.7-28.el9_4" and flags the patched host.
	// ParseRPMQuery keeps it; this documents why.
	noEpoch := Host{Distro: "rocky", Release: "9.4", PackageManager: "rpm", Packages: []Package{
		{Name: "openssl-libs", Version: "3.0.7-28.el9_4"},
	}}
	if res := openFindings(t, src, noEpoch); len(res.Findings) != 1 {
		t.Errorf("an epoch-less version of an epoch 1 package must not look patched: %+v", res.Findings)
	}
}

func TestOpenSUSEBackport(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "openSUSE", Distro: "opensuse-leap", Release: "15.6",
			Package: "openssh-server", Fixed: "9.6p1-150600.6.6.1", State: StateFixed, Feed: "suse-leap-15.6"}),
	}}
	h := func(ver string) Host {
		return Host{Distro: "opensuse-leap", Release: "15.6", PackageManager: "rpm", Packages: []Package{
			{Name: "openssh-server", Version: ver},
		}}
	}
	if res := openFindings(t, src, h("9.6p1-150600.6.9.1")); len(res.Findings) != 0 {
		t.Errorf("patched Leap 15.6: %+v", res.Findings)
	}
	if res := openFindings(t, src, h("9.6p1-150600.6.3.1")); len(res.Findings) != 1 {
		t.Errorf("Leap 15.6 behind: %+v", res.Findings)
	}
}

func TestFixStates(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		// Debian says this code path was never shipped.
		rng(Candidate{CVE: "CVE-2024-0001", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "libfoo", SourcePackage: "libfoo", State: StateNotAffected, Feed: "debian"}),
		// Debian will not fix this.
		rng(Candidate{CVE: "CVE-2024-0002", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "libbar", SourcePackage: "libbar", State: StateWillNotFix, Feed: "debian"}),
		// Open with no fix yet.
		rng(Candidate{CVE: "CVE-2024-0003", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "libbaz", SourcePackage: "libbaz", State: StateAffected, Feed: "debian"}),
		rng(Candidate{CVE: "CVE-2024-0004", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "libqux", SourcePackage: "libqux", State: StateUnderInvestigation, Feed: "debian"}),
		// Introduced after the installed version.
		rng(Candidate{CVE: "CVE-2024-0005", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "libnew", SourcePackage: "libnew", Introduced: "2.0-1", Fixed: "2.0-3", State: StateFixed, Feed: "debian"}),
	}}
	h := Host{Distro: "debian", Release: "12", PackageManager: "dpkg", Packages: []Package{
		{Name: "libfoo", Version: "1.0-1", SourcePackage: "libfoo"},
		{Name: "libbar", Version: "1.0-1", SourcePackage: "libbar"},
		{Name: "libbaz", Version: "1.0-1", SourcePackage: "libbaz"},
		{Name: "libqux", Version: "1.0-1", SourcePackage: "libqux"},
		{Name: "libnew", Version: "1.9-1", SourcePackage: "libnew"},
	}}
	res := openFindings(t, src, h)
	got := map[string]Kind{}
	for _, f := range res.Findings {
		got[f.CVE] = f.Kind
	}
	want := map[string]Kind{
		"CVE-2024-0002": KindInformational, // will_not_fix: shown, not a finding
		"CVE-2024-0003": KindUnfixed,       // affected, no fix published: exposure, nothing to install
		"CVE-2024-0004": KindInformational,
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// A host with nothing to install has no open findings, whatever the
	// distro has left unfixed.
	if n := len(res.Open()); n != 0 {
		t.Errorf("Open() = %d, want 0", n)
	}
	if res.Stats.NotAffected != 1 || res.Stats.Unfixed != 1 || res.Stats.Informational != 2 {
		t.Errorf("stats = %+v", res.Stats)
	}
	// Unfixed sorts before informational.
	if res.Findings[0].Kind != KindUnfixed {
		t.Errorf("unfixed first: %+v", res.Findings)
	}
}

// not_affected on the distro's side outranks a fixed range for the same CVE.
func TestNotAffectedWinsOverFixedRange(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-0009", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "libx", SourcePackage: "x", Fixed: "2.0-1", State: StateFixed, Feed: "ubuntu-jammy"}),
		rng(Candidate{CVE: "CVE-2024-0009", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "libx", SourcePackage: "x", State: StateNotAffected, Feed: "ubuntu-jammy"}),
	}}
	h := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
		{Name: "libx", Version: "1.0-1", SourcePackage: "x"}}}
	if res := openFindings(t, src, h); len(res.Findings) != 0 {
		t.Errorf("%+v", res.Findings)
	}
}

// Ubuntu security-pocket and ESM ranges can both apply; the host is patched if
// it has reached either, and the finding names the lower fix.
func TestSeveralFixedRanges(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-0010", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "libz", SourcePackage: "z", Fixed: "1.2-1ubuntu0.2", State: StateFixed, Feed: "ubuntu-jammy"}),
		rng(Candidate{CVE: "CVE-2024-0010", Ecosystem: "Ubuntu:Pro", Distro: "ubuntu", Release: "22.04",
			Package: "libz", SourcePackage: "z", Fixed: "1.2-1ubuntu0.2~esm1", State: StateFixed, Feed: "ubuntu-jammy"}),
	}}
	h := func(v string) Host {
		return Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
			{Name: "libz", Version: v, SourcePackage: "z"}}}
	}
	if res := openFindings(t, src, h("1.2-1ubuntu0.2")); len(res.Findings) != 0 {
		t.Errorf("at the security fix: %+v", res.Findings)
	}
	if res := openFindings(t, src, h("1.2-1ubuntu0.2~esm1")); len(res.Findings) != 0 {
		t.Errorf("at the ESM fix: %+v", res.Findings)
	}
	// Not on Pro: the ESM range is not installable, the security fix is.
	res := openFindings(t, src, h("1.2-1ubuntu0.1"))
	if len(res.Findings) != 1 || res.Findings[0].Fixed != "1.2-1ubuntu0.2" {
		t.Errorf("behind both, no Pro: %+v", res.Findings)
	}
	// On Pro: the lower of the two fixes is the one to name.
	onPro := h("1.2-1ubuntu0.1")
	onPro.Packages = append(onPro.Packages, Package{Name: "libother", Version: "3.1-1+esm1", SourcePackage: "other"})
	res = openFindings(t, src, onPro)
	if len(res.Findings) != 1 || res.Findings[0].Fixed != "1.2-1ubuntu0.2~esm1" {
		t.Errorf("behind both, on Pro: %+v", res.Findings)
	}
}

// A fix that ships only through Ubuntu Pro is not something a plain host can
// install: it must not read as a finding to act on. On a host that evidently
// uses Pro (an ESM build installed) it is a finding like any other.
func TestUbuntuProFixesNeedPro(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2026-0001", Ecosystem: ecosystemUbuntuPro, Distro: "ubuntu", Release: "22.04",
			Package: "kitty", SourcePackage: "kitty", Fixed: "0.21.2-1ubuntu0.22.04.1+esm1", State: StateFixed, Feed: "ubuntu-jammy"}),
	}}
	h := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
		{Name: "kitty", Version: "0.21.2-1ubuntu0.22.04.1", SourcePackage: "kitty"}}}
	res := openFindings(t, src, h)
	if len(res.Open()) != 0 || len(res.Findings) != 1 || res.Findings[0].Kind != KindUnfixed ||
		res.Findings[0].Fixed != "0.21.2-1ubuntu0.22.04.1+esm1" || !strings.Contains(res.Findings[0].Reason, "Ubuntu Pro") {
		t.Fatalf("no Pro: %+v", res.Findings)
	}
	// An ESM package elsewhere on the host shows Pro is in use.
	h.Packages = append(h.Packages, Package{Name: "libfoo", Version: "1.0-1ubuntu1+esm2", SourcePackage: "foo"})
	if res := openFindings(t, src, h); len(res.Open()) != 1 {
		t.Fatalf("on Pro: %+v", res.Findings)
	}
	// Having reached the ESM fix is clean either way.
	h.Packages[0].Version = "0.21.2-1ubuntu0.22.04.1+esm1"
	if res := openFindings(t, src, h); len(res.Findings) != 0 {
		t.Fatalf("patched: %+v", res.Findings)
	}
}

// dpkg's Source: field can carry a version that differs from the binary's.
// Ranges keyed on the source compare against that.
func TestSourceVersionIsUsedForSourceKeyedRanges(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-0011", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "glibc", SourcePackage: "glibc", Fixed: "2.36-9+deb12u4", State: StateFixed, Feed: "debian"}),
	}}
	// binNMU: binary 2.36-9+deb12u4+b1, built from source 2.36-9+deb12u4.
	h := Host{Distro: "debian", Release: "12", PackageManager: "dpkg", Packages: []Package{
		{Name: "libc6", Version: "2.36-9+deb12u4+b1", SourcePackage: "glibc", SourceVersion: "2.36-9+deb12u4"}}}
	if res := openFindings(t, src, h); len(res.Findings) != 0 {
		t.Errorf("%+v", res.Findings)
	}
	h.Packages[0].SourceVersion = "2.36-9+deb12u3"
	h.Packages[0].Version = "2.36-9+deb12u3+b1"
	if res := openFindings(t, src, h); len(res.Findings) != 1 {
		t.Errorf("%+v", res.Findings)
	}
}

// Upstream floors apply only to software the distro feed knows nothing about.
func TestUpstreamFallbackOnlyForUnmappedSoftware(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "openssh-server", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", State: StateFixed, Feed: "ubuntu-jammy"}),
		rng(Candidate{AdvisoryID: "FLOOR-OPENSSH", CVE: "CVE-2024-6387", Ecosystem: "legacy",
			Package: "openssh-server", Fixed: "9.8p1", State: StateFixed}),
		rng(Candidate{AdvisoryID: "FLOOR-VENDORAPP", CVE: "CVE-2024-7777", Ecosystem: "legacy",
			Package: "vendorapp", Fixed: "4.2.0", State: StateFixed}),
		rng(Candidate{AdvisoryID: "FLOOR-DISTROPKG", CVE: "CVE-2024-8888", Ecosystem: "legacy",
			Package: "somedistropkg", Fixed: "5.0", State: StateFixed}),
	}}
	h := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
		// Patched distro build with an upstream floor above it: no finding.
		{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.11", SourcePackage: "openssh"},
		// Vendor tarball, no distro revision, below the floor: finding.
		{Name: "vendorapp", Version: "4.1.9", SourcePackage: "vendorapp"},
		// Distro-built package the feed has no entry for: the comparison is
		// undecidable (a backport cannot be ruled out), so no finding.
		{Name: "somedistropkg", Version: "4.9-1ubuntu1", SourcePackage: "somedistropkg"},
	}}
	res := openFindings(t, src, h)
	if len(res.Findings) != 1 || res.Findings[0].Package != "vendorapp" || res.Findings[0].Basis != BasisUpstream {
		t.Fatalf("findings = %+v, want exactly the vendor app via upstream", res.Findings)
	}
	if res.Stats.Undecidable != 1 || res.Stats.DistroMapped != 1 || res.Stats.Upstream != 2 {
		t.Errorf("stats = %+v", res.Stats)
	}
}

// A host with no usable feed has no findings because nothing was checked, not
// because it is clean. Coverage says which.
func TestCoverage(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "openssh-server", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", State: StateFixed}),
	}}
	pk := []Package{{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.1", SourcePackage: "openssh"}}
	for _, tc := range []struct {
		h    Host
		want Coverage
	}{
		{Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: pk}, CoverageFull},
		{Host{Distro: "ubuntu", Release: "24.04", PackageManager: "dpkg", Packages: pk}, CoverageNoFeed},
		{Host{Distro: "fedora", Release: "40", PackageManager: "rpm", Packages: pk}, CoverageNoFeed},
		{Host{Packages: pk}, CoverageNoDistro},
	} {
		res := openFindings(t, src, tc.h)
		if res.Coverage != tc.want {
			t.Errorf("%s %s: coverage %s, want %s", tc.h.Distro, tc.h.Release, res.Coverage, tc.want)
		}
		if tc.want != CoverageFull && len(res.Findings) != 0 {
			t.Errorf("%s %s without a feed must not invent findings: %+v", tc.h.Distro, tc.h.Release, res.Findings)
		}
	}
}

// An agent that predates the source-package field still gets matched, by
// binary name where the feed names the binary, and by source name where the
// feed keys on the source and the binary shares it.
func TestOldAgentWithoutSourcePackage(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2024-6387", Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04",
			Package: "openssh-server", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", State: StateFixed}),
		rng(Candidate{CVE: "CVE-2024-0100", Ecosystem: "Debian", Distro: "debian", Release: "12",
			Package: "curl", SourcePackage: "curl", Fixed: "7.88.1-10+deb12u6", State: StateFixed}),
	}}
	ubuntu := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
		{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.11"}}}
	if res := openFindings(t, src, ubuntu); len(res.Findings) != 0 {
		t.Errorf("%+v", res.Findings)
	}
	ubuntu.Packages[0].Version = "1:8.9p1-3ubuntu0.2"
	if res := openFindings(t, src, ubuntu); len(res.Findings) != 1 {
		t.Errorf("%+v", res.Findings)
	}
	debian := Host{Distro: "debian", Release: "12", PackageManager: "dpkg", Packages: []Package{
		{Name: "curl", Version: "7.88.1-10+deb12u5"}}}
	if res := openFindings(t, src, debian); len(res.Findings) != 1 {
		t.Errorf("%+v", res.Findings)
	}
}

func TestMatchPropagatesSourceErrors(t *testing.T) {
	src := &fakeSource{err: errors.New("db down"), covered: map[[2]string]bool{{"ubuntu", "22.04"}: true}}
	_, err := Match(context.Background(), src, Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg",
		Packages: []Package{{Name: "a", Version: "1"}}})
	if err == nil {
		t.Fatal("a failing range source must fail the run, not report a clean host")
	}
}

func TestNormalizeDistro(t *testing.T) {
	for _, tc := range []struct {
		id, ver, mgr string
		distro, rel  string
		scheme       Scheme
	}{
		{"ubuntu", "22.04", "dpkg", "ubuntu", "22.04", SchemeDpkg},
		{"Rocky", "9.4", "rpm", "rhel", "9", SchemeRPM},
		{"almalinux", "8.10", "", "rhel", "8", SchemeRPM},
		{"debian", "12", "dpkg", "debian", "12", SchemeDpkg},
		{"opensuse-tumbleweed", "20241012", "rpm", "opensuse-tumbleweed", "", SchemeRPM},
		{"opensuse-leap", "15.6", "rpm", "opensuse-leap", "15.6", SchemeRPM},
		{"", "", "", "", "", SchemeAuto},
	} {
		d, r, s := NormalizeDistro(tc.id, tc.ver, tc.mgr)
		if d != tc.distro || r != tc.rel || s != tc.scheme {
			t.Errorf("NormalizeDistro(%q,%q,%q) = %q %q %v, want %q %q %v", tc.id, tc.ver, tc.mgr, d, r, s, tc.distro, tc.rel, tc.scheme)
		}
	}
}

// The Source: field and SOURCERPM never carry the epoch, but the feeds' fixed
// versions do. Real patched hosts: Ubuntu 22.04 libbpf0 (1:0.5.0-1ubuntu22.04.1
// built from source "0.5.0-1ubuntu22.04.1") was flagged against the feed's
// fixed "1:0.5.0-1ubuntu22.04.1". Measured on a real host, 2026-10-23.
func TestSourceVersionInheritsBinaryEpoch(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2022-3534", Ecosystem: "Ubuntu:22.04", Distro: "ubuntu", Release: "22.04",
			Package: "libbpf", SourcePackage: "libbpf", Fixed: "1:0.5.0-1ubuntu22.04.1", State: StateFixed, Feed: "ubuntu-jammy"}),
	}}
	h := Host{Distro: "ubuntu", Release: "22.04", PackageManager: "dpkg", Packages: []Package{
		{Name: "libbpf0", Version: "1:0.5.0-1ubuntu22.04.1", SourcePackage: "libbpf", SourceVersion: "0.5.0-1ubuntu22.04.1"}}}
	if res := openFindings(t, src, h); len(res.Findings) != 0 {
		t.Errorf("dpkg, patched: %+v", res.Findings)
	}
	// Really older: same epoch, lower revision still flags.
	h.Packages[0] = Package{Name: "libbpf0", Version: "1:0.5.0-1", SourcePackage: "libbpf", SourceVersion: "0.5.0-1"}
	if res := openFindings(t, src, h); len(res.Findings) != 1 {
		t.Errorf("dpkg, vulnerable: %+v", res.Findings)
	}

	// rpm: openssl-style epoch 1; SOURCERPM gives "openssl-3.5.1-4.el9_8.src.rpm", no epoch.
	rsrc := &fakeSource{ranges: []Candidate{
		rng(Candidate{CVE: "CVE-2026-0001", Ecosystem: "Red Hat:9", Distro: "rhel", Release: "9",
			Package: "openssl", SourcePackage: "openssl", Fixed: "1:3.5.1-4.el9_8", State: StateFixed, Feed: "rhel-9"}),
	}}
	rh := Host{Distro: "rocky", Release: "9.8", PackageManager: "rpm", Packages: []Package{
		{Name: "openssl-libs", Version: "1:3.5.1-4.el9_8", SourcePackage: "openssl", SourceVersion: "3.5.1-4.el9_8"}}}
	if res := openFindings(t, rsrc, rh); len(res.Findings) != 0 {
		t.Errorf("rpm, patched: %+v", res.Findings)
	}
	rh.Packages[0] = Package{Name: "openssl-libs", Version: "1:3.5.1-3.el9_8", SourcePackage: "openssl", SourceVersion: "3.5.1-3.el9_8"}
	if res := openFindings(t, rsrc, rh); len(res.Findings) != 1 {
		t.Errorf("rpm, vulnerable: %+v", res.Findings)
	}
}

func TestInheritEpoch(t *testing.T) {
	for _, c := range []struct{ src, bin, want string }{
		{"0.5.0-1", "1:0.5.0-1", "1:0.5.0-1"},
		{"2.36-9", "1:2.36-9+b1", "1:2.36-9"},
		{"2:1.0-1", "1:1.0-1", "2:1.0-1"}, // an explicit epoch is never overridden
		{"1.0-1", "1.0-1", "1.0-1"},
		{"1.0-1", "", "1.0-1"},
		{"1.0-1", "a:1.0-1", "1.0-1"}, // not an epoch
	} {
		if got := inheritEpoch(c.src, c.bin); got != c.want {
			t.Errorf("inheritEpoch(%q,%q) = %q, want %q", c.src, c.bin, got, c.want)
		}
	}
}
