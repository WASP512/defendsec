package storepg

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- No database needed ----------------------------------------------------

func TestAdvisoryValidate(t *testing.T) {
	score := func(v float64) *float64 { return &v }
	good := AdvisoryRange{Package: "openssl", FixState: FixStateFixed, Fixed: "1.1.1f-1ubuntu2.24", Distro: "ubuntu", Release: "20.04"}

	cases := []struct {
		name    string
		adv     Advisory
		wantErr string // substring; "" = valid
	}{
		{"valid", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{good}}, ""},
		{"valid without ranges", Advisory{ID: "CVE-1", Severity: "high"}, ""},
		{"no id", Advisory{Severity: "high"}, "id is required"},
		{"no severity", Advisory{ID: "CVE-1"}, "severity is required"},
		{"cvss too high", Advisory{ID: "CVE-1", Severity: "high", CVSSScore: score(10.1)}, "cvss_score"},
		{"epss above 1", Advisory{ID: "CVE-1", Severity: "high", EPSS: score(1.2)}, "epss"},
		{"epss negative", Advisory{ID: "CVE-1", Severity: "high", EPSS: score(-0.1)}, "epss"},
		{"range without package", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{{FixState: FixStateAffected}}}, "package is required"},
		{"bad fix state", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{{Package: "p", FixState: "patched"}}}, "fix_state"},
		{"empty fix state", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{{Package: "p"}}}, "fix_state"},
		{"fixed without version", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{{Package: "p", FixState: FixStateFixed}}}, "requires a fixed version"},
		{"release without distro", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{{Package: "p", FixState: FixStateAffected, Release: "9"}}}, "release requires distro"},
		{"reserved ecosystem", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{{Package: "p", FixState: FixStateAffected, Ecosystem: "legacy"}}}, "reserved"},
		{"duplicate range", Advisory{ID: "CVE-1", Severity: "high", Ranges: []AdvisoryRange{good, good}}, "duplicates range 0"},
		{"same package other release is not a duplicate", Advisory{ID: "CVE-1", Severity: "high",
			Ranges: []AdvisoryRange{good, {Package: "openssl", FixState: FixStateFixed, Fixed: "3.0.2-0ubuntu1.18", Distro: "ubuntu", Release: "22.04"}}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.adv.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestFeedRefValidate(t *testing.T) {
	ok := FeedRef{Name: "cisa-kev", URL: "https://example.invalid/kev.json", FetchedAt: time.Now(), SHA256: strings.Repeat("a", 64), RecordCount: 3}
	if err := ok.validate(); err != nil {
		t.Fatalf("valid feed rejected: %v", err)
	}
	bad := map[string]func(*FeedRef){
		"name":       func(f *FeedRef) { f.Name = " " },
		"url":        func(f *FeedRef) { f.URL = "" },
		"fetched_at": func(f *FeedRef) { f.FetchedAt = time.Time{} },
		"sha256":     func(f *FeedRef) { f.SHA256 = strings.Repeat("A", 64) },
		"short sha":  func(f *FeedRef) { f.SHA256 = "abc" },
		"count":      func(f *FeedRef) { f.RecordCount = -1 },
	}
	for name, mutate := range bad {
		f := ok
		mutate(&f)
		if err := f.validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRecordFeedSnapshotRejectsEmptyWithoutTouchingDB(t *testing.T) {
	// A nil pool proves validation happens before any database access.
	s := &Store{}
	if _, err := s.RecordFeedSnapshot(context.Background(), nil); err == nil {
		t.Fatal("empty feed list accepted")
	}
	if _, err := s.RecordFeedSnapshot(context.Background(), []FeedRef{{Name: "x"}}); err == nil {
		t.Fatal("invalid feed accepted")
	}
}

func TestListAdvisoryRangesRejectsBadQuery(t *testing.T) {
	s := &Store{}
	if _, err := s.ListAdvisoryRanges(context.Background(), RangeQuery{Distro: "ubuntu"}); err == nil {
		t.Fatal("missing package accepted")
	}
	if _, err := s.ListAdvisoryRanges(context.Background(), RangeQuery{Package: "openssl"}); err == nil {
		t.Fatal("missing distro without IncludeDistroAgnostic accepted")
	}
}

// The SQL placeholders and the argument lists in UpsertAdvisoryWithRanges are
// written by hand; pin their counts so adding a column to one and not the
// other fails here rather than at runtime against Postgres.
func TestAdvisorySQLPlaceholderCounts(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		args int
	}{
		{"upsertAdvisory", upsertAdvisorySQL, 13},
		{"insertRange", insertRangeSQL, 10},
		{"listRanges", listRangesSQL, 4},
		{"deleteRanges", deleteRangesSQL, 1},
		{"getAdvisory", getAdvisorySQL, 1},
		{"getRanges", getRangesSQL, 1},
		{"insertSnapshot", insertSnapshotSQL, 1},
	}
	for _, tc := range cases {
		highest := 0
		for n := 1; n <= 20; n++ {
			if strings.Contains(tc.sql, "$"+strconv.Itoa(n)) {
				highest = n
			}
		}
		if highest != tc.args {
			t.Errorf("%s: highest placeholder $%d, want $%d", tc.name, highest, tc.args)
		}
	}
	// The conflict update must clear the legacy floor so the migration
	// trigger removes the mirrored range.
	if !strings.Contains(upsertAdvisorySQL, "package='', below=''") {
		t.Error("upsertAdvisorySQL does not clear the legacy package/below on conflict")
	}
}

// --- Against Postgres (TEST_DATABASE_URL) ----------------------------------

func f64(v float64) *float64 { return &v }

func date(y int, m time.Month, d int) *time.Time {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return &t
}

func TestRecordFeedSnapshotRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	fetched := time.Date(2026, 10, 23, 6, 0, 0, 0, time.FixedZone("MDT", -6*3600))
	feeds := []FeedRef{
		{Name: "cisa-kev", URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", FetchedAt: fetched, SHA256: strings.Repeat("ab", 32), RecordCount: 1200},
		{Name: "epss", URL: "https://epss.cyentia.com/epss_scores-current.csv.gz", FetchedAt: fetched, SHA256: strings.Repeat("cd", 32), RecordCount: 250000},
	}
	snap, err := s.RecordFeedSnapshot(ctx, feeds)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ID == 0 || snap.CreatedAt.IsZero() {
		t.Fatalf("snapshot not populated: %+v", snap)
	}
	got, err := s.GetFeedSnapshot(ctx, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Feeds) != 2 || got.Feeds[0].Name != "cisa-kev" || got.Feeds[1].SHA256 != feeds[1].SHA256 || got.Feeds[1].RecordCount != 250000 {
		t.Fatalf("feeds did not round-trip: %+v", got.Feeds)
	}
	if !got.Feeds[0].FetchedAt.Equal(fetched) {
		t.Fatalf("fetched_at = %v, want instant %v", got.Feeds[0].FetchedAt, fetched)
	}
	if _, err := s.GetFeedSnapshot(ctx, snap.ID+1_000_000); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing snapshot err = %v, want ErrNoRows", err)
	}
}

func TestUpsertAdvisoryWithRangesRoundTripAndReplace(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{{Name: "ubuntu-oval-jammy", URL: "https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2", FetchedAt: time.Now(), SHA256: strings.Repeat("01", 32), RecordCount: 10}})
	if err != nil {
		t.Fatal(err)
	}
	id := "TEST-" + randID(t)
	adv := Advisory{
		ID: id, CVE: "CVE-2024-6387", Summary: "regreSSHion", Severity: "high", Source: "ubuntu-oval",
		CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSSScore: f64(8.1),
		CWE: []string{"CWE-364"}, KEV: true, KEVAdded: date(2024, 7, 1), EPSS: f64(0.42), EPSSDate: date(2026, 10, 22),
		SnapshotID: &snap.ID,
		Ranges: []AdvisoryRange{
			{Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "22.04", Package: "openssh-server", SourcePackage: "openssh", Fixed: "1:8.9p1-3ubuntu0.10", FixState: FixStateFixed},
			{Ecosystem: "Ubuntu", Distro: "ubuntu", Release: "20.04", Package: "openssh-server", SourcePackage: "openssh", FixState: FixStateNotAffected},
			{Ecosystem: "Debian", Distro: "debian", Release: "12", Package: "openssh-server", SourcePackage: "openssh", Introduced: "1:9.2", Fixed: "1:9.2p1-2+deb12u3", FixState: FixStateFixed},
		},
	}
	if err := s.UpsertAdvisoryWithRanges(ctx, adv); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAdvisory(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.CVE != adv.CVE || got.Severity != "high" || got.CVSSVector != adv.CVSSVector || got.CVSSScore == nil || *got.CVSSScore != 8.1 ||
		len(got.CWE) != 1 || got.CWE[0] != "CWE-364" || !got.KEV || got.KEVAdded == nil || got.KEVAdded.Format("2006-01-02") != "2024-07-01" ||
		got.EPSS == nil || *got.EPSS != 0.42 || got.EPSSDate == nil || got.EPSSDate.Format("2006-01-02") != "2026-10-22" ||
		got.SnapshotID == nil || *got.SnapshotID != snap.ID {
		t.Fatalf("advisory did not round-trip: %+v", got)
	}
	if len(got.Ranges) != 3 {
		t.Fatalf("ranges = %d, want 3: %+v", len(got.Ranges), got.Ranges)
	}
	for _, r := range got.Ranges {
		if r.SnapshotID == nil || *r.SnapshotID != snap.ID {
			t.Errorf("range did not inherit snapshot: %+v", r)
		}
	}
	if r := got.Ranges[1]; r.FixState != FixStateNotAffected || r.Fixed != "" || r.Introduced != "" {
		t.Errorf("not_affected range = %+v", r)
	}

	// Replace: same advisory, one range. Old ranges must be gone.
	adv.Ranges = adv.Ranges[:1]
	adv.KEV = false
	adv.KEVAdded = nil
	if err := s.UpsertAdvisoryWithRanges(ctx, adv); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetAdvisory(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ranges) != 1 || got.Ranges[0].Release != "22.04" || got.KEV || got.KEVAdded != nil {
		t.Fatalf("replace failed: %+v", got)
	}
}

func TestUpsertAdvisoryWithRangesIsAtomic(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id := "TEST-" + randID(t)
	good := Advisory{ID: id, Severity: "high", Ranges: []AdvisoryRange{{Package: "keep-me", FixState: FixStateAffected, Distro: "debian", Release: "12"}}}
	if err := s.UpsertAdvisoryWithRanges(ctx, good); err != nil {
		t.Fatal(err)
	}
	// Passes Go validation, fails in Postgres: snapshot_id has no such row.
	missing := int64(999_999_999)
	bad := Advisory{ID: id, Severity: "critical", SnapshotID: &missing, Ranges: []AdvisoryRange{{Package: "new", FixState: FixStateAffected}}}
	if err := s.UpsertAdvisoryWithRanges(ctx, bad); err == nil {
		t.Fatal("expected a foreign-key failure")
	}
	got, err := s.GetAdvisory(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Severity != "high" || len(got.Ranges) != 1 || got.Ranges[0].Package != "keep-me" {
		t.Fatalf("failed upsert left partial state: %+v", got)
	}
}

func TestListAdvisoryRanges(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	pkg := "pkg" + randID(t)
	src := "src" + randID(t)
	a1, a2, a3 := "TEST-"+randID(t), "TEST-"+randID(t), "TEST-"+randID(t)
	for _, a := range []Advisory{
		{ID: a1, Severity: "high", Ranges: []AdvisoryRange{
			{Distro: "ubuntu", Release: "22.04", Package: pkg, SourcePackage: src, Fixed: "2", FixState: FixStateFixed},
			{Distro: "ubuntu", Release: "20.04", Package: pkg, SourcePackage: src, Fixed: "1", FixState: FixStateFixed},
		}},
		{ID: a2, Severity: "high", Ranges: []AdvisoryRange{
			{Distro: "ubuntu", Package: "other" + pkg, SourcePackage: src, FixState: FixStateWillNotFix}, // any release, matched via source name
		}},
		{ID: a3, Severity: "low", Ranges: []AdvisoryRange{
			{Distro: "debian", Release: "12", Package: pkg, FixState: FixStateAffected},
			{Package: pkg, Fixed: "9", FixState: FixStateFixed}, // distro-agnostic
		}},
	} {
		if err := s.UpsertAdvisoryWithRanges(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.ListAdvisoryRanges(ctx, RangeQuery{Distro: "ubuntu", Release: "22.04", Package: pkg})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AdvisoryID != a1 || got[0].Fixed != "2" {
		t.Fatalf("ubuntu 22.04 by binary name = %+v", got)
	}
	got, err = s.ListAdvisoryRanges(ctx, RangeQuery{Distro: "ubuntu", Release: "22.04", Package: src})
	if err != nil {
		t.Fatal(err)
	}
	// By source name: a1's 22.04 range and a2's any-release range, not 20.04.
	if len(got) != 2 || got[0].AdvisoryID != a1 && got[1].AdvisoryID != a1 {
		t.Fatalf("ubuntu 22.04 by source name = %+v", got)
	}
	for _, r := range got {
		if r.Release == "20.04" {
			t.Fatalf("20.04 range leaked into 22.04 query: %+v", r)
		}
	}
	got, err = s.ListAdvisoryRanges(ctx, RangeQuery{Distro: "debian", Release: "12", Package: pkg})
	if err != nil || len(got) != 1 || got[0].AdvisoryID != a3 || got[0].FixState != FixStateAffected {
		t.Fatalf("debian 12 = %+v, err %v (distro-agnostic range must be excluded by default)", got, err)
	}
	got, err = s.ListAdvisoryRanges(ctx, RangeQuery{Distro: "debian", Release: "12", Package: pkg, IncludeDistroAgnostic: true})
	if err != nil || len(got) != 2 {
		t.Fatalf("debian 12 with agnostic = %+v, err %v", got, err)
	}
	got, err = s.ListAdvisoryRanges(ctx, RangeQuery{Distro: "rocky", Release: "9", Package: pkg})
	if err != nil || len(got) != 0 {
		t.Fatalf("rocky 9 = %+v, err %v; want none", got, err)
	}
}

// A new-shape advisory must not appear in the legacy list the current matcher
// reads, and the legacy writer must still work and be mirrored into ranges.
func TestLegacyAdvisoryPathUnchanged(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	legacy, modern := "TEST-"+randID(t), "TEST-"+randID(t)
	pkg := "legacypkg" + randID(t)
	if err := s.UpsertAdvisory(ctx, legacy, "CVE-1", pkg, "1.2.3", "high", "old shape", "local"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAdvisoryWithRanges(ctx, Advisory{ID: modern, Severity: "high", Ranges: []AdvisoryRange{{Package: pkg, FixState: FixStateAffected}}}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListAdvisories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sawLegacy bool
	for _, row := range list {
		if row["id"] == modern {
			t.Fatalf("new-shape advisory leaked into legacy list: %v", row)
		}
		if row["id"] == legacy {
			sawLegacy = true
			if row["package"] != pkg || row["below"] != "1.2.3" {
				t.Fatalf("legacy row changed: %v", row)
			}
		}
	}
	if !sawLegacy {
		t.Fatal("legacy advisory missing from ListAdvisories")
	}
	got, err := s.GetAdvisory(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ranges) != 1 || got.Ranges[0].Ecosystem != "legacy" || got.Ranges[0].Fixed != "1.2.3" || got.Ranges[0].FixState != FixStateFixed || got.Ranges[0].Distro != "" {
		t.Fatalf("legacy row not mirrored: %+v", got.Ranges)
	}
	// Legacy re-upsert with a new floor moves the mirrored range.
	if err := s.UpsertAdvisory(ctx, legacy, "CVE-1", pkg, "1.2.4", "high", "old shape", "local"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAdvisory(ctx, legacy)
	if len(got.Ranges) != 1 || got.Ranges[0].Fixed != "1.2.4" {
		t.Fatalf("mirrored range did not follow the floor: %+v", got.Ranges)
	}
	// Taking the advisory over in the new shape drops the mirrored range.
	if err := s.UpsertAdvisoryWithRanges(ctx, Advisory{ID: legacy, Severity: "high", Ranges: []AdvisoryRange{{Distro: "ubuntu", Release: "22.04", Package: pkg, Fixed: "2", FixState: FixStateFixed}}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAdvisory(ctx, legacy)
	if len(got.Ranges) != 1 || got.Ranges[0].Distro != "ubuntu" {
		t.Fatalf("takeover left a legacy range behind: %+v", got.Ranges)
	}
}
