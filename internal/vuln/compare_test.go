package vuln

import "testing"

func TestAssessBackportsAreNotGuessed(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		floor     string
		scheme    Scheme
		want      Verdict
	}{
		{
			// The case the previous test suite asserted as "vulnerable".
			// Canonical fixed CVE-2024-6387 in 1:8.9p1-3ubuntu0.10 without
			// ever moving to upstream 9.8p1, so a version comparison alone
			// cannot tell a patched host from an exposed one.
			name:      "ubuntu openssh backport",
			installed: "1:8.9p1-3ubuntu0.11",
			floor:     "9.8p1",
			scheme:    SchemeDpkg,
			want:      VerdictUnknown,
		},
		{
			name:      "ubuntu openssl backport",
			installed: "1.1.1f-1ubuntu2.19",
			floor:     "1.1.1k",
			scheme:    SchemeDpkg,
			want:      VerdictUnknown,
		},
		{
			name:      "rhel family backport",
			installed: "3.0.7-18.el8",
			floor:     "3.0.9",
			scheme:    SchemeRPM,
			want:      VerdictUnknown,
		},
		{
			// No distro revision, so the upstream comparison is the whole
			// story and the verdict is safe to give.
			name:      "upstream build below the floor",
			installed: "3.0.2",
			floor:     "3.0.14",
			scheme:    SchemeDpkg,
			want:      VerdictVulnerable,
		},
		{
			// Distro-packaged, but upstream is already past the floor, so a
			// backport cannot change the answer.
			name:      "distro build above the floor",
			installed: "3.0.15-1ubuntu1",
			floor:     "3.0.14",
			scheme:    SchemeDpkg,
			want:      VerdictNotVulnerable,
		},
		{
			name:      "exactly at the floor",
			installed: "3.0.14",
			floor:     "3.0.14",
			scheme:    SchemeDpkg,
			want:      VerdictNotVulnerable,
		},
		{
			name:      "pre-release sorts below the floor",
			installed: "3.0.14~rc1",
			floor:     "3.0.14",
			scheme:    SchemeDpkg,
			want:      VerdictVulnerable,
		},
		{
			name:      "missing version",
			installed: "",
			floor:     "3.0.14",
			scheme:    SchemeDpkg,
			want:      VerdictUnknown,
		},
		{
			name:      "missing floor",
			installed: "3.0.14",
			floor:     "",
			scheme:    SchemeDpkg,
			want:      VerdictUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.installed, tc.floor, tc.scheme)
			if got.Verdict != tc.want {
				t.Errorf("Assess(%q, %q) = %v (%s), want %v",
					tc.installed, tc.floor, got.Verdict, got.Reason, tc.want)
			}
			if got.Reason == "" {
				t.Error("every assessment should carry a reason")
			}
		})
	}
}

// An undecidable comparison must not raise an alert. VersionOlderThan is the
// boolean the alert path still calls, so VerdictUnknown has to collapse to
// false rather than true.
func TestVersionOlderThanDoesNotAlertOnUnknown(t *testing.T) {
	if VersionOlderThan("1:8.9p1-3ubuntu0.11", "9.8p1") {
		t.Error("a possible backport must not be reported as older")
	}
	if VersionOlderThan("1.1.1f-1ubuntu2.19", "1.1.1k") {
		t.Error("a possible backport must not be reported as older")
	}
	if !VersionOlderThan("3.0.2", "3.0.14") {
		t.Error("an upstream build below the floor is older")
	}
	if VersionOlderThan("3.0.14", "3.0.14") {
		t.Error("a version at the floor is not older")
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{
		VerdictUnknown:       "unknown",
		VerdictVulnerable:    "vulnerable",
		VerdictNotVulnerable: "not-vulnerable",
	} {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, got, want)
		}
	}
}
