package feeds

import "testing"

func TestNormalizeSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"Critical": "critical", "IMPORTANT": "high", "high": "high", "Moderate": "medium", "medium": "medium",
		"Low": "low", "negligible": "low", "unimportant": "low",
		"": "unknown", "untriaged": "unknown", "not yet assigned": "unknown", "end-of-life": "unknown",
	} {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
	if !(SeverityRank("critical") > SeverityRank("high") && SeverityRank("high") > SeverityRank("medium") &&
		SeverityRank("medium") > SeverityRank("low") && SeverityRank("low") > SeverityRank("unknown")) {
		t.Error("severity ranks are not ordered")
	}
}

func TestSplitCVSS(t *testing.T) {
	s, v, ok := SplitCVSS("7.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
	if !ok || s != 7.5 || v != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Errorf("got %v %q %v", s, v, ok)
	}
	for _, bad := range []string{"", "CVSS:3.1/AV:N", "11/CVSS:3.1/x", "-1/x", "7.5", "abc/def"} {
		if _, _, ok := SplitCVSS(bad); ok {
			t.Errorf("SplitCVSS(%q) accepted", bad)
		}
	}
}

func TestIsCVE(t *testing.T) {
	for _, ok := range []string{"CVE-2021-44228", "CVE-2026-110875", "CVE-1999-0001"} {
		if !IsCVE(ok) {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "cve-2021-44228", "CVE-21-1", "CVE-2021-123", "TEMP-0000000-ABC", "CVE-2021-44228 ", "GHSA-xxxx"} {
		if IsCVE(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestStatsSkip(t *testing.T) {
	var s Stats
	s.Skip("a")
	s.Skip("a")
	s.Skip("b")
	if s.Skipped["a"] != 2 || s.Skipped["b"] != 1 {
		t.Errorf("%v", s.Skipped)
	}
}
