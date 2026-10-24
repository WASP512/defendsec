package kev

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseFixture(t *testing.T) {
	f, err := os.Open("testdata/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cat, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if cat.Version != "2026.10.23" {
		t.Errorf("version = %q", cat.Version)
	}
	// 4 rows in the file, 1 with a malformed id.
	if len(cat.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(cat.Entries))
	}
	if got := cat.Stats.Skipped["malformed cveID"]; got != 1 {
		t.Errorf("skipped malformed = %d, want 1", got)
	}
	// Sorted by CVE.
	want := []string{"CVE-2014-0160", "CVE-2021-44228", "CVE-2024-3094"}
	for i, e := range cat.Entries {
		if e.CVE != want[i] {
			t.Errorf("entry %d = %s, want %s", i, e.CVE, want[i])
		}
	}
	log4j := cat.Entries[1]
	if !log4j.DateAdded.Equal(time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("dateAdded = %v", log4j.DateAdded)
	}
	if !log4j.Ransomware || cat.Entries[0].Ransomware {
		t.Errorf("ransomware flags wrong: log4j=%v heartbleed=%v", log4j.Ransomware, cat.Entries[0].Ransomware)
	}
	if log4j.Vendor != "Apache" || log4j.Product != "Log4j2" {
		t.Errorf("vendor/product = %q/%q", log4j.Vendor, log4j.Product)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"not json":           {`<html>`, "decode"},
		"no array":           {`{"catalogVersion":"x"}`, "no vulnerabilities array"},
		"truncated vs count": {`{"count":5,"vulnerabilities":[{"cveID":"CVE-2020-0001","dateAdded":"2020-01-01"}]}`, "count=5"},
		"bad date":           {`{"vulnerabilities":[{"cveID":"CVE-2020-0001","dateAdded":"01/02/2020"}]}`, "dateAdded"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseDeduplicates(t *testing.T) {
	cat, err := Parse(strings.NewReader(`{"vulnerabilities":[
		{"cveID":"CVE-2020-0001","dateAdded":"2020-01-01"},
		{"cveID":"CVE-2020-0001","dateAdded":"2020-02-02"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 1 || cat.Stats.Skipped["duplicate cveID"] != 1 {
		t.Fatalf("entries=%d skipped=%v", len(cat.Entries), cat.Stats.Skipped)
	}
	if cat.Entries[0].DateAdded.Month() != time.January {
		t.Errorf("kept the later duplicate")
	}
}

func TestEmptyCatalogParsesAsEmpty(t *testing.T) {
	// A zero-row catalog would clear every KEV flag, so the sync layer refuses
	// it; Parse itself just reports 0 entries.
	cat, err := Parse(strings.NewReader(`{"vulnerabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 0 {
		t.Fatal("expected no entries")
	}
}
