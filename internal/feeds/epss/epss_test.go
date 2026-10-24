package epss

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
	"time"
)

func gz(t *testing.T, b []byte) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestParseGzipFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/epss.csv")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Score{}
	meta, err := ParseGzip(gz(t, raw), func(s Score) error { got[s.CVE] = s; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if meta.ModelVersion != "v2026.06.15" {
		t.Errorf("model = %q", meta.ModelVersion)
	}
	if !meta.ScoreDate.Equal(time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("score date = %v", meta.ScoreDate)
	}
	// 8 data rows: 4 valid; 4 malformed (score>1, non-numeric, bad id, short row).
	if meta.Rows != 4 || len(got) != 4 {
		t.Fatalf("rows = %d, got %d, want 4", meta.Rows, len(got))
	}
	if meta.Stats.Skipped["malformed row"] != 4 {
		t.Errorf("skipped = %v, want 4 malformed", meta.Stats.Skipped)
	}
	if s := got["CVE-2021-44228"]; s.EPSS != 0.97565 || s.Percentile != 1.0 {
		t.Errorf("log4j = %+v", s)
	}
	if _, bad := got["CVE-2020-0002"]; bad {
		t.Error("score above 1 was accepted")
	}
}

func TestParseRejectsBadFiles(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"no header":      {"#model_version:v1,score_date:2026-01-01T00:00:00Z\nCVE-2020-0001,0.1,0.2\n", "header"},
		"empty":          {"", "no header"},
		"no score date":  {"#model_version:v1\ncve,epss,percentile\nCVE-2020-0001,0.1,0.2\n", "score_date"},
		"no rows":        {"#model_version:v1,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n", "no score rows"},
		"html error doc": {"<html>503</html>\n", "header"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.in), func(Score) error { return nil })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
	if _, err := ParseGzip(strings.NewReader("not gzip"), func(Score) error { return nil }); err == nil {
		t.Error("non-gzip input accepted")
	}
}

func TestParseNoTrailingNewlineAndCRLF(t *testing.T) {
	in := "#model_version:v1,score_date:2026-01-02T00:00:00Z\r\ncve,epss,percentile\r\nCVE-2020-0001,0.1,0.2\r\nCVE-2020-0002,0.3,0.4"
	n := 0
	meta, err := Parse(strings.NewReader(in), func(Score) error { n++; return nil })
	if err != nil || n != 2 || meta.Rows != 2 {
		t.Fatalf("n=%d rows=%d err=%v", n, meta.Rows, err)
	}
}
