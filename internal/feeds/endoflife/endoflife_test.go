package endoflife

import (
	"os"
	"strings"
	"testing"
)

func openFixture(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open("testdata/products-trimmed.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseKeepsOnlyWantedProducts(t *testing.T) {
	cat, err := Parse(openFixture(t), []string{"php", "nodejs", "python", "postgresql", "dotnet", "redis"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range cat.Products {
		names = append(names, p.Name)
	}
	if got := strings.Join(names, ","); got != "dotnet,nodejs,php,postgresql,python" {
		t.Errorf("products = %s", got)
	}
	// android is in the file and not wanted; redis is wanted and not in the file.
	if cat.Stats.Skipped["wanted product not in the feed"] != 1 {
		t.Errorf("skips = %v, want one missing product", cat.Stats.Skipped)
	}
	if cat.SchemaVersion != "1.2.1" {
		t.Errorf("schema = %q", cat.SchemaVersion)
	}
	if cat.Releases() != 5+5+3+4+4 {
		t.Errorf("releases = %d", cat.Releases())
	}
}

func TestParsePHP80(t *testing.T) {
	cat, err := Parse(openFixture(t), []string{"php"})
	if err != nil {
		t.Fatal(err)
	}
	var got *Release
	for i, r := range cat.Products[0].Releases {
		if r.Cycle == "8.0" {
			got = &cat.Products[0].Releases[i]
		}
	}
	if got == nil {
		t.Fatal("php 8.0 missing")
	}
	// The motivating case: PHP 8.0 ended security support on 2023-11-26.
	if got.EolFrom != "2023-11-26" || got.EoasFrom != "2022-11-26" || got.Latest != "8.0.30" {
		t.Errorf("php 8.0 = %+v", *got)
	}
	if cat.Products[0].Label != "PHP" {
		t.Errorf("label = %q", cat.Products[0].Label)
	}
}

func TestParseNullDatesAndFlag(t *testing.T) {
	cat, err := Parse(openFixture(t), []string{"nodejs"})
	if err != nil {
		t.Fatal(err)
	}
	var n3 Release
	for _, r := range cat.Products[0].Releases {
		if r.Cycle == "3" {
			n3 = r
		}
	}
	// Node.js 3 is end of life with no date on record.
	if n3.EolFrom != "" || !n3.IsEol {
		t.Errorf("nodejs 3 = %+v, want no eol date and IsEol", n3)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"not json":       {`{`, "decode"},
		"old schema":     {`{"schema_version":"0.9","result":[]}`, "schema_version"},
		"no result":      {`{"schema_version":"1.2.1"}`, "no result"},
		"truncated":      {`{"schema_version":"1.2.1","total":3,"result":[{"name":"php","label":"PHP","releases":[]}]}`, "truncated"},
		"nothing wanted": {`{"schema_version":"1.2.1","total":1,"result":[{"name":"android","label":"Android","releases":[]}]}`, "none of the"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.in), []string{"php"})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestParseToleratesOddDates(t *testing.T) {
	in := `{"schema_version":"1.2.1","total":1,"result":[{"name":"php","label":"PHP","releases":[
		{"name":"8.0","releaseDate":"2020-11-26","eolFrom":"soon","eoasFrom":true,"isEol":true,"latest":{"name":"8.0.30","link":"x"}},
		{"name":"8.0","releaseDate":"2020-11-26"},
		{"name":"","releaseDate":"2020-11-26"}]}]}`
	cat, err := Parse(strings.NewReader(in), []string{"php"})
	if err != nil {
		t.Fatal(err)
	}
	rs := cat.Products[0].Releases
	if len(rs) != 1 || rs[0].EolFrom != "" || !rs[0].IsEol {
		t.Fatalf("releases = %+v", rs)
	}
	if cat.Stats.Skipped["unreadable date (left empty)"] != 1 || cat.Stats.Skipped["release without a unique name"] != 2 {
		t.Errorf("skips = %v", cat.Stats.Skipped)
	}
}
