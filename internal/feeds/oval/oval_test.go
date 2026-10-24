package oval

import (
	"errors"
	"io"
	"strings"
	"testing"
)

const doc = `<?xml version="1.0"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:lx="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator><product_name>t</product_name></generator>
  <definitions>
    <definition id="d:1" class="patch">
      <metadata><title> T1 </title>
        <reference source="CVE" ref_id="CVE-2020-0001"/>
        <advisory><severity>High</severity>
          <cve priority="high" cvss_score="7.5" cvss_vector="V">CVE-2020-0001</cve>
          <cve impact="low">CVE-2020-0002 at SUSE</cve>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="t:1" comment="a"/>
        <criteria operator="OR"><criterion test_ref="t:2" comment="b"/><criteria><criterion test_ref="t:3" comment="deep"/></criteria></criteria>
      </criteria>
    </definition>
    <definition id="d:2" class="inventory"><metadata><title>skip me</title></metadata><criteria><criterion test_ref="t:9" comment="x"/></criteria></definition>
  </definitions>
  <tests>
    <lx:dpkginfo_test id="t:1" comment="c1"><lx:object object_ref="o:1"/><lx:state state_ref="s:1"/></lx:dpkginfo_test>
    <lx:rpminfo_test id="t:2" comment="c2"><lx:object object_ref="o:2"/></lx:rpminfo_test>
    <lx:rpminfo_test id="t:3" comment="c3"><lx:object object_ref="o:3"/><lx:state state_ref="s:3"/></lx:rpminfo_test>
    <lx:rpminfo_test id="t:9" comment="unreferenced"><lx:object object_ref="o:9"/></lx:rpminfo_test>
  </tests>
  <objects>
    <lx:dpkginfo_object id="o:1"><lx:name var_ref="v:1" var_check="at least one"/></lx:dpkginfo_object>
    <lx:rpminfo_object id="o:2"><lx:name> plain </lx:name></lx:rpminfo_object>
    <lx:rpminfo_object id="o:3"><lx:name>other</lx:name></lx:rpminfo_object>
    <lx:rpminfo_object id="o:9"><lx:name>never</lx:name></lx:rpminfo_object>
  </objects>
  <states>
    <lx:dpkginfo_state id="s:1"><lx:evr datatype="debian_evr_string" operation="less than">1.2-3</lx:evr></lx:dpkginfo_state>
    <lx:rpminfo_state id="s:3"><lx:arch operation="pattern match">x86_64</lx:arch><lx:version operation="equals">0</lx:version></lx:rpminfo_state>
    <lx:rpminfo_state id="s:9"><lx:evr operation="less than">9</lx:evr></lx:rpminfo_state>
  </states>
  <variables>
    <local_variable id="v:local"><concat/></local_variable>
    <constant_variable id="v:1"><value>bin-a</value><value> bin-b </value><value></value></constant_variable>
    <constant_variable id="v:unreferenced"><value>zzz</value></constant_variable>
  </variables>
</oval_definitions>`

func opener(s string) Opener {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
}

func TestReadFlattensAndFilters(t *testing.T) {
	d, err := Read(opener(doc), "patch")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Defs) != 1 {
		t.Fatalf("defs = %d, want 1 (inventory class filtered out)", len(d.Defs))
	}
	def := d.Defs[0]
	if def.ID != "d:1" || def.Title != "T1" || def.Severity != "High" {
		t.Errorf("def = %+v", def)
	}
	if len(def.Criteria) != 3 {
		t.Errorf("criteria = %+v, want 3 (nested criteria flattened)", def.Criteria)
	}
	if len(def.RefCVEs) != 1 || def.RefCVEs[0] != "CVE-2020-0001" {
		t.Errorf("RefCVEs = %v", def.RefCVEs)
	}
	if len(def.CVEs) != 2 || def.CVEs[0].ID != "CVE-2020-0001" || def.CVEs[1].ID != "CVE-2020-0002" {
		t.Fatalf("CVEs = %+v", def.CVEs)
	}
	if def.CVEs[0].CVSSScore == nil || *def.CVEs[0].CVSSScore != 7.5 || def.CVEs[0].Priority != "high" || def.CVEs[1].Impact != "low" {
		t.Errorf("CVE attrs = %+v", def.CVEs)
	}

	// Only what the kept definitions reference survives pass two.
	if _, ok := d.Tests["t:9"]; ok {
		t.Error("unreferenced test kept")
	}
	if _, ok := d.Objects["o:9"]; ok {
		t.Error("unreferenced object kept")
	}
	if _, ok := d.States["s:9"]; ok {
		t.Error("unreferenced state kept")
	}
	if _, ok := d.Vars["v:unreferenced"]; ok {
		t.Error("unreferenced variable kept")
	}

	t1 := d.Tests["t:1"]
	if t1.Kind != "dpkginfo_test" || t1.Object != "o:1" || t1.State != "s:1" || t1.Comment != "c1" {
		t.Errorf("t:1 = %+v", t1)
	}
	if got := d.Names(t1); len(got) != 2 || got[0] != "bin-a" || got[1] != "bin-b" {
		t.Errorf("variable names = %v (blank values dropped, trimmed)", got)
	}
	if got := d.Names(d.Tests["t:2"]); len(got) != 1 || got[0] != "plain" {
		t.Errorf("plain names = %v", got)
	}
	if s := d.States["s:1"]; s.EVR != "1.2-3" || s.EVROp != "less than" {
		t.Errorf("s:1 = %+v", s)
	}
	if s := d.States["s:3"]; s.Version != "0" || s.VersionOp != "equals" || s.EVR != "" {
		t.Errorf("s:3 = %+v", s)
	}
}

func TestReadKeepsAllClassesWhenUnfiltered(t *testing.T) {
	d, err := Read(opener(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Defs) != 2 {
		t.Fatalf("defs = %d, want 2", len(d.Defs))
	}
	if _, ok := d.Tests["t:9"]; !ok {
		t.Error("test referenced by the inventory definition was dropped")
	}
}

func TestReadNoMatchingDefinitions(t *testing.T) {
	d, err := Read(opener(doc), "vulnerability")
	if err != nil || len(d.Defs) != 0 || len(d.Tests) != 0 {
		t.Fatalf("defs=%v tests=%v err=%v", d.Defs, d.Tests, err)
	}
}

func TestReadErrors(t *testing.T) {
	if _, err := Read(opener("<oval_definitions><definitions><definition id='x' class='patch'><metadata>"), "patch"); err == nil {
		t.Error("truncated XML accepted")
	}
	if _, err := Read(opener("not xml at all"), "patch"); err == nil {
		t.Error("non-XML accepted")
	}
	want := errors.New("boom")
	if _, err := Read(func() (io.ReadCloser, error) { return nil, want }, "patch"); !errors.Is(err, want) {
		t.Errorf("opener error = %v", err)
	}
	// Second pass fails (tests section truncated): must not return a half doc.
	cut := doc[:strings.Index(doc, "<objects>")]
	if _, err := Read(opener(cut), "patch"); err == nil {
		t.Error("truncated tests/objects accepted")
	}
}

func TestOpenerCalledOncePerPass(t *testing.T) {
	n := 0
	_, err := Read(func() (io.ReadCloser, error) { n++; return io.NopCloser(strings.NewReader(doc)), nil }, "patch")
	if err != nil || n != 2 {
		t.Fatalf("opens = %d err = %v, want 2 passes", n, err)
	}
}
