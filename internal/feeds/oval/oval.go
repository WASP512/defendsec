// Package oval is a streaming reader for the subset of OVAL 5 that the distro
// vulnerability feeds (Ubuntu USN, Red Hat, SUSE) share: definitions with their
// criteria, and the package tests, objects, states and constant variables the
// criteria point at.
//
// It deliberately does not evaluate criteria. OVAL criteria are boolean trees
// evaluated against a live host; DefendSec never runs them. It flattens each
// definition to the list of tests it mentions and lets the per-distro parser
// (internal/feeds/{ubuntu,rhel,suse}) pull package, fixed version and state out
// of the tests it understands. Anything it does not understand is counted as
// skipped by the caller, not guessed.
//
// Files are large (Ubuntu jammy is 41 MB of XML, SUSE Leap 16 about 150 MB), so
// Read makes two passes over the file with encoding/xml tokens: the first keeps
// only the definitions asked for, the second keeps only the tests, objects,
// states and variables those definitions reference. Memory stays proportional
// to what is referenced, not to the file.
package oval

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Criterion is one <criterion> element, wherever it sits in the criteria tree.
type Criterion struct {
	TestRef string
	Comment string
}

// CVE is one <cve> element inside a definition's <advisory>.
type CVE struct {
	ID         string
	Priority   string // Ubuntu
	Impact     string // Red Hat, SUSE
	CVSSScore  *float64
	CVSSVector string
	CVSS3      string // "<score>/<vector>" (Red Hat, SUSE)
	CWE        string
}

// Definition is a flattened <definition>.
type Definition struct {
	ID       string
	Class    string
	Title    string
	Severity string
	RefCVEs  []string // <reference source="CVE">, for definitions without <advisory><cve>
	Issued   string   // <advisory><issued date="YYYY-MM-DD"/> (Red Hat); empty if absent
	CVEs     []CVE
	Criteria []Criterion
}

// Test is a <*_test> element. Kind is the element's local name, e.g.
// "dpkginfo_test" or "rpminfo_test".
type Test struct {
	Kind    string
	Comment string
	Object  string
	State   string
}

// Object is a <*_object> element, reduced to the package name or the variable
// holding the package names.
type Object struct {
	Kind   string
	Name   string
	VarRef string
}

// State is a <*_state> element, reduced to its evr and version constraints.
type State struct {
	Kind      string
	EVR       string
	EVROp     string
	Version   string
	VersionOp string
}

// Doc is the result of Read.
type Doc struct {
	Defs    []Definition
	Tests   map[string]Test
	Objects map[string]Object
	States  map[string]State
	Vars    map[string][]string
}

// Opener returns a fresh reader over the decompressed XML each time it is
// called; Read calls it once per pass.
type Opener func() (io.ReadCloser, error)

// Names returns the package names a test's object refers to, resolving a
// variable reference through the document's constant variables.
func (d *Doc) Names(t Test) []string {
	obj, ok := d.Objects[t.Object]
	if !ok {
		return nil
	}
	if obj.VarRef != "" {
		return d.Vars[obj.VarRef]
	}
	if obj.Name != "" {
		return []string{obj.Name}
	}
	return nil
}

// ---- XML shapes ------------------------------------------------------------

type xCriteria struct {
	Criterion []struct {
		TestRef string `xml:"test_ref,attr"`
		Comment string `xml:"comment,attr"`
	} `xml:"criterion"`
	Criteria []xCriteria `xml:"criteria"`
}

type xDefinition struct {
	ID    string `xml:"id,attr"`
	Class string `xml:"class,attr"`
	Meta  struct {
		Title string `xml:"title"`
		Refs  []struct {
			Source string `xml:"source,attr"`
			RefID  string `xml:"ref_id,attr"`
		} `xml:"reference"`
		Advisory struct {
			Severity string `xml:"severity"`
			Issued   struct {
				Date string `xml:"date,attr"`
			} `xml:"issued"`
			CVEs []struct {
				Text       string `xml:",chardata"`
				Priority   string `xml:"priority,attr"`
				Impact     string `xml:"impact,attr"`
				CVSSScore  string `xml:"cvss_score,attr"`
				CVSSVector string `xml:"cvss_vector,attr"`
				CVSS3      string `xml:"cvss3,attr"`
				CWE        string `xml:"cwe,attr"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria xCriteria `xml:"criteria"`
}

type xTest struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
	Object  struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State []struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type xObject struct {
	ID   string `xml:"id,attr"`
	Name struct {
		Text   string `xml:",chardata"`
		VarRef string `xml:"var_ref,attr"`
	} `xml:"name"`
}

type xState struct {
	ID  string `xml:"id,attr"`
	EVR struct {
		Text string `xml:",chardata"`
		Op   string `xml:"operation,attr"`
	} `xml:"evr"`
	Version struct {
		Text string `xml:",chardata"`
		Op   string `xml:"operation,attr"`
	} `xml:"version"`
}

type xVariable struct {
	ID     string   `xml:"id,attr"`
	Values []string `xml:"value"`
}

func flatten(c xCriteria, out *[]Criterion) {
	for _, cr := range c.Criterion {
		*out = append(*out, Criterion{TestRef: cr.TestRef, Comment: cr.Comment})
	}
	for _, sub := range c.Criteria {
		flatten(sub, out)
	}
}

// ---- Reader ----------------------------------------------------------------

// Read parses the document. Only definitions whose class is in classes are
// kept (an empty list keeps all). The tests, objects, states and variables
// returned are those referenced, directly or through a kept test, by a kept
// definition.
func Read(open Opener, classes ...string) (*Doc, error) {
	doc := &Doc{
		Tests:   map[string]Test{},
		Objects: map[string]Object{},
		States:  map[string]State{},
		Vars:    map[string][]string{},
	}
	keepClass := func(c string) bool {
		if len(classes) == 0 {
			return true
		}
		for _, k := range classes {
			if k == c {
				return true
			}
		}
		return false
	}

	// Pass 1: definitions.
	if err := walk(open, func(d *xml.Decoder, section string, se xml.StartElement) error {
		if section != "definitions" || se.Name.Local != "definition" {
			return d.Skip()
		}
		for _, a := range se.Attr {
			if a.Name.Local == "class" && !keepClass(a.Value) {
				return d.Skip()
			}
		}
		var xd xDefinition
		if err := d.DecodeElement(&xd, &se); err != nil {
			return err
		}
		doc.Defs = append(doc.Defs, convertDefinition(xd))
		return nil
	}, "definitions"); err != nil {
		return nil, fmt.Errorf("oval: definitions: %w", err)
	}
	if len(doc.Defs) == 0 {
		return doc, nil
	}

	wantTests := map[string]bool{}
	for _, def := range doc.Defs {
		for _, c := range def.Criteria {
			wantTests[c.TestRef] = true
		}
	}
	wantObjects := map[string]bool{}
	wantStates := map[string]bool{}
	wantVars := map[string]bool{}

	// Pass 2: tests, objects, states, variables, in document order.
	err := walk(open, func(d *xml.Decoder, section string, se xml.StartElement) error {
		local := se.Name.Local
		switch section {
		case "tests":
			if !strings.HasSuffix(local, "_test") {
				return d.Skip()
			}
			var xt xTest
			if err := d.DecodeElement(&xt, &se); err != nil {
				return err
			}
			if !wantTests[xt.ID] {
				return nil
			}
			t := Test{Kind: local, Comment: xt.Comment, Object: xt.Object.Ref}
			if len(xt.State) > 0 {
				t.State = xt.State[0].Ref
			}
			doc.Tests[xt.ID] = t
			if t.Object != "" {
				wantObjects[t.Object] = true
			}
			if t.State != "" {
				wantStates[t.State] = true
			}
		case "objects":
			if !strings.HasSuffix(local, "_object") {
				return d.Skip()
			}
			var xo xObject
			if err := d.DecodeElement(&xo, &se); err != nil {
				return err
			}
			if !wantObjects[xo.ID] {
				return nil
			}
			doc.Objects[xo.ID] = Object{Kind: local, Name: strings.TrimSpace(xo.Name.Text), VarRef: xo.Name.VarRef}
			if xo.Name.VarRef != "" {
				wantVars[xo.Name.VarRef] = true
			}
		case "states":
			if !strings.HasSuffix(local, "_state") {
				return d.Skip()
			}
			var xs xState
			if err := d.DecodeElement(&xs, &se); err != nil {
				return err
			}
			if !wantStates[xs.ID] {
				return nil
			}
			doc.States[xs.ID] = State{
				Kind: local, EVR: strings.TrimSpace(xs.EVR.Text), EVROp: xs.EVR.Op,
				Version: strings.TrimSpace(xs.Version.Text), VersionOp: xs.Version.Op,
			}
		case "variables":
			if local != "constant_variable" {
				return d.Skip()
			}
			var xv xVariable
			if err := d.DecodeElement(&xv, &se); err != nil {
				return err
			}
			if wantVars[xv.ID] {
				vals := make([]string, 0, len(xv.Values))
				for _, v := range xv.Values {
					if v = strings.TrimSpace(v); v != "" {
						vals = append(vals, v)
					}
				}
				doc.Vars[xv.ID] = vals
			}
		default:
			return d.Skip()
		}
		return nil
	}, "")
	if err != nil {
		return nil, fmt.Errorf("oval: tests/objects/states: %w", err)
	}
	return doc, nil
}

func convertDefinition(xd xDefinition) Definition {
	d := Definition{ID: xd.ID, Class: xd.Class, Title: strings.TrimSpace(xd.Meta.Title), Severity: strings.TrimSpace(xd.Meta.Advisory.Severity),
		Issued: strings.TrimSpace(xd.Meta.Advisory.Issued.Date)}
	for _, r := range xd.Meta.Refs {
		if strings.EqualFold(r.Source, "CVE") {
			d.RefCVEs = append(d.RefCVEs, strings.TrimSpace(r.RefID))
		}
	}
	for _, c := range xd.Meta.Advisory.CVEs {
		fields := strings.Fields(c.Text)
		if len(fields) == 0 {
			continue
		}
		cve := CVE{ID: fields[0], Priority: c.Priority, Impact: c.Impact, CVSSVector: c.CVSSVector, CVSS3: c.CVSS3, CWE: c.CWE}
		if c.CVSSScore != "" {
			if f, err := strconv.ParseFloat(c.CVSSScore, 64); err == nil {
				cve.CVSSScore = &f
			}
		}
		d.CVEs = append(d.CVEs, cve)
	}
	flatten(xd.Criteria, &d.Criteria)
	return d
}

// walk opens the file and calls fn for every element that is a child of a
// child of the root (<definitions>/<definition>, <tests>/<*_test>, ...), with
// section set to the name of the intermediate element. A top-level element
// named stopAfter ends the walk once it closes; any other top-level element
// that fn is not interested in is skipped in one step by fn returning
// d.Skip() for its children, but top-level elements named "definitions" are
// skipped wholesale when stopAfter is empty (second pass).
func walk(open Opener, fn func(d *xml.Decoder, section string, se xml.StartElement) error, stopAfter string) error {
	rc, err := open()
	if err != nil {
		return err
	}
	defer rc.Close()
	d := xml.NewDecoder(rc)
	d.Strict = false
	section := ""
	depth := 0
	sawRoot := false
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			if !sawRoot {
				return errors.New("no <oval_definitions> document")
			}
			if depth != 0 {
				return fmt.Errorf("unexpected end of document at depth %d", depth)
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch depth {
			case 0:
				if t.Name.Local != "oval_definitions" {
					return fmt.Errorf("root element is <%s>, want <oval_definitions>", t.Name.Local)
				}
				sawRoot = true
				depth = 1
			case 1:
				if stopAfter == "" && t.Name.Local == "definitions" {
					if err := d.Skip(); err != nil {
						return err
					}
					continue
				}
				section = t.Name.Local
				depth = 2
			case 2:
				// Child of a section: hand it to fn, which consumes it
				// (DecodeElement or Skip), so depth is unchanged afterwards.
				if err := fn(d, section, t); err != nil {
					return err
				}
			}
		case xml.EndElement:
			depth--
			if depth == 1 {
				if stopAfter != "" && t.Name.Local == stopAfter {
					return nil
				}
				section = ""
			}
		}
	}
}
