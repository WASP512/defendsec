package evidence

import (
	"strings"
	"testing"
)

// Slice 7c: the bundle's findings are rows the chain never held, so a bundle
// that drops, edits or invents one must not verify. Every case here starts from
// the intact surfaceBundle (which verifies) and changes only the findings.

func TestVerifySurfaceCatchesTamperedFindings(t *testing.T) {
	cases := map[string]func(b *Bundle){
		"findings emptied":       func(b *Bundle) { b.Surface.Findings = []SurfaceFinding{} },
		"findings removed (nil)": func(b *Bundle) { b.Surface.Findings = nil },
		"severity edited":        func(b *Bundle) { b.Surface.Findings[0].Severity = "low" },
		"severity raised":        func(b *Bundle) { b.Surface.Findings[0].Severity = "critical" },
		"title edited":           func(b *Bundle) { b.Surface.Findings[0].Title = "DMARC is fine" },
		"check group edited":     func(b *Bundle) { b.Surface.Findings[0].Check = "spf" },
		"detail edited":          func(b *Bundle) { b.Surface.Findings[0].Detail = "nothing to see" },
		"fix edited":             func(b *Bundle) { b.Surface.Findings[0].Fix = "do nothing" },
		"evidence edited":        func(b *Bundle) { b.Surface.Findings[0].Evidence = map[string]any{"record": "v=DMARC1; p=reject"} },
		"controls edited":        func(b *Bundle) { b.Surface.Findings[0].Controls = []string{"CC1.1"} },
		"finding moved to asset": func(b *Bundle) { b.Surface.Findings[0].AssetValue = "example.net" },
		"finding id renamed":     func(b *Bundle) { b.Surface.Findings[0].FindingID = "dmarc.missing" },
		"subject renamed":        func(b *Bundle) { b.Surface.Findings[0].Subject = "mail.example.com" },
		"injected, no intervals": func(b *Bundle) { b.Surface.Findings = append(b.Surface.Findings, injectedFinding(nil)) },
		"injected, copied dates": func(b *Bundle) {
			b.Surface.Findings = append(b.Surface.Findings, injectedFinding(b.Surface.Findings[0].Intervals))
		},
		"duplicate of a finding": func(b *Bundle) { b.Surface.Findings = append(b.Surface.Findings, b.Surface.Findings[0]) },
		"duplicate, other title": func(b *Bundle) {
			f := b.Surface.Findings[0]
			f.Title = "x"
			b.Surface.Findings = append(b.Surface.Findings, f)
		},
		"section removed whole":   func(b *Bundle) { b.Surface = nil },
		"findings emptied, title": func(b *Bundle) { b.Surface.Findings[0].Title = ""; b.Surface.Findings[0].Intervals = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := surfaceBundle(t)
			mutate(b)
			r := Verify(b)
			if r.OK() {
				t.Fatalf("a bundle with %s verified: %+v %+v", name, r.Surface, r.Checks)
			}
		})
	}
}

func injectedFinding(iv []SurfaceInterval) SurfaceFinding {
	return SurfaceFinding{
		AssetID: 7, AssetKind: "domain", AssetValue: "example.com", Check: "spf", FindingID: "spf.plus_all", Subject: "example.com",
		Severity: "critical", Title: "SPF allows everyone", Evidence: map[string]any{}, Intervals: iv,
	}
}

// Reordering what the bundle carries changes nothing it claims, so it must
// still verify: the digests sort their inputs, and so must the cross-check.
func TestVerifySurfaceReorderedBundleStillVerifies(t *testing.T) {
	b := surfaceBundle(t)
	s := b.Surface
	for i, j := 0, len(s.Scans)-1; i < j; i, j = i+1, j-1 {
		s.Scans[i], s.Scans[j] = s.Scans[j], s.Scans[i]
	}
	for k := range s.Scans {
		o := s.Scans[k].Observations
		for i, j := 0, len(o)-1; i < j; i, j = i+1, j-1 {
			o[i], o[j] = o[j], o[i]
		}
	}
	iv := s.Findings[0].Intervals
	iv[0], iv[1] = iv[1], iv[0]
	r := Verify(b)
	if !r.OK() {
		t.Fatalf("a reordered but intact bundle must verify: %+v", r.Checks)
	}
	if r.Surface.FindingsVerified != 1 || r.Surface.FindingsFailed != 0 {
		t.Fatalf("%+v", r.Surface)
	}
}

// The failure has to say what is wrong in words an auditor can act on.
func TestVerifySurfaceFailureNamesTheFinding(t *testing.T) {
	b := surfaceBundle(t)
	b.Surface.Findings[0].Title = "DMARC is fine"
	r := Verify(b)
	c := check(t, r, "surface findings")
	if c.OK || !strings.Contains(c.Detail, "dmarc.p_none") || !strings.Contains(c.Detail, "title") {
		t.Fatalf("the failure must name the finding and the field: %+v", c)
	}
}
