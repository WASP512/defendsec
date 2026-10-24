package posture

import "testing"

// The edition is the EditionID registry value: it is what tells Windows Server
// 2016 from Windows 10 LTSB 2016, which share build 14393.
func TestParseWindowsReportsEdition(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{`{"os":{"caption":"Microsoft Windows Server 2016 Standard","version":"10.0.14393","build":"14393","productType":3},"edition":"ServerStandard"}`, "ServerStandard"},
		{`{"os":{"caption":"Microsoft Windows 10 Enterprise 2016 LTSB","version":"10.0.14393","build":"14393","productType":1},"edition":" EnterpriseS \n"}`, "EnterpriseS"},
		// the registry read failed: no edition, and the rest still parses
		{`{"os":{"caption":"Microsoft Windows 10 Pro","version":"10.0.19045","build":"19045","productType":1}}`, ""},
	} {
		_, facts, err := ParseWindows([]byte(tc.doc))
		if err != nil {
			t.Fatal(err)
		}
		if facts.OSEdition != tc.want {
			t.Errorf("edition = %q, want %q for %s", facts.OSEdition, tc.want, tc.doc)
		}
		if facts.OSVersion == "" || facts.OSName == "" {
			t.Errorf("facts = %+v", facts)
		}
	}
}

func TestWindowsScriptAsksForTheEdition(t *testing.T) {
	for _, want := range []string{"EditionID", "ProductType"} {
		if !contains(WindowsScript, want) {
			t.Errorf("the collection script does not read %s", want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
