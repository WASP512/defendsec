package agentcmd

import "testing"

func TestProtectedNamesIgnoreCaseAndExe(t *testing.T) {
	for _, n := range []string{"LSASS.EXE", "lsass", "csrss.exe", "defendsec-agentd.exe"} {
		if _, err := KillByName(n); err == nil || !contains(err.Error(), "protected") {
			t.Errorf("%s: want protected refusal, got %v", n, err)
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
