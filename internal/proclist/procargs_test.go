package proclist

import "testing"

func TestParseProcArgs2(t *testing.T) {
	raw := []byte{3, 0, 0, 0}
	raw = append(raw, "/bin/zsh\x00\x00\x00\x00-zsh\x00-c\x00echo hi\x00PATH=/usr/bin\x00"...)
	if got := parseProcArgs2(raw); got != "-zsh -c echo hi" {
		t.Errorf("got %q", got)
	}
	if got := parseProcArgs2([]byte{1, 0}); got != "" {
		t.Errorf("short: %q", got)
	}
}
