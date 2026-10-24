package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadFile(t *testing.T) {
	v, warn, err := ReadFile(write(t, "abc123DEF\n", 0o600))
	if err != nil || v != "abc123DEF" || warn != "" {
		t.Fatalf("got %q %q %v", v, warn, err)
	}
	// Readable by the group: usable, with a warning that names the file and not the value.
	p := write(t, "abc123DEF", 0o640)
	v, warn, err = ReadFile(p)
	if err != nil || v != "abc123DEF" || !strings.Contains(warn, "readable by group or others") || strings.Contains(warn, "abc123DEF") {
		t.Fatalf("got %q %q %v", v, warn, err)
	}
}

func TestReadFileRefusals(t *testing.T) {
	dir := t.TempDir()
	for name, p := range map[string]string{
		"empty path":     "",
		"missing":        filepath.Join(dir, "nope"),
		"directory":      dir,
		"empty":          write(t, "", 0o600),
		"two values":     write(t, "one two", 0o600),
		"two lines":      write(t, "one\ntwo\n", 0o600),
		"group writable": write(t, "secretvalue", 0o660),
		"world writable": write(t, "secretvalue", 0o602),
		"too large":      write(t, strings.Repeat("a", maxCredentialFile+1), 0o600),
	} {
		v, _, err := ReadFile(p)
		if err == nil || v != "" {
			t.Errorf("%s: accepted (%q)", name, v)
			continue
		}
		for _, leak := range []string{"secretvalue", "one two"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error echoes the value: %v", name, err)
			}
		}
	}
}
