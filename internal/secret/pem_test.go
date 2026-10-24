package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPEMFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pem := "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n"

	got, warn, err := ReadPEMFile(write("ok.pem", pem, 0o600))
	if err != nil || warn != "" || string(got) != pem {
		t.Fatalf("0600 PEM: err=%v warn=%q", err, warn)
	}
	if _, warn, err = ReadPEMFile(write("grp.pem", pem, 0o640)); err != nil || !strings.Contains(warn, "0600") {
		t.Fatalf("group-readable PEM: err=%v warn=%q, want a warning only", err, warn)
	}
	if _, _, err = ReadPEMFile(write("w.pem", pem, 0o660)); err == nil {
		t.Error("a group-writable file was accepted")
	}
	if _, _, err = ReadPEMFile(write("notpem.txt", "just-a-secret-value\n", 0o600)); err == nil {
		t.Error("a file with no BEGIN line was accepted")
	} else if strings.Contains(err.Error(), "just-a-secret-value") {
		t.Errorf("the error repeats the content: %v", err)
	}
	if _, _, err = ReadPEMFile(write("empty.pem", "", 0o600)); err == nil {
		t.Error("an empty file was accepted")
	}
	if _, _, err = ReadPEMFile(write("big.pem", pem+strings.Repeat("A", maxPEMFile), 0o600)); err == nil {
		t.Error("an oversized file was accepted")
	}
	if _, _, err = ReadPEMFile(dir); err == nil {
		t.Error("a directory was accepted")
	}
	if _, _, err = ReadPEMFile(""); err == nil {
		t.Error("no path was accepted")
	}
	if _, _, err = ReadPEMFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("a missing file was accepted")
	}
}
