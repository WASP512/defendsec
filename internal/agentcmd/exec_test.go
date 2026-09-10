package agentcmd

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestIsolateStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Isolate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Isolated {
		t.Fatal("expected isolated")
	}
	got := LoadState(dir)
	if !got.Isolated {
		t.Fatal("state not persisted")
	}
	st, err = Release(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Isolated {
		t.Fatal("expected released")
	}
}

func TestKillRejectsBadAndProtectedNames(t *testing.T) {
	if _, err := KillByName("../etc"); err == nil {
		t.Fatal("expected reject")
	}
	if _, err := KillByName("keel-agentd"); err == nil {
		t.Fatal("expected protected")
	}
	if _, err := ParseKillPayload([]byte(`{}`)); err == nil {
		t.Fatal("expected missing name")
	}
}

func TestKillByNameSignalsSleep(t *testing.T) {
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not on PATH")
	}
	dst := filepath.Join(t.TempDir(), "keeltestsleep")
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	cmd := exec.Command(dst, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(80 * time.Millisecond)
	n, err := KillByName("keeltestsleep")
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("signaled %d", n)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("process did not exit")
	case <-done:
	}
}
