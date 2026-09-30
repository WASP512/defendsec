package agentcmd

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func fakeNet(t *testing.T, apply func(string) error) {
	t.Helper()
	applyNet, clearNet = apply, func(string) error { return nil }
	t.Cleanup(func() { applyNet, clearNet = applyNetIsolate, clearNetIsolate })
}

// A re-apply that fails at start must be tried again at the next start.
// Recording only the failure made the next start skip the host, so after its
// next reboot it came up fully networked while the console showed it
// isolated.
func TestFailedReapplyIsRetriedAtNextStart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("re-apply at start is Linux only")
	}
	dir := t.TempDir()
	calls, fail := 0, true
	fakeNet(t, func(string) error {
		calls++
		if fail {
			return errors.New("resolve control plane: i/o timeout")
		}
		return nil
	})
	if err := SaveState(dir, State{Isolated: true, Mode: "net"}); err != nil {
		t.Fatal(err)
	}

	st, reapplied, err := ReapplyIsolation(dir)
	if err != nil || !reapplied {
		t.Fatalf("first start: reapplied=%v err=%v", reapplied, err)
	}
	if st.Mode != "flag" || !strings.Contains(st.Message, "not in effect") {
		t.Errorf("a failed re-apply must say isolation is not in effect: %+v", st)
	}
	if saved := LoadState(dir); !saved.Isolated || !saved.NetRequested {
		t.Fatalf("the request must survive the failure: %+v", saved)
	}

	fail = false
	st, reapplied, err = ReapplyIsolation(dir)
	if err != nil || !reapplied || st.Mode != "net" {
		t.Fatalf("next start must retry and succeed: %+v reapplied=%v err=%v", st, reapplied, err)
	}
	if calls != 2 {
		t.Errorf("apply called %d times, want 2", calls)
	}

	// Release ends the request and forgets the addresses isolation used.
	if err := os.WriteFile(resolvedPath(dir), []byte(`{"ds.example":["10.0.0.5"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := Release(dir); err != nil || st.Isolated || st.NetRequested {
		t.Fatalf("release: %+v %v", st, err)
	}
	if _, err := os.Stat(resolvedPath(dir)); !os.IsNotExist(err) {
		t.Errorf("remembered addresses left after release: %v", err)
	}
	if _, reapplied, _ := ReapplyIsolation(dir); reapplied {
		t.Error("a released host was re-isolated at start")
	}
}

// A host only marked isolated (no network drop was asked for) is left alone.
func TestFlagOnlyIsolationIsNotReapplied(t *testing.T) {
	dir := t.TempDir()
	fakeNet(t, func(string) error { t.Fatal("applied network isolation nobody asked for"); return nil })
	if err := SaveState(dir, State{Isolated: true, Mode: "flag"}); err != nil {
		t.Fatal(err)
	}
	if _, reapplied, err := ReapplyIsolation(dir); reapplied || err != nil {
		t.Errorf("reapplied=%v err=%v", reapplied, err)
	}
}
