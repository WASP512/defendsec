package main

import "testing"

func TestRemoveFlag(t *testing.T) {
	in := `"C:\Program Files\DefendSec\defendsec-agentd.exe" -server-http "https://s:47262" -enroll-secret "abc def" -tls-server-name "s"`
	got, changed := removeFlag(in, "-enroll-secret")
	want := `"C:\Program Files\DefendSec\defendsec-agentd.exe" -server-http "https://s:47262" -tls-server-name "s"`
	if !changed || got != want {
		t.Errorf("got %q", got)
	}
	if _, changed := removeFlag(want, "-enroll-secret"); changed {
		t.Error("nothing to remove")
	}
	got, _ = removeFlag(`x.exe --enroll-secret=abc -v`, "-enroll-secret")
	if got != `x.exe -v` {
		t.Errorf("= form: %q", got)
	}
}

func TestStateDirFromArgs(t *testing.T) {
	if got := stateDirFromArgs([]string{"-server-http", "x", "-state-dir", `D:\agent`}); got != `D:\agent` {
		t.Error(got)
	}
	if got := stateDirFromArgs([]string{"--state-dir=/x"}); got != "/x" {
		t.Error(got)
	}
}
