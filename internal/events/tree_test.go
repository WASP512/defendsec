package events

import (
	"testing"
	"time"
)

var base = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func TestAncestryWalksTheChain(t *testing.T) {
	tr := NewTree(0, 0)
	tr.Observe(1, 1, "/sbin/init", "init", "root", base)
	tr.Observe(100, 1, "/usr/sbin/sshd", "sshd -D", "root", base)
	tr.Observe(200, 100, "/bin/bash", "-bash", "deploy", base)
	tr.Observe(300, 200, "/usr/bin/curl", "curl https://x", "deploy", base)

	chain := tr.Ancestry(300)
	if len(chain) != 4 {
		t.Fatalf("chain = %d entries, want 4: %+v", len(chain), chain)
	}
	want := []string{"/usr/bin/curl", "/bin/bash", "/usr/sbin/sshd", "/sbin/init"}
	for i, image := range want {
		if chain[i].Image != image {
			t.Errorf("chain[%d] = %q, want %q", i, chain[i].Image, image)
		}
	}
	if chain[0].User != "deploy" || chain[0].CommandLine != "curl https://x" {
		t.Errorf("the nearest ancestor lost its detail: %+v", chain[0])
	}
}

// The parent of a suspicious process has very often already exited, and a
// lineage that stops there is the one that matters least.
func TestExitedParentsRemainInTheLineage(t *testing.T) {
	tr := NewTree(time.Hour, 0)
	tr.Observe(100, 1, "/tmp/dropper", "./dropper", "root", base)
	tr.Observe(200, 100, "/bin/sh", "sh -c curl ...", "root", base)
	tr.MarkExited(100, base.Add(time.Second))

	chain := tr.Ancestry(200)
	if len(chain) != 2 {
		t.Fatalf("chain = %+v", chain)
	}
	if chain[1].Image != "/tmp/dropper" {
		t.Errorf("the exited parent was lost: %+v", chain)
	}
}

func TestExitedProcessesExpire(t *testing.T) {
	tr := NewTree(time.Minute, 0)
	tr.Observe(100, 1, "/tmp/x", "x", "root", base)
	tr.MarkExited(100, base)

	// Observing anything triggers eviction, which is when expiry happens.
	tr.Observe(101, 1, "/bin/true", "true", "root", base.Add(2*time.Minute))
	if len(tr.Ancestry(100)) != 0 {
		t.Error("an expired process is still remembered")
	}

	// A live process is never expired on age.
	tr.Observe(200, 1, "/usr/sbin/sshd", "sshd", "root", base)
	tr.Observe(201, 1, "/bin/true", "true", "root", base.Add(time.Hour))
	if len(tr.Ancestry(200)) == 0 {
		t.Error("a live process was expired")
	}
}

// A pid can be reused. Keeping the old lineage would attribute a child to a
// parent it never had.
func TestPIDReuseReplacesTheEntry(t *testing.T) {
	tr := NewTree(time.Hour, 0)
	tr.Observe(100, 1, "/tmp/old", "old", "root", base)
	tr.MarkExited(100, base)
	tr.Observe(100, 50, "/usr/bin/new", "new", "deploy", base.Add(time.Second))

	chain := tr.Ancestry(100)
	if len(chain) == 0 || chain[0].Image != "/usr/bin/new" {
		t.Fatalf("pid reuse kept the old process: %+v", chain)
	}
	if chain[0].User != "deploy" {
		t.Errorf("reused pid kept the old user: %+v", chain[0])
	}
}

// A build host forks tens of thousands of processes a minute; an unbounded
// table is a slow leak on the machines least able to tolerate one.
func TestTableIsBounded(t *testing.T) {
	tr := NewTree(time.Hour, 100)
	for i := int32(1); i <= 1000; i++ {
		tr.Observe(i, 1, "/bin/true", "true", "root", base.Add(time.Duration(i)*time.Second))
	}
	if got := tr.Len(); got > 100 {
		t.Fatalf("table holds %d entries, want at most 100", got)
	}
	// The most recent survive, since an old entry is least likely to explain
	// a live alert.
	if len(tr.Ancestry(1000)) == 0 {
		t.Error("the most recent process was evicted")
	}
}

// A pid-reuse race can produce a cycle in a remembered snapshot even though a
// real process table cannot have one. An unbounded walk would hang alerting.
func TestAncestryTerminatesOnCycles(t *testing.T) {
	tr := NewTree(time.Hour, 0)
	tr.Observe(100, 200, "/a", "a", "root", base)
	tr.Observe(200, 100, "/b", "b", "root", base)

	done := make(chan int, 1)
	go func() { done <- len(tr.Ancestry(100)) }()
	select {
	case n := <-done:
		if n != 2 {
			t.Errorf("cycle produced %d entries", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ancestry did not terminate on a cycle")
	}

	// Self-parenting, as pid 1 has on some systems.
	tr.Observe(1, 1, "/sbin/init", "init", "root", base)
	if n := len(tr.Ancestry(1)); n != 1 {
		t.Errorf("self-parented process produced %d entries", n)
	}
}

// Stopping at the last known process is honest; a placeholder would suggest
// the chain ended when it was simply not observed.
func TestUnknownProcessYieldsNothing(t *testing.T) {
	tr := NewTree(0, 0)
	if got := tr.Ancestry(4242); len(got) != 0 {
		t.Errorf("an unobserved pid produced %+v", got)
	}
	tr.Observe(200, 999, "/bin/sh", "sh", "root", base)
	chain := tr.Ancestry(200)
	if len(chain) != 1 {
		t.Errorf("chain = %+v, want to stop at the last known process", chain)
	}
}

func TestInvalidPIDsAreIgnored(t *testing.T) {
	tr := NewTree(0, 0)
	tr.Observe(0, 1, "/x", "x", "root", base)
	tr.Observe(-1, 1, "/x", "x", "root", base)
	if tr.Len() != 0 {
		t.Error("an invalid pid was recorded")
	}
}
