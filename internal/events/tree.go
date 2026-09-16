package events

import (
	"sync"
	"time"
)

// Process-tree context (roadmap 3.5).
//
// When an alert fires, the single thing an analyst needs first is what ran,
// what ran it, and what ran that. State-based tools cannot provide it at all:
// by the time a file-integrity check notices a change, the process that made
// it has usually exited.
//
// So lineage is recorded as processes are observed, and kept for a while after
// they exit. Keeping the dead ones is the whole point — the parent of a
// suspicious process has very often already gone, and a lineage that stops at
// "pid 4242, no longer exists" is the lineage that matters least.

// treeEntry is one remembered process.
type treeEntry struct {
	pid         int32
	ppid        int32
	image       string
	commandLine string
	user        string
	seen        time.Time
	// exited is when the process was noticed gone, zero while it is alive.
	exited time.Time
}

// Tree remembers process lineage, including recently-exited processes.
type Tree struct {
	mu    sync.RWMutex
	byPID map[int32]*treeEntry
	// retain is how long an exited process is kept. Long enough that the
	// parent of a short-lived process is still there when its child alerts.
	retain time.Duration
	// maxEntries bounds memory on a host that forks heavily.
	maxEntries int
}

// DefaultTreeRetention keeps exited processes for long enough to explain a
// child that outlived them.
const DefaultTreeRetention = 10 * time.Minute

// DefaultTreeSize bounds the table. A build host can fork tens of thousands of
// processes a minute, and an unbounded table would be a slow memory leak on
// exactly the machines least able to tolerate one.
const DefaultTreeSize = 20000

// NewTree creates a process tree.
func NewTree(retain time.Duration, maxEntries int) *Tree {
	if retain <= 0 {
		retain = DefaultTreeRetention
	}
	if maxEntries <= 0 {
		maxEntries = DefaultTreeSize
	}
	return &Tree{byPID: map[int32]*treeEntry{}, retain: retain, maxEntries: maxEntries}
}

// Observe records a process.
func (t *Tree) Observe(pid, ppid int32, image, commandLine, user string, at time.Time) {
	if pid <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// A pid can be reused after the original exits. Replacing the entry
	// outright is right: the new process genuinely is a different one, and
	// keeping the old lineage would attribute a child to a parent it never
	// had.
	t.byPID[pid] = &treeEntry{
		pid: pid, ppid: ppid, image: image,
		commandLine: commandLine, user: user, seen: at,
	}
	t.evictLocked(at)
}

// MarkExited notes that a process is gone, keeping it for the retention window.
func (t *Tree) MarkExited(pid int32, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.byPID[pid]; ok && entry.exited.IsZero() {
		entry.exited = at
	}
}

// evictLocked removes entries past retention, and trims oldest-first if the
// table is still over its bound. Caller holds the lock.
func (t *Tree) evictLocked(now time.Time) {
	for pid, entry := range t.byPID {
		if !entry.exited.IsZero() && now.Sub(entry.exited) > t.retain {
			delete(t.byPID, pid)
		}
	}
	if len(t.byPID) <= t.maxEntries {
		return
	}
	// Over the bound even after expiry. Drop the least recently seen, since
	// an old entry is the one least likely to explain a live alert.
	var oldestPID int32
	var oldest time.Time
	for len(t.byPID) > t.maxEntries {
		oldestPID, oldest = 0, time.Time{}
		for pid, entry := range t.byPID {
			if oldest.IsZero() || entry.seen.Before(oldest) {
				oldestPID, oldest = pid, entry.seen
			}
		}
		if oldestPID == 0 {
			return
		}
		delete(t.byPID, oldestPID)
	}
}

// maxAncestry bounds how far a lineage is walked. A cycle cannot happen in a
// real process table, but a pid-reuse race can produce one in a remembered
// snapshot, and an unbounded walk would hang the alerting path.
const maxAncestry = 24

// Ancestry returns a process and its parents, nearest first.
func (t *Tree) Ancestry(pid int32) []Ancestor {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []Ancestor
	seen := map[int32]bool{}
	for current := pid; current > 0 && len(out) < maxAncestry; {
		if seen[current] {
			break
		}
		seen[current] = true
		entry, ok := t.byPID[current]
		if !ok {
			// The lineage is recorded as far as it is known. Stopping here is
			// honest; inventing a placeholder would suggest the chain ended
			// when it was simply not observed.
			break
		}
		out = append(out, Ancestor{
			PID: entry.pid, Image: entry.image,
			CommandLine: entry.commandLine, User: entry.user,
		})
		if entry.ppid == current {
			// pid 1's parent is itself on some systems.
			break
		}
		current = entry.ppid
	}
	return out
}

// Len is how many processes are remembered.
func (t *Tree) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byPID)
}

// Sweep expires entries, for a caller that wants to do it on a timer rather
// than only when a process is observed.
func (t *Tree) Sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.evictLocked(now)
}
