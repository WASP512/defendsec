package control

import (
	"log/slog"
	"path/filepath"
	"testing"

	"defendsec/internal/presence"
	"defendsec/internal/sca"
)

// An alert raised by a check that was later scoped to other distros must be
// resolved once the agent stops running it on this host, or it stays open
// forever: the Debian audit package name failed on every RPM host before
// the check was scoped.
func TestOutOfScopeScaAlertIsResolved(t *testing.T) {
	const pack = "sca-linux-cis-v8-ig1"
	const debianOnly = pack + "/cis-8.2-auditd-installed"
	dev := presence.Device{ID: "dev-1", Hostname: "fedora-1", Platform: "linux"}

	open := func(s *Server) int {
		return len(s.store.ListAlerts("open", "sca", dev.ID, 0))
	}
	raise := func() *Server {
		s := &Server{
			store: presence.New(filepath.Join(t.TempDir(), "state.json")),
			log:   slog.New(slog.DiscardHandler),
		}
		s.processScaAlerts(dev, []sca.Result{{
			PackID: pack, CheckID: "cis-8.2-auditd-installed", Title: "The audit daemon is installed",
			Severity: "medium", Pass: false, Detail: "package auditd not installed",
		}})
		if open(s) != 1 {
			t.Fatalf("setup: want 1 open alert, got %d", open(s))
		}
		return s
	}
	rpmReport := []presence.ScaResult{
		{PackID: pack, CheckID: "cis-8.2-audit-installed-rpm", Pass: true},
		{PackID: pack, CheckID: "cis-4.1-aslr-enabled", Pass: true},
	}

	s := raise()
	s.resolveOutOfScopeSca(dev, rpmReport)
	if n := open(s); n != 0 {
		t.Errorf("the pack ran without the Debian-only check: want it resolved, %d still open", n)
	}

	// A report with no SCA results says nothing about which checks ran.
	s = raise()
	s.resolveOutOfScopeSca(dev, nil)
	if n := open(s); n != 1 {
		t.Errorf("no SCA results in the report: want the alert kept, %d open", n)
	}

	// Results from a different pack are not evidence about this one.
	s = raise()
	s.resolveOutOfScopeSca(dev, []presence.ScaResult{{PackID: "some-other-pack", CheckID: "x", Pass: true}})
	if n := open(s); n != 1 {
		t.Errorf("only another pack ran: want the alert kept, %d open", n)
	}

	// An agent still running the check (older packs) keeps reporting it; its
	// result decides, not this function.
	s = raise()
	s.resolveOutOfScopeSca(dev, append(rpmReport, presence.ScaResult{PackID: pack, CheckID: "cis-8.2-auditd-installed", Pass: false}))
	if n := open(s); n != 1 {
		t.Errorf("the check still ran: want the alert kept, %d open", n)
	}
}
