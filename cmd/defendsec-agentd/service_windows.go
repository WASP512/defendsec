package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// ServiceName is what the MSI and install-agent.ps1 register.
const ServiceName = "DefendSecAgent"

// defaultStateDir is under ProgramData, which the installer restricts to
// SYSTEM and Administrators, as /var/lib/defendsec-agent is restricted to
// root on Linux.
func defaultStateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "DefendSec", "agent")
}

// runAsPlatformService runs the agent under the service control manager when
// started by it. Returns false when started from a console, so the agent can
// still be run by hand for diagnosis.
func runAsPlatformService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	logw := serviceLog()
	log := slog.New(slog.NewTextHandler(logw, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := svc.Run(ServiceName, &agentService{log: log}); err != nil {
		if el, e := eventlog.Open(ServiceName); e == nil {
			_ = el.Error(1, "service failed: "+err.Error())
			el.Close()
		}
		os.Exit(1)
	}
	return true
}

// serviceLog is a file in the state directory, rotated once at start when it
// has grown past 10 MiB. A service has no console, and the Event Log is a
// poor place for routine text; start/stop and fatal errors go there too.
func serviceLog() io.Writer {
	dir := defaultStateDir()
	_ = os.MkdirAll(dir, 0o700)
	path := filepath.Join(dir, "agent.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}

type agentService struct{ log *slog.Logger }

// Execute implements svc.Handler.
func (s *agentService) Execute(args []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The SCM passes the service name as args[0] and start parameters after
	// it; the configured command line arrives through os.Args.
	done := make(chan error, 1)
	go func() { done <- run(ctx, s.log, os.Args[1:]) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	if el, e := eventlog.Open(ServiceName); e == nil {
		_ = el.Info(1, "DefendSec agent started")
		el.Close()
	}
	for {
		select {
		case err := <-done:
			if err != nil {
				s.log.Error("agent stopped", "err", err)
				if el, e := eventlog.Open(ServiceName); e == nil {
					_ = el.Error(1, "DefendSec agent stopped: "+err.Error())
					el.Close()
				}
				// A non-zero exit code makes the SCM apply the recovery
				// actions the installer configures (restart after 10s).
				return true, 1
			}
			return false, 0
		case c := <-reqs:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		}
	}
}
