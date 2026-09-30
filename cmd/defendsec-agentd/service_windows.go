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
	"golang.org/x/sys/windows/svc/mgr"
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

	configureService(s.log)

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

// configureService sets restart-on-failure and, once the agent holds a client
// certificate, removes the enroll secret from the service's command line.
// Both are done by the agent because the MSI is built without custom
// actions, and doing them here also covers a service created by
// install-agent.ps1.
func configureService(log *slog.Logger) {
	m, err := mgr.Connect()
	if err != nil {
		log.Warn("service manager", "err", err)
		return
	}
	defer m.Disconnect()
	svcH, err := m.OpenService(ServiceName)
	if err != nil {
		log.Warn("open service", "err", err)
		return
	}
	defer svcH.Close()

	if err := svcH.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400); err != nil {
		log.Warn("set recovery actions", "err", err)
	}
	go scrubEnrollSecret(log, svcH.Name)
}

// scrubEnrollSecret waits for enrollment, then rewrites the service command
// line without -enroll-secret. The secret is single-purpose; after the agent
// has a certificate it is only a liability sitting in the registry.
func scrubEnrollSecret(log *slog.Logger, name string) {
	cert := filepath.Join(stateDirFromArgs(os.Args[1:]), "client.pem")
	for i := 0; i < 120; i++ {
		if _, err := os.Stat(cert); err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if _, err := os.Stat(cert); err != nil {
		return
	}
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	svcH, err := m.OpenService(name)
	if err != nil {
		return
	}
	defer svcH.Close()
	cfg, err := svcH.Config()
	if err != nil {
		return
	}
	cleaned, changed := removeFlag(cfg.BinaryPathName, "-enroll-secret")
	if !changed {
		return
	}
	cfg.BinaryPathName = cleaned
	if err := svcH.UpdateConfig(cfg); err != nil {
		log.Warn("remove enroll secret from service configuration", "err", err)
		return
	}
	log.Info("enroll secret removed from the service configuration")
}
