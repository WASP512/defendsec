//go:build !windows

package main

// runAsPlatformService is Windows-only; systemd and launchd run the agent as
// an ordinary process and stop it with SIGTERM.
func runAsPlatformService() bool { return false }

func defaultStateDir() string { return "data/agent-mtls" }
