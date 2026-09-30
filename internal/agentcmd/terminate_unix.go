//go:build !windows

package agentcmd

import "syscall"

func terminate(pid int32) error { return syscall.Kill(int(pid), syscall.SIGTERM) }
