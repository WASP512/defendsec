package agentcmd

import "defendsec/internal/proclist"

func terminate(pid int32) error { return proclist.Terminate(pid) }
