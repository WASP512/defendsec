//go:build !windows

package agentcmd

func runWindowsLiveQuery(string) (string, bool, error) { return "", false, nil }
