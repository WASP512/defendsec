package main

import "strings"

// removeFlag drops a flag and its value from a Windows command line, which
// may quote the value. It works on the tokens the MSI and install-agent.ps1
// produce, not on arbitrary shell syntax.
func removeFlag(cmdline, flagName string) (string, bool) {
	toks := splitCommandLine(cmdline)
	var out []string
	changed := false
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		bare := strings.Trim(t, `"`)
		if bare == flagName || bare == "-"+flagName {
			changed = true
			i++ // skip its value
			continue
		}
		if strings.HasPrefix(bare, flagName+"=") || strings.HasPrefix(bare, "-"+flagName+"=") {
			changed = true
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, " "), changed
}

// splitCommandLine splits on spaces outside double quotes, keeping quotes.
func splitCommandLine(s string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

// stateDirFromArgs finds -state-dir in the agent's arguments, falling back
// to the platform default.
func stateDirFromArgs(args []string) string {
	for i, a := range args {
		a = strings.TrimLeft(a, "-")
		if a == "state-dir" && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "state-dir="); ok {
			return v
		}
	}
	return defaultStateDir()
}
