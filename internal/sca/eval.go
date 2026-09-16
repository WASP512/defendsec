package sca

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Dispatch across check types (roadmap 3.7).

// HostCheckTypes are the types evaluated on the host itself. inventory_field
// is absent because it is answered from the snapshot the server already holds,
// and re-collecting it on the agent would give two answers to one question.
var HostCheckTypes = []string{
	"file_regex", "file_mode", "mount_option", "sysctl",
	"package", "systemd_unit", "command",
}

// KnownCheckTypes is every type the engine understands.
func KnownCheckTypes() []string {
	out := append([]string{"inventory_field"}, HostCheckTypes...)
	sort.Strings(out)
	return out
}

// IsHostCheck reports whether a type runs on the host.
func IsHostCheck(checkType string) bool {
	for _, t := range HostCheckTypes {
		if t == checkType {
			return true
		}
	}
	return false
}

// Eval runs one host check.
//
// An unknown type returns a failing result rather than being skipped. Skipping
// would let a typo silently remove a check from a benchmark, and the pack
// would still report a clean run — the failure mode hardest to notice and
// worst to find during an audit.
func (h *Host) Eval(ctx context.Context, check Check) Result {
	switch check.Type {
	case "file_regex":
		return EvalFileRegex(check)
	case "file_mode":
		return h.EvalFileMode(check)
	case "mount_option":
		return h.EvalMountOption(check)
	case "sysctl":
		return h.EvalSysctl(check)
	case "package":
		return h.EvalPackage(ctx, check)
	case "systemd_unit":
		return h.EvalSystemdUnit(ctx, check)
	case "command":
		return h.EvalCommand(ctx, check)
	default:
		res := newResult(check)
		res.Detail = fmt.Sprintf("unknown check type %q; the engine understands %s",
			check.Type, strings.Join(KnownCheckTypes(), ", "))
		return res
	}
}

// EvalPack runs every host check in a pack.
func (h *Host) EvalPack(ctx context.Context, pack *Pack) []Result {
	var out []Result
	for _, check := range pack.Checks {
		if !IsHostCheck(check.Type) {
			continue
		}
		r := h.Eval(ctx, check)
		r.PackID = pack.ID
		out = append(out, r)
	}
	return out
}

// Coverage counts a pack's checks by type, so coverage can be published as a
// fraction with its denominator rather than as a claim of completeness
// (§3.7). A number with no denominator is the thing this exists to avoid.
type Coverage struct {
	PackID string         `json:"packId"`
	Total  int            `json:"total"`
	ByType map[string]int `json:"byType"`
}

// Describe summarises a pack.
func Describe(pack *Pack) Coverage {
	c := Coverage{PackID: pack.ID, ByType: map[string]int{}}
	for _, check := range pack.Checks {
		c.Total++
		c.ByType[check.Type]++
	}
	return c
}
