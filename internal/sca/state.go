package sca

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Package presence and systemd unit state (roadmap 3.7).
//
// Both shell out, but neither lets the pack decide what runs: the check names
// a package or a unit, and the argument shape is fixed here. That is the
// difference between "check whether openssh-server is installed" and "run this
// string" — the first cannot be turned into the second by editing a data file.

// EvalPackage checks whether a package is installed.
func (h *Host) EvalPackage(ctx context.Context, check Check) Result {
	res := newResult(check)
	if check.Package == "" {
		res.Detail = "check is missing package"
		return res
	}
	// A package name is interpolated into a command, so it is constrained to
	// what a package name can actually contain. Belt and braces: there is no
	// shell here, so nothing in it could become syntax anyway.
	if strings.ContainsAny(check.Package, " \t\n;|&$`'\"\\") {
		res.Detail = fmt.Sprintf("package name %q contains unusable characters", check.Package)
		return res
	}
	want := true
	if check.Present != nil {
		want = *check.Present
	}

	installed, detail, err := h.packageInstalled(ctx, check.Package)
	if err != nil {
		res.Detail = err.Error()
		return res
	}

	res.Pass = installed == want
	switch {
	case installed && want:
		res.Detail = fmt.Sprintf("%s is installed (%s)", check.Package, detail)
	case installed && !want:
		res.Detail = fmt.Sprintf("%s is installed but should not be (%s)", check.Package, detail)
	case !installed && want:
		res.Detail = fmt.Sprintf("%s is not installed", check.Package)
	default:
		res.Detail = fmt.Sprintf("%s is not installed, as required", check.Package)
	}
	return res
}

// packageInstalled queries whichever package manager this host uses.
func (h *Host) packageInstalled(ctx context.Context, name string) (bool, string, error) {
	switch h.packageManager() {
	case "dpkg":
		// dpkg-query exits non-zero for an unknown package, which is the
		// answer rather than an error.
		out, code, err := h.runner().Run(ctx, []string{"dpkg-query", "-W", "-f=${Status} ${Version}", name})
		if err != nil {
			return false, "", fmt.Errorf("query dpkg for %s: %w", name, err)
		}
		if code != 0 {
			return false, "", nil
		}
		// "install ok installed" is the only status that means present. A
		// package can be removed but not purged, which still has a version
		// and would otherwise read as installed.
		if !strings.HasPrefix(out, "install ok installed") {
			return false, strings.TrimSpace(out), nil
		}
		return true, strings.TrimSpace(strings.TrimPrefix(out, "install ok installed")), nil

	case "rpm":
		out, code, err := h.runner().Run(ctx, []string{"rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name})
		if err != nil {
			return false, "", fmt.Errorf("query rpm for %s: %w", name, err)
		}
		if code != 0 {
			return false, "", nil
		}
		return true, strings.TrimSpace(out), nil

	default:
		return false, "", fmt.Errorf("no supported package manager found on this host")
	}
}

// packageManager picks dpkg or rpm from what is on disk, rather than trying
// each in turn and reading a failure as an answer.
func (h *Host) packageManager() string {
	if _, err := os.Stat(h.resolve("/var/lib/dpkg/status")); err == nil {
		return "dpkg"
	}
	if _, err := os.Stat(h.resolve("/var/lib/rpm")); err == nil {
		return "rpm"
	}
	return ""
}

// EvalSystemdUnit checks whether a unit is enabled and/or running.
func (h *Host) EvalSystemdUnit(ctx context.Context, check Check) Result {
	res := newResult(check)
	if check.Unit == "" {
		res.Detail = "check is missing unit"
		return res
	}
	if strings.ContainsAny(check.Unit, " \t\n;|&$`'\"\\/") {
		res.Detail = fmt.Sprintf("unit name %q contains unusable characters", check.Unit)
		return res
	}
	if check.Enabled == nil && check.Active == nil {
		res.Detail = "check specifies neither enabled nor active"
		return res
	}

	var problems, facts []string

	if check.Enabled != nil {
		out, _, err := h.runner().Run(ctx, []string{"systemctl", "is-enabled", "--", check.Unit})
		if err != nil {
			res.Detail = fmt.Sprintf("query %s: %v", check.Unit, err)
			return res
		}
		state := firstLine(out)
		// "enabled-runtime" and "static" both mean the unit will come up, so
		// treating only "enabled" as enabled would report a false finding on
		// a correctly-configured host.
		isEnabled := state == "enabled" || state == "enabled-runtime" ||
			state == "static" || state == "indirect" || state == "alias"
		facts = append(facts, "is-enabled="+state)
		if isEnabled != *check.Enabled {
			problems = append(problems, fmt.Sprintf("enabled is %v, want %v", isEnabled, *check.Enabled))
		}
	}

	if check.Active != nil {
		out, _, err := h.runner().Run(ctx, []string{"systemctl", "is-active", "--", check.Unit})
		if err != nil {
			res.Detail = fmt.Sprintf("query %s: %v", check.Unit, err)
			return res
		}
		state := firstLine(out)
		isActive := state == "active"
		facts = append(facts, "is-active="+state)
		if isActive != *check.Active {
			problems = append(problems, fmt.Sprintf("active is %v, want %v", isActive, *check.Active))
		}
	}

	res.Detail = fmt.Sprintf("%s: %s", check.Unit, strings.Join(facts, ", "))
	if len(problems) > 0 {
		res.Detail += " — " + strings.Join(problems, "; ")
		return res
	}
	res.Pass = true
	return res
}
