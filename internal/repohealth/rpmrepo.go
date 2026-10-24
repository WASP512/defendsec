package repohealth

import (
	"regexp"
	"strings"
)

// RPMRepo is one repository section of a yum/dnf/zypper .repo file.
type RPMRepo struct {
	ID      string
	Name    string
	File    string
	Enabled bool
	// GPGCheck is the repository's own gpgcheck= (packages); RepoGPGCheck is
	// repo_gpgcheck= (metadata). nil means the file does not say.
	GPGCheck     *bool
	RepoGPGCheck *bool
	// GPGKeys are the gpgkey= locations, variables substituted.
	GPGKeys []string
	// Address is the first of baseurl, metalink, mirrorlist, for the label.
	Address string
}

// ParseRepoFile reads a .repo file. vars substitutes $releasever, $basearch
// (and the ${...} forms) in gpgkey and address values. A section with
// enabled=0 is returned with Enabled false so the caller can skip it; zypper
// repo files default to enabled=1 as dnf does.
func ParseRepoFile(file, text string, vars map[string]string) []RPMRepo {
	var out []RPMRepo
	var cur *RPMRepo
	lastKey := ""
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
		}
		cur, lastKey = nil, ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			flush()
			id := strings.TrimSpace(trim[1 : len(trim)-1])
			if id == "main" {
				continue
			}
			cur = &RPMRepo{ID: id, File: file, Enabled: true}
			continue
		}
		if cur == nil {
			continue
		}
		// A value may continue on following indented lines (gpgkey and baseurl
		// lists do).
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			cur.add(lastKey, trim, vars)
			continue
		}
		k, v, ok := strings.Cut(trim, "=")
		if !ok {
			continue
		}
		lastKey = strings.ToLower(strings.TrimSpace(k))
		cur.add(lastKey, strings.TrimSpace(v), vars)
	}
	flush()
	return out
}

func (r *RPMRepo) add(key, val string, vars map[string]string) {
	val = substitute(val, vars)
	switch key {
	case "name":
		r.Name = val
	case "enabled":
		r.Enabled = val != "0" && !strings.EqualFold(val, "false") && !strings.EqualFold(val, "no")
	case "gpgcheck":
		b := truthy(val)
		r.GPGCheck = &b
	case "repo_gpgcheck":
		b := truthy(val)
		r.RepoGPGCheck = &b
	case "gpgkey":
		for _, f := range strings.FieldsFunc(val, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
			if f != "" {
				r.GPGKeys = append(r.GPGKeys, f)
			}
		}
	case "baseurl", "metalink", "mirrorlist":
		if r.Address == "" {
			r.Address = strings.Fields(val + " ")[0]
		}
	}
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

var variableRef = regexp.MustCompile(`\$\{?([A-Za-z_]+)\}?`)

func substitute(s string, vars map[string]string) string {
	return variableRef.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.Trim(m, "${}")
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}

// MainGPGCheck reads gpgcheck= from the [main] section of dnf.conf or
// yum.conf, the default every repository without its own setting takes.
func MainGPGCheck(text string) *bool {
	in := false
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "["):
			in = strings.EqualFold(t, "[main]")
		case in:
			if k, v, ok := strings.Cut(t, "="); ok && strings.EqualFold(strings.TrimSpace(k), "gpgcheck") {
				b := truthy(v)
				return &b
			}
		}
	}
	return nil
}

// LocalKeyPath turns a gpgkey= location into a path the agent can read, or ""
// for a location it cannot (an https address: nothing is fetched).
func LocalKeyPath(loc string) string {
	if p, ok := strings.CutPrefix(loc, "file://"); ok {
		return p
	}
	if strings.HasPrefix(loc, "/") {
		return loc
	}
	return ""
}
