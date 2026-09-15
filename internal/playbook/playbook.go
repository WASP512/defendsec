// Package playbook defines named, versioned sequences of bounded commands
// (roadmap 2.5) and the conditions under which they may run unattended
// (roadmap 2.6).
//
// A playbook is not a new authority. Every step is signed individually and
// policy-checked individually, at the moment it runs, against the host it
// targets. A playbook that could execute three commands on one policy decision
// would be a way to smuggle past the engine, which is the opposite of the
// point.
//
// This also turns run_script and quarantine_path — primitives the white paper
// notes have no UI at all — into something an operator can see, name and
// review before an incident rather than assemble during one.
package playbook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Step is one command in a sequence.
type Step struct {
	ID      string `yaml:"id"`
	Command string `yaml:"command"`
	// Payload is the command's arguments. Values may reference the triggering
	// alert through the substitutions in bind.go.
	Payload map[string]any `yaml:"payload"`
	// Description says what this step is for, in the words an operator will
	// read while deciding whether to approve it.
	Description string `yaml:"description"`
	// ContinueOnFailure lets a sequence proceed when this step does not
	// complete. Off by default: a playbook whose first step failed is usually
	// operating on assumptions that no longer hold.
	ContinueOnFailure bool `yaml:"continue_on_failure"`
}

// Trigger describes which findings a playbook responds to (roadmap 2.6).
type Trigger struct {
	// AlertKinds are the finding kinds that match: fim, sca, vuln.
	AlertKinds []string `yaml:"alert_kinds"`
	// Severities narrows to particular severities. Empty means any.
	Severities []string `yaml:"severities"`
	// PathPrefix matches FIM findings under a directory.
	PathPrefix string `yaml:"path_prefix"`
	// HostClasses restricts the trigger to particular hosts.
	HostClasses []string `yaml:"host_classes"`
}

// Playbook is a named sequence.
type Playbook struct {
	Version int    `yaml:"version"`
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	// Description is shown before a run. A playbook nobody can explain is one
	// nobody should approve.
	Description string `yaml:"description"`
	Steps       []Step `yaml:"steps"`

	// Trigger, when set, allows this playbook to be matched against incoming
	// findings. Matching does not mean running: see Automatic.
	Trigger *Trigger `yaml:"trigger"`

	// Automatic allows the playbook to run without a human pressing anything
	// (roadmap 2.6). It is off by default and is only half the gate — policy
	// still decides every step, so an automatic playbook whose steps policy
	// refuses does nothing at all.
	Automatic bool `yaml:"automatic"`

	// Hash identifies this document, recorded on every run so the ledger says
	// which version of the playbook executed rather than which version is on
	// disk today.
	Hash   string `yaml:"-"`
	Source string `yaml:"-"`
}

// knownCommands is the set a step may name. Restricting it here means a typo
// fails at load rather than producing a step that is denied at run time, in
// the middle of an incident, for a reason that reads like a policy problem.
var knownCommands = map[string]bool{
	"isolate": true, "release": true, "kill_process": true,
	"live_query": true, "agent_update": true,
	"run_script": true, "quarantine_path": true,
}

// Parse validates a playbook document.
func Parse(raw []byte) (*Playbook, error) {
	var p Playbook
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse playbook: %w", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("playbook version %d is not supported, want 1", p.Version)
	}
	if strings.TrimSpace(p.ID) == "" {
		return nil, fmt.Errorf("playbook needs an id")
	}
	if strings.TrimSpace(p.Name) == "" {
		return nil, fmt.Errorf("playbook %q needs a name", p.ID)
	}
	if len(p.Steps) == 0 {
		return nil, fmt.Errorf("playbook %q has no steps", p.ID)
	}

	seen := map[string]bool{}
	for i := range p.Steps {
		s := &p.Steps[i]
		if strings.TrimSpace(s.ID) == "" {
			return nil, fmt.Errorf("playbook %q: step %d has no id", p.ID, i+1)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("playbook %q: duplicate step id %q", p.ID, s.ID)
		}
		seen[s.ID] = true
		if !knownCommands[s.Command] {
			return nil, fmt.Errorf("playbook %q step %q: unknown command %q", p.ID, s.ID, s.Command)
		}
		// Payloads are validated structurally here; the command-specific
		// validation runs again at issue time, because a substituted value
		// is not known until then.
		if _, err := json.Marshal(s.Payload); err != nil {
			return nil, fmt.Errorf("playbook %q step %q: unusable payload: %w", p.ID, s.ID, err)
		}
	}

	if p.Automatic && p.Trigger == nil {
		// An automatic playbook with nothing to trigger it can only be run by
		// hand, so the flag would be a promise the file does not keep.
		return nil, fmt.Errorf("playbook %q is marked automatic but has no trigger", p.ID)
	}
	if p.Trigger != nil {
		for _, k := range p.Trigger.AlertKinds {
			switch k {
			case "fim", "sca", "vuln":
			default:
				return nil, fmt.Errorf("playbook %q: unknown alert kind %q", p.ID, k)
			}
		}
		if len(p.Trigger.AlertKinds) == 0 {
			return nil, fmt.Errorf("playbook %q: a trigger must name at least one alert kind", p.ID)
		}
	}

	p.Hash = hashOf(raw)
	return &p, nil
}

// Load reads a playbook from disk.
func Load(path string) (*Playbook, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read playbook: %w", err)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Source = path
	return p, nil
}

// Set is the loaded collection.
type Set struct {
	byID map[string]*Playbook
}

// LoadDir reads every .yaml in a directory.
//
// One bad file fails the whole load. A partially-loaded set means the operator
// believes a playbook exists when it does not, and they find out during the
// incident it was written for.
func LoadDir(dir string) (*Set, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	set := &Set{byID: map[string]*Playbook{}}
	for _, path := range matches {
		p, err := Load(path)
		if err != nil {
			return nil, err
		}
		if _, dup := set.byID[p.ID]; dup {
			return nil, fmt.Errorf("duplicate playbook id %q in %s", p.ID, path)
		}
		set.byID[p.ID] = p
	}
	return set, nil
}

// Get returns a playbook by id.
func (s *Set) Get(id string) (*Playbook, bool) {
	if s == nil {
		return nil, false
	}
	p, ok := s.byID[id]
	return p, ok
}

// All returns every playbook, ordered by id.
func (s *Set) All() []*Playbook {
	if s == nil {
		return nil
	}
	out := make([]*Playbook, 0, len(s.byID))
	for _, p := range s.byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len reports how many playbooks are loaded.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byID)
}
