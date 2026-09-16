// Package events defines the behavioural telemetry DefendSec collects
// (roadmap 3.1-3.2).
//
// Detection before this was entirely state-based: what is installed, what
// changed on disk between two hashes, what is configured. That can tell you a
// file changed up to sixty seconds later. It cannot tell you which process
// changed it, what that process's parent was, whether it opened a network
// connection, or whether it is still running — so the response capability, the
// best part of the product, was driven by the weakest available signal.
//
// # Why the field names look like Sysmon's
//
// The field names here are deliberately the ones Sigma rules already use:
// Image, CommandLine, ParentImage, DestinationIp, and so on. Sigma has
// thousands of community-maintained rules written against that vocabulary.
// Inventing a cleaner schema would mean every one of those rules needs
// translating, and a translation layer is a permanent source of rules that
// silently match nothing.
//
// So the mapping happens once, here, at the point of collection.
package events

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is the category of an event.
type Kind string

const (
	// KindProcess is a process execution.
	KindProcess Kind = "process"
	// KindNetwork is an outbound connection or an accepted one.
	KindNetwork Kind = "network"
	// KindFile is a write or open on a watched path.
	KindFile Kind = "file"
	// KindPrivilege is a setuid, setgid or capability transition.
	KindPrivilege Kind = "privilege"
	// KindModule is a kernel module load.
	KindModule Kind = "module"
)

// Kinds lists every kind, in a stable order.
func Kinds() []Kind {
	return []Kind{KindProcess, KindNetwork, KindFile, KindPrivilege, KindModule}
}

// Event is one observed behaviour.
//
// Fields carries the Sigma-compatible attributes; the struct fields above it
// are the ones DefendSec itself routes on. Keeping the two separate means a
// rule can match on anything the sensor produces without this struct growing a
// field per rule.
type Event struct {
	// ID is unique per event, so an alert can point at the exact record.
	ID string `json:"id"`
	// DeviceID and Hostname identify where it happened.
	DeviceID string `json:"deviceId"`
	Hostname string `json:"hostname,omitempty"`
	Kind     Kind   `json:"kind"`
	// At is when the sensor observed it, in UTC.
	At time.Time `json:"at"`

	// PID and PPID anchor the process tree (roadmap 3.5).
	PID  int32 `json:"pid,omitempty"`
	PPID int32 `json:"ppid,omitempty"`

	// Fields are the Sigma-compatible attributes. Values are strings,
	// integers or lists of them; see Match for how comparison works.
	Fields map[string]any `json:"fields,omitempty"`
}

// Field reads an attribute, returning "" when absent.
func (e *Event) Field(name string) any {
	if e == nil || e.Fields == nil {
		return nil
	}
	return e.Fields[name]
}

// String reads an attribute as text.
func (e *Event) String(name string) string {
	return toString(e.Field(name))
}

// Set stores an attribute, dropping empty values so a rule asking whether a
// field is null gets the right answer. A field present but empty and a field
// absent are different facts, and sensors are inconsistent about which they
// produce.
func (e *Event) Set(name string, value any) {
	if e.Fields == nil {
		e.Fields = map[string]any{}
	}
	if s, ok := value.(string); ok && s == "" {
		delete(e.Fields, name)
		return
	}
	if value == nil {
		delete(e.Fields, name)
		return
	}
	e.Fields[name] = value
}

// FieldNames lists the attributes present, for the coverage view.
func (e *Event) FieldNames() []string {
	out := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Standard field names. Spelled as constants so a typo in DefendSec's own
// code is a compile error, while rules keep using the strings Sigma expects.
const (
	FieldImage            = "Image"
	FieldCommandLine      = "CommandLine"
	FieldParentImage      = "ParentImage"
	FieldParentCommand    = "ParentCommandLine"
	FieldUser             = "User"
	FieldUID              = "Uid"
	FieldCurrentDirectory = "CurrentDirectory"
	FieldProcessID        = "ProcessId"
	FieldParentProcessID  = "ParentProcessId"

	FieldDestinationIP   = "DestinationIp"
	FieldDestinationPort = "DestinationPort"
	FieldSourceIP        = "SourceIp"
	FieldSourcePort      = "SourcePort"
	FieldProtocol        = "Protocol"
	FieldInitiated       = "Initiated"

	FieldTargetFilename = "TargetFilename"
	FieldFileAction     = "FileAction"

	FieldTargetUID  = "TargetUid"
	FieldTargetUser = "TargetUser"
	FieldCapability = "Capability"

	FieldModuleName = "ModuleName"
)

// toString renders a field value for comparison. Numbers are rendered without
// exponent form, because a rule written as `DestinationPort: 4444` must match
// an event whose port arrived as a float from JSON.
func toString(v any) string {
	switch typed := v.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint32:
		return strconv.FormatUint(uint64(typed), 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		// JSON numbers arrive as float64. An integral value must render as an
		// integer or every port and pid comparison fails.
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case float32:
		return toString(float64(typed))
	default:
		return ""
	}
}

// Values renders a field as a list, so a rule matching one value against a
// multi-valued field (an argv list, several capabilities) behaves as an OR.
func Values(v any) []string {
	switch typed := v.(type) {
	case nil:
		return nil
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, toString(item))
		}
		return out
	default:
		return []string{toString(v)}
	}
}

// ProcessKey identifies a process within a host's lifetime.
type ProcessKey struct {
	DeviceID string
	PID      int32
}

// Ancestor is one step in a process's lineage.
type Ancestor struct {
	PID         int32  `json:"pid"`
	Image       string `json:"image,omitempty"`
	CommandLine string `json:"commandLine,omitempty"`
	User        string `json:"user,omitempty"`
}

// Describe renders an event for a human, which is what lands in an alert
// summary. Kept short: an analyst scanning a list needs the shape of the
// event, not every field.
func (e *Event) Describe() string {
	switch e.Kind {
	case KindProcess:
		if cmd := e.String(FieldCommandLine); cmd != "" {
			return truncate(cmd, 200)
		}
		return e.String(FieldImage)
	case KindNetwork:
		dest := e.String(FieldDestinationIP)
		if port := e.String(FieldDestinationPort); port != "" {
			dest += ":" + port
		}
		if img := e.String(FieldImage); img != "" {
			return img + " → " + dest
		}
		return dest
	case KindFile:
		action := e.String(FieldFileAction)
		if action == "" {
			action = "wrote"
		}
		return action + " " + e.String(FieldTargetFilename)
	case KindPrivilege:
		return e.String(FieldImage) + " → uid " + e.String(FieldTargetUID)
	case KindModule:
		return "module " + e.String(FieldModuleName)
	default:
		return string(e.Kind)
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
