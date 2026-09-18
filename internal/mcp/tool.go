package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// Tool is one callable operation.
type Tool struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	// InputSchema must be a JSON Schema object. A tool taking no arguments
	// declares an object that accepts only empty ones rather than omitting
	// the schema, which the specification forbids.
	InputSchema map[string]any `json:"inputSchema"`
	// OutputSchema is optional, and when present the server must honour it.
	OutputSchema map[string]any `json:"outputSchema,omitempty"`

	// Handler runs the tool. Returning an error means a protocol-level
	// failure; returning a Result with IsError set means the tool ran and
	// failed in a way the model can read and correct.
	Handler func(ctx context.Context, args json.RawMessage) (Result, error) `json:"-"`
}

// Result is a tool's reply.
type Result struct {
	Content []Content `json:"content"`
	// StructuredContent is the machine-readable form. Text is still sent
	// alongside it, because a client that cannot read the structure should
	// still be able to show the operator what happened.
	StructuredContent any `json:"structuredContent,omitempty"`
	// IsError marks a failure the model can act on — bad arguments, a denied
	// request — as distinct from a protocol error.
	IsError bool `json:"isError,omitempty"`
}

// Content is one content block. Only text is produced here: DefendSec has
// nothing to say to an agent that is not text or structured data.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Text builds a successful text result.
func Text(format string, args ...any) Result {
	return Result{Content: []Content{{Type: "text", Text: fmt.Sprintf(format, args...)}}}
}

// Structured builds a result carrying both a human-readable summary and the
// machine-readable payload.
func Structured(summary string, payload any) Result {
	return Result{
		Content:           []Content{{Type: "text", Text: summary}},
		StructuredContent: payload,
	}
}

// ToolError builds a result the model is expected to read and correct.
//
// Deliberately not a protocol error: a denied proposal or a bad argument is
// information an agent should act on, and a JSON-RPC error is likely to be
// swallowed by the client instead of shown to the model.
func ToolError(format string, args ...any) Result {
	return Result{
		Content: []Content{{Type: "text", Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}
}

// toolNamePattern is the character set the specification allows. Enforced at
// registration so a malformed name is a start-up failure rather than a tool
// that some clients silently drop from their list.
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// ToolSet is a registry of tools.
type ToolSet struct {
	tools map[string]Tool
}

// NewToolSet creates an empty registry.
func NewToolSet() *ToolSet {
	return &ToolSet{tools: map[string]Tool{}}
}

// Add registers a tool, returning an error rather than panicking so a caller
// assembling a tool surface can report every problem at once.
func (s *ToolSet) Add(t Tool) error {
	if !toolNamePattern.MatchString(t.Name) {
		return fmt.Errorf("tool name %q is not allowed: letters, digits, underscore, hyphen and dot only, 1-128 characters", t.Name)
	}
	if t.Handler == nil {
		return fmt.Errorf("tool %q has no handler", t.Name)
	}
	if t.Description == "" {
		// A tool a model cannot understand is a tool it will misuse.
		return fmt.Errorf("tool %q has no description", t.Name)
	}
	if t.InputSchema == nil {
		return fmt.Errorf("tool %q has no input schema; a tool taking no arguments still declares an empty object schema", t.Name)
	}
	if _, exists := s.tools[t.Name]; exists {
		return fmt.Errorf("tool %q is already registered", t.Name)
	}
	s.tools[t.Name] = t
	return nil
}

// MustAdd registers a tool and panics on a programming error. Used for the
// built-in surface, which is a compile-time constant in everything but form.
func (s *ToolSet) MustAdd(t Tool) {
	if err := s.Add(t); err != nil {
		panic(err)
	}
}

// List returns the tools in a deterministic order, which the specification
// asks for so clients can cache the list.
func (s *ToolSet) List() []Tool {
	names := make([]string, 0, len(s.tools))
	for name := range s.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Tool, 0, len(names))
	for _, name := range names {
		out = append(out, s.tools[name])
	}
	return out
}

// Lookup finds a tool by name.
func (s *ToolSet) Lookup(name string) (Tool, bool) {
	t, ok := s.tools[name]
	return t, ok
}

// Len is how many tools are registered.
func (s *ToolSet) Len() int { return len(s.tools) }

// NoArguments is the schema for a tool that takes none. Spelled out because
// the specification requires a valid schema object and recommends refusing
// unexpected properties rather than silently ignoring them.
func NoArguments() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false}
}
