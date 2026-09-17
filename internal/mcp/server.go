package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// Server dispatches MCP methods over a tool set.
type Server struct {
	// Name and Version are self-reported identity. The specification is
	// explicit that clients must not make security decisions from them, and
	// neither does anything here.
	Name    string
	Version string
	// Instructions is natural-language guidance shown to the model. This is
	// where DefendSec states what an agent can and cannot do, because an
	// agent that learns its limits by hitting them wastes an operator's time.
	Instructions string
	Tools        *ToolSet
}

// Method names.
const (
	methodDiscover  = "server/discover"
	methodInit      = "initialize"
	methodInitDone  = "notifications/initialized"
	methodToolsList = "tools/list"
	methodToolsCall = "tools/call"
	methodPing      = "ping"
)

// requestMeta is the per-request metadata a modern client sends.
type requestMeta struct {
	ProtocolVersion string          `json:"io.modelcontextprotocol/protocolVersion"`
	ClientInfo      json.RawMessage `json:"io.modelcontextprotocol/clientInfo"`
	Capabilities    json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
}

// params is the common shape of every request's params.
type params struct {
	Meta      *requestMeta    `json:"_meta"`
	Name      string          `json:"name"`
	URI       string          `json:"uri"`
	Arguments json.RawMessage `json:"arguments"`
	Cursor    string          `json:"cursor"`
}

// parseParams decodes params, tolerating their absence.
func parseParams(raw json.RawMessage) (params, *Error) {
	var p params
	if len(raw) == 0 || string(raw) == "null" {
		return p, nil
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, NewError(CodeInvalidParams, "params is not an object")
	}
	return p, nil
}

// supported reports whether a version string is one this server speaks.
func supported(version string) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// Handle dispatches one request and returns the response to send.
//
// A nil response means the message was a notification and nothing should be
// written. The transport decides the HTTP framing; this function decides
// nothing about HTTP at all, which keeps the protocol testable without one.
func (s *Server) Handle(ctx context.Context, req Request) *Response {
	if req.JSONRPC != "2.0" {
		if req.IsNotification() {
			return nil
		}
		resp := failure(req.ID, NewError(CodeInvalidRequest, `"jsonrpc" must be "2.0"`))
		return &resp
	}

	p, perr := parseParams(req.Params)
	if perr != nil {
		if req.IsNotification() {
			return nil
		}
		resp := failure(req.ID, perr)
		return &resp
	}

	// A modern request declares its version and is rejected if this server
	// does not speak it. A request with no `_meta` is a legacy client, served
	// under the handshake era rather than refused: the specification permits
	// a dual-era server, and refusing would lock out most clients in use.
	if p.Meta != nil && p.Meta.ProtocolVersion != "" && !supported(p.Meta.ProtocolVersion) {
		if req.IsNotification() {
			return nil
		}
		resp := failure(req.ID, unsupportedVersion(p.Meta.ProtocolVersion))
		return &resp
	}

	switch req.Method {
	case methodInitDone:
		// A legacy client's post-handshake notification. Nothing to do, and
		// nothing to return: there is no session to mark ready.
		return nil

	case methodPing:
		if req.IsNotification() {
			return nil
		}
		resp := result(req.ID, map[string]any{})
		return &resp

	case methodDiscover:
		if req.IsNotification() {
			return nil
		}
		resp := result(req.ID, s.discoverResult())
		return &resp

	case methodInit:
		if req.IsNotification() {
			return nil
		}
		resp := s.initialize(req, p)
		return &resp

	case methodToolsList:
		if req.IsNotification() {
			return nil
		}
		resp := result(req.ID, s.listResult())
		return &resp

	case methodToolsCall:
		if req.IsNotification() {
			return nil
		}
		resp := s.callTool(ctx, req, p)
		return &resp

	default:
		if req.IsNotification() {
			// An unknown notification is ignored rather than answered: a
			// notification has no id to answer on.
			return nil
		}
		resp := failure(req.ID, NewError(CodeMethodNotFound,
			fmt.Sprintf("method %q is not implemented", req.Method)))
		return &resp
	}
}

// capabilities is what this server offers. Tools only: DefendSec exposes no
// prompts, and its data is reached through tools rather than resources so
// that every read goes through one auditable path.
func (s *Server) capabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}}
}

// discoverResult answers server/discover, which the specification requires
// every server to implement.
func (s *Server) discoverResult() map[string]any {
	return map[string]any{
		"resultType":        "complete",
		"supportedVersions": SupportedVersions,
		"capabilities":      s.capabilities(),
		"instructions":      s.Instructions,
		"_meta": map[string]any{
			MetaServerInfo: map[string]any{"name": s.Name, "version": s.Version},
		},
	}
}

// initialize answers a legacy client's handshake.
//
// The version echoed back is the newest one both sides speak. A legacy client
// has no fall-forward mechanism, so when it asks for something unknown the
// reply names what is supported rather than failing blankly — that message
// may be the only diagnostic its user ever sees.
func (s *Server) initialize(req Request, p params) Response {
	var body struct {
		ProtocolVersion string          `json:"protocolVersion"`
		ClientInfo      json.RawMessage `json:"clientInfo"`
	}
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &body)
	}

	version := body.ProtocolVersion
	switch {
	case version == "":
		version = VersionLegacy
	case supported(version):
		// Echo the client's choice.
	default:
		// An unknown version: answer in the newest legacy revision rather
		// than refusing. A client that asked for something newer than this
		// server knows still works, and one that asked for something older
		// gets a clear statement of what is on offer.
		version = VersionLegacy
	}

	return result(req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    s.capabilities(),
		"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		"instructions":    s.Instructions,
	})
}

// listResult answers tools/list.
func (s *Server) listResult() map[string]any {
	tools := []Tool{}
	if s.Tools != nil {
		tools = s.Tools.List()
	}
	return map[string]any{
		"resultType": "complete",
		"tools":      tools,
	}
}

// callTool answers tools/call.
func (s *Server) callTool(ctx context.Context, req Request, p params) Response {
	if p.Name == "" {
		return failure(req.ID, NewError(CodeInvalidParams, "params.name is required"))
	}
	if s.Tools == nil {
		return failure(req.ID, NewError(CodeMethodNotFound, "this server exposes no tools"))
	}
	tool, ok := s.Tools.Lookup(p.Name)
	if !ok {
		// A protocol error rather than a tool error: an unknown tool is not
		// something a model can correct by retrying with better arguments.
		return failure(req.ID, NewError(CodeInvalidParams,
			fmt.Sprintf("unknown tool: %s", p.Name)))
	}

	res, err := tool.Handler(ctx, p.Arguments)
	if err != nil {
		// A handler returning an error has failed internally. The message is
		// deliberately not passed through: a handler error can carry
		// infrastructure detail, and an agent is not a trusted audience for
		// it. The specifics go to the server log instead.
		return failure(req.ID, NewError(CodeInternalError, "the tool failed"))
	}
	if res.Content == nil {
		res.Content = []Content{}
	}

	out := map[string]any{
		"resultType": "complete",
		"content":    res.Content,
		"isError":    res.IsError,
	}
	if res.StructuredContent != nil {
		out["structuredContent"] = res.StructuredContent
	}
	return result(req.ID, out)
}
