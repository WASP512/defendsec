// Package mcp implements the Model Context Protocol server side (roadmap 4.1).
//
// # What this package is for
//
// DefendSec's Phase 4 claim is narrow and worth stating precisely: it is the
// enforcement layer that makes AI-initiated response safe and provable. An
// agent connected here cannot exceed the bounded command set, cannot bypass
// the policy engine, cannot sign its own authority, and cannot act without
// leaving a cryptographic record.
//
// None of that is enforced in this package. This package speaks a wire
// protocol and nothing else — it has no knowledge of DefendSec, no access to
// the signer, and no ability to issue a command. The enforcement lives where
// it belongs, in the policy engine and the signing path, and the tools exposed
// here reach it through the same door a human does. Keeping the protocol layer
// ignorant is the point: a protocol bug cannot become an authority bug.
//
// # DefendSec does not call a model
//
// This is a server. An agent runs wherever its operator runs it and connects
// inward. DefendSec never sends data to a model provider, holds no API key,
// and has no outbound dependency on any AI service — which for self-hosted
// security software is not a limitation but the only defensible design.
package mcp

import "encoding/json"

// Protocol versions.
//
// The current revision is stateless: there is no initialize handshake, no
// session id, and no server-initiated requests. Every request carries its own
// version, identity and capabilities in `_meta`.
const (
	// VersionCurrent is the revision this server implements natively.
	VersionCurrent = "2026-07-28"
	// VersionLegacy is the newest handshake-based revision accepted for
	// backward compatibility. Most clients in the field still speak this era,
	// and a spec-pure server nobody can connect to is not a feature.
	VersionLegacy = "2025-11-25"
	// VersionLegacyAlt is another handshake-era revision widely implemented.
	VersionLegacyAlt = "2025-06-18"
)

// SupportedVersions is what an UnsupportedProtocolVersionError advertises,
// newest first so a client picking the head of the list picks the best one.
var SupportedVersions = []string{VersionCurrent, VersionLegacy, VersionLegacyAlt}

// Meta keys carried in a modern request's params._meta.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// JSON-RPC error codes. The -320xx range below -32600 is reserved by the MCP
// specification for protocol-defined errors.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// CodeHeaderMismatch reports that the mirrored HTTP headers disagree with
	// the request body. It exists because an intermediary may route on the
	// header while the server acts on the body, and a mismatch between those
	// two views is exactly the gap an attacker aims at.
	CodeHeaderMismatch = -32020
	// CodeUnsupportedProtocolVersion carries the versions the server does
	// support, so a client can retry rather than guess.
	CodeUnsupportedProtocolVersion = -32022
)

// Request is an inbound JSON-RPC request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the message expects no response. A JSON-RPC
// notification is one with no id at all; an explicit null id is not the same
// thing, and treating it as one would silently swallow a malformed request.
func (r Request) IsNotification() bool {
	return len(r.ID) == 0
}

// Response is an outbound JSON-RPC response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements error so a handler can return one directly.
func (e *Error) Error() string { return e.Message }

// NewError builds a protocol error.
func NewError(code int, message string) *Error {
	return &Error{Code: code, Message: message}
}

// unsupportedVersion builds the error that tells a client what to retry with.
func unsupportedVersion(requested string) *Error {
	return &Error{
		Code:    CodeUnsupportedProtocolVersion,
		Message: "Unsupported protocol version",
		Data: map[string]any{
			"supported": SupportedVersions,
			"requested": requested,
		},
	}
}

// result wraps a successful reply.
func result(id json.RawMessage, value any) Response {
	return Response{JSONRPC: "2.0", ID: id, Result: value}
}

// failure wraps an error reply.
func failure(id json.RawMessage, err *Error) Response {
	return Response{JSONRPC: "2.0", ID: id, Error: err}
}
