package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// The Streamable HTTP transport (MCP revision 2026-07-28).
//
// One endpoint, POST only. The current revision removed the GET stream and
// protocol-level sessions, so there is no session id to mint, nothing to
// resume, and no server-initiated request. That makes the server stateless,
// which is the property worth having here: an agent's authority comes from
// the credential on each request and from nothing it established earlier.

// maxBodyBytes bounds one request. Generous for a JSON-RPC message and far
// below anything that could be used to exhaust memory.
const maxBodyBytes = 1 << 20

// Transport serves an MCP server over HTTP.
type Transport struct {
	Server *Server
	Log    *slog.Logger
	// Authorize gates every request. It returns the identity to attribute the
	// call to, and false to refuse. Required: a transport with no
	// authorization is an unauthenticated remote-control surface, so a nil
	// Authorize refuses everything rather than allowing it.
	Authorize func(r *http.Request) (identity string, ok bool)
	// AllowedOrigins are the Origin values accepted. Origin validation is
	// mandatory in the specification because without it a web page the
	// operator visits can drive a local MCP server through DNS rebinding.
	// Empty means: accept only requests that send no Origin at all, which is
	// what a non-browser client does.
	AllowedOrigins []string
}

// identityKey is the context key carrying the caller's identity into a tool.
//
// Passed in the context rather than as a handler argument because a tool must
// not be able to choose who it acts as. The transport establishes the
// identity from the credential and the tool can only read it.
type identityKey struct{}

// withIdentity attaches the authorized identity.
func withIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// IdentityFrom returns the authorized identity for the current call. An empty
// string means the call was not attributed, which a tool that writes anything
// must treat as a refusal rather than as an anonymous permit.
func IdentityFrom(ctx context.Context) string {
	if v, ok := ctx.Value(identityKey{}).(string); ok {
		return v
	}
	return ""
}

// ServeHTTP handles one MCP request.
func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Older revisions used GET for a standalone event stream and DELETE to
	// end a session. Neither exists now, and the specification says to answer
	// them with 405 so an older client fails clearly instead of hanging.
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this MCP endpoint accepts POST only; the GET event stream and sessions were removed in revision "+VersionCurrent, http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Origin first, before authentication and before reading the body: a DNS
	// rebinding attempt should be refused without the server doing any work
	// on its behalf.
	if origin := r.Header.Get("Origin"); origin != "" && !t.originAllowed(origin) {
		t.writeError(w, http.StatusForbidden, nil,
			NewError(CodeInvalidRequest, "origin is not allowed"))
		return
	}

	identity, ok := t.authorize(r)
	if !ok {
		// Not a JSON-RPC error: the caller has not established who it is, so
		// there is no protocol conversation to have yet.
		w.Header().Set("WWW-Authenticate", `Bearer realm="defendsec-mcp"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		t.writeError(w, http.StatusBadRequest, nil,
			NewError(CodeParseError, "could not read the request body"))
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		t.writeError(w, http.StatusBadRequest, nil,
			NewError(CodeParseError, "the request body is not valid JSON"))
		return
	}

	// Header/body agreement. An intermediary may route on the mirrored header
	// while this server acts on the body; when the two disagree, one of them
	// is being lied to, and the specification requires refusing rather than
	// picking a side.
	if mismatch := t.validateHeaders(r, req); mismatch != nil {
		t.writeError(w, http.StatusBadRequest, req.ID, mismatch)
		return
	}

	ctx := r.Context()
	if identity != "" {
		ctx = withIdentity(ctx, identity)
	}

	resp := t.Server.Handle(ctx, req)
	if resp == nil {
		// A notification the server accepted.
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// An unimplemented method gets 404 as well as the JSON-RPC error, which
	// is what lets a dual-era client tell a modern server from a legacy
	// endpoint that simply is not there.
	status := http.StatusOK
	if resp.Error != nil {
		switch resp.Error.Code {
		case CodeMethodNotFound:
			status = http.StatusNotFound
		case CodeUnsupportedProtocolVersion, CodeHeaderMismatch, CodeParseError, CodeInvalidRequest:
			status = http.StatusBadRequest
		}
	}
	t.write(w, status, *resp)
}

// validateHeaders checks the mirrored request metadata.
//
// The protocol version header is required on every POST, and must agree with
// the body. Mcp-Method must agree with the method, and Mcp-Name with the tool
// or resource name. A legacy client sends none of these, and is not held to
// them: it is identified by the absence of modern `_meta`, and holding it to
// modern headers would make dual-era support meaningless.
func (t *Transport) validateHeaders(r *http.Request, req Request) *Error {
	var p params
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &p)
	}
	modern := p.Meta != nil && p.Meta.ProtocolVersion != ""

	headerVersion := r.Header.Get("MCP-Protocol-Version")
	if !modern {
		// Legacy era. A header without body metadata is accepted so long as
		// it names something this server speaks; a client that sends the
		// modern header should not be worse off than one that sends nothing.
		if headerVersion != "" && !supported(headerVersion) {
			return unsupportedVersion(headerVersion)
		}
		return nil
	}

	if headerVersion == "" {
		return NewError(CodeHeaderMismatch,
			"the MCP-Protocol-Version header is required and was not sent")
	}
	if headerVersion != p.Meta.ProtocolVersion {
		return NewError(CodeHeaderMismatch,
			"the MCP-Protocol-Version header does not match the protocol version in the request body")
	}
	if got := r.Header.Get("Mcp-Method"); got != "" && got != req.Method {
		return NewError(CodeHeaderMismatch,
			"the Mcp-Method header does not match the method in the request body")
	}

	// Mcp-Name mirrors params.name for tools/call, or params.uri for a
	// resource read. Either may arrive base64-encoded when the value is not
	// safe to put in a header verbatim.
	want := p.Name
	if want == "" {
		want = p.URI
	}
	if got := r.Header.Get("Mcp-Name"); got != "" {
		if decodeHeaderValue(got) != want {
			return NewError(CodeHeaderMismatch,
				"the Mcp-Name header does not match the name in the request body")
		}
	}
	return nil
}

// decodeHeaderValue undoes the specification's base64 sentinel encoding,
// which a client uses when a value cannot be sent as plain ASCII.
func decodeHeaderValue(v string) string {
	const prefix, suffix = "=?base64?", "?="
	if !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, suffix) {
		return v
	}
	inner := v[len(prefix) : len(v)-len(suffix)]
	decoded, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		// Left as-is so the comparison fails and the request is refused,
		// rather than silently matching on the raw sentinel text.
		return v
	}
	return string(decoded)
}

// originAllowed checks a browser-supplied Origin against the allowlist.
func (t *Transport) originAllowed(origin string) bool {
	for _, allowed := range t.AllowedOrigins {
		if strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

// authorize resolves the caller.
func (t *Transport) authorize(r *http.Request) (string, bool) {
	if t.Authorize == nil {
		// Deny, not allow. An MCP endpoint is a control surface, and the
		// failure direction for a missing authorization hook is refusal.
		return "", false
	}
	return t.Authorize(r)
}

func (t *Transport) write(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil && t.Log != nil {
		t.Log.Warn("write mcp response", "err", err)
	}
}

func (t *Transport) writeError(w http.ResponseWriter, status int, id json.RawMessage, e *Error) {
	t.write(w, status, failure(id, e))
}
