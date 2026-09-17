package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer() *Server {
	tools := NewToolSet()
	tools.MustAdd(Tool{
		Name:        "echo",
		Description: "Returns its argument.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (Result, error) {
			var in struct{ Text string }
			_ = json.Unmarshal(args, &in)
			return Structured("echoed", map[string]any{
				"text":   in.Text,
				"caller": IdentityFrom(ctx),
			}), nil
		},
	})
	return &Server{
		Name: "defendsec", Version: "test",
		Instructions: "Read freely; propose, never act.",
		Tools:        tools,
	}
}

func testTransport() *Transport {
	return &Transport{
		Server:    testServer(),
		Authorize: func(r *http.Request) (string, bool) { return "agent:test", true },
	}
}

// post sends a modern request with all the mirrored headers the
// specification requires.
func post(t *testing.T, tr *Transport, method string, params map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		MetaProtocolVersion:    VersionCurrent,
		MetaClientInfo:         map[string]any{"name": "test", "version": "1"},
		MetaClientCapabilities: map[string]any{},
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", VersionCurrent)
	req.Header.Set("Mcp-Method", method)
	if name, ok := params["name"].(string); ok {
		req.Header.Set("Mcp-Name", name)
	}
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// server/discover is a MUST in the specification, and it is how a client
// learns what to speak before sending anything else.
func TestDiscoverAdvertisesSupportedVersions(t *testing.T) {
	tr := testTransport()
	rec, out := post(t, tr, methodDiscover, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %s", rec.Body)
	}
	if res["resultType"] != "complete" {
		t.Errorf("resultType = %v", res["resultType"])
	}
	versions, _ := res["supportedVersions"].([]any)
	if len(versions) == 0 || versions[0] != VersionCurrent {
		t.Errorf("supportedVersions = %v, want the current revision first", versions)
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Error("the server does not advertise the tools capability")
	}
	meta, _ := res["_meta"].(map[string]any)
	if _, ok := meta[MetaServerInfo]; !ok {
		t.Error("discover carries no serverInfo")
	}
}

// A version this server does not speak must be refused with the list of what
// it does speak, or a client has nothing to retry with.
func TestUnsupportedVersionNamesWhatIsSupported(t *testing.T) {
	tr := testTransport()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"` +
		MetaProtocolVersion + `":"1900-01-01"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", "1900-01-01")
	req.Header.Set("Mcp-Method", "tools/list")
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var out struct {
		Error struct {
			Code int `json:"code"`
			Data struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body)
	}
	if out.Error.Code != CodeUnsupportedProtocolVersion {
		t.Errorf("code = %d, want %d", out.Error.Code, CodeUnsupportedProtocolVersion)
	}
	if len(out.Error.Data.Supported) == 0 {
		t.Error("the error does not say what is supported, so the client cannot retry")
	}
	if out.Error.Data.Requested != "1900-01-01" {
		t.Errorf("requested = %q", out.Error.Data.Requested)
	}
}

// The header and the body are two views of one request. An intermediary may
// route on one while this server acts on the other, so a disagreement is
// refused rather than resolved in favour of either.
func TestHeaderBodyMismatchIsRefused(t *testing.T) {
	cases := []struct {
		name         string
		headers      map[string]string
		dropProtoHdr bool
		bodyName     string
		wantMismatch bool
	}{
		{
			name:         "protocol version header disagrees with the body",
			headers:      map[string]string{"MCP-Protocol-Version": VersionLegacy},
			wantMismatch: true,
		},
		{
			name:         "method header disagrees with the body",
			headers:      map[string]string{"Mcp-Method": "tools/list"},
			bodyName:     "echo",
			wantMismatch: true,
		},
		{
			name:         "name header disagrees with the body",
			headers:      map[string]string{"Mcp-Name": "something-else"},
			bodyName:     "echo",
			wantMismatch: true,
		},
		{
			name:         "protocol version header missing entirely",
			dropProtoHdr: true,
			bodyName:     "echo",
			wantMismatch: true,
		},
		{
			name:         "everything agrees",
			bodyName:     "echo",
			wantMismatch: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := testTransport()
			params := map[string]any{
				"_meta": map[string]any{MetaProtocolVersion: VersionCurrent},
			}
			if tc.bodyName != "" {
				params["name"] = tc.bodyName
				params["arguments"] = map[string]any{"text": "hi"}
			}
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params,
			})
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body)))
			if !tc.dropProtoHdr {
				req.Header.Set("MCP-Protocol-Version", VersionCurrent)
			}
			req.Header.Set("Mcp-Method", "tools/call")
			if tc.bodyName != "" {
				req.Header.Set("Mcp-Name", tc.bodyName)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			tr.ServeHTTP(rec, req)

			var out struct {
				Error *struct{ Code int } `json:"error"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &out)

			gotMismatch := out.Error != nil && out.Error.Code == CodeHeaderMismatch
			if gotMismatch != tc.wantMismatch {
				t.Fatalf("mismatch=%v want %v (status %d, body %s)",
					gotMismatch, tc.wantMismatch, rec.Code, rec.Body)
			}
			if tc.wantMismatch && rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

// A value that cannot travel as plain ASCII arrives base64-encoded, and the
// server must decode before comparing or it refuses a conforming client.
func TestBase64SentinelHeaderIsDecodedBeforeComparing(t *testing.T) {
	tr := testTransport()
	tr.Server.Tools.MustAdd(Tool{
		Name:        "unicode.tool",
		Description: "Has a header-unsafe argument.",
		InputSchema: NoArguments(),
		Handler: func(ctx context.Context, args json.RawMessage) (Result, error) {
			return Text("ok"), nil
		},
	})

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":  "unicode.tool",
			"_meta": map[string]any{MetaProtocolVersion: VersionCurrent},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body)))
	req.Header.Set("MCP-Protocol-Version", VersionCurrent)
	req.Header.Set("Mcp-Method", "tools/call")
	encoded := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("unicode.tool")) + "?="
	req.Header.Set("Mcp-Name", encoded)
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a correctly encoded header was refused: %d %s", rec.Code, rec.Body)
	}
}

// Origin validation is mandatory: without it a page the operator visits can
// drive a local MCP server through DNS rebinding.
func TestOriginIsValidated(t *testing.T) {
	tr := testTransport()
	tr.AllowedOrigins = []string{"https://console.example"}

	for _, tc := range []struct {
		origin string
		want   int
	}{
		{"", http.StatusOK},                        // a non-browser client
		{"https://console.example", http.StatusOK}, // allowlisted
		{"https://CONSOLE.example", http.StatusOK}, // case-insensitive
		{"https://evil.example", http.StatusForbidden},
	} {
		body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"` +
			MetaProtocolVersion + `":"` + VersionCurrent + `"}}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("MCP-Protocol-Version", VersionCurrent)
		req.Header.Set("Mcp-Method", "server/discover")
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		rec := httptest.NewRecorder()
		tr.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("origin %q: status %d, want %d", tc.origin, rec.Code, tc.want)
		}
	}
}

// An origin is refused before the request is authenticated or parsed: a
// rebinding attempt should not get the server to do work on its behalf.
func TestOriginIsCheckedBeforeAuthorization(t *testing.T) {
	authorizeCalled := false
	tr := testTransport()
	tr.AllowedOrigins = []string{"https://console.example"}
	tr.Authorize = func(r *http.Request) (string, bool) {
		authorizeCalled = true
		return "agent:test", true
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if authorizeCalled {
		t.Error("the credential was examined for a request from a refused origin")
	}
}

// A transport with no authorization hook is an unauthenticated control
// surface. The failure direction is refusal.
func TestMissingAuthorizeHookDeniesEverything(t *testing.T) {
	tr := &Transport{Server: testServer()}
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a nil Authorize must not mean open access", rec.Code)
	}
}

// GET and DELETE were the session mechanics of earlier revisions. Answering
// 405 makes an older client fail clearly rather than hang on a stream that
// will never open.
func TestRemovedSessionMechanicsAnswer405(t *testing.T) {
	tr := testTransport()
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req := httptest.NewRequest(method, "/mcp", nil)
		rec := httptest.NewRecorder()
		tr.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, rec.Code)
		}
		if rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s: Allow = %q", method, rec.Header().Get("Allow"))
		}
	}
}

// A session id or resume header from an older client is ignored rather than
// honoured, and must not stop the request working.
func TestLegacySessionHeadersAreIgnoredNotHonoured(t *testing.T) {
	tr := testTransport()
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"` +
		MetaProtocolVersion + `":"` + VersionCurrent + `"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", VersionCurrent)
	req.Header.Set("Mcp-Method", "server/discover")
	req.Header.Set("Mcp-Session-Id", "should-be-ignored")
	req.Header.Set("Last-Event-ID", "7")
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Mcp-Session-Id"); got != "" {
		t.Errorf("the server minted or echoed a session id: %q", got)
	}
}

// An unknown method gets 404 as well as -32601. That pairing is what lets a
// dual-era client tell a modern server from an endpoint that is not there.
func TestUnknownMethodIs404AndMethodNotFound(t *testing.T) {
	tr := testTransport()
	rec, out := post(t, tr, "resources/subscribe", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil || int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("error = %v, want %d", errObj, CodeMethodNotFound)
	}
}

// A legacy client sends no per-request metadata and expects a handshake.
// Serving it is deliberate: a spec-pure server that no client in the field
// can talk to has shipped nothing.
func TestLegacyInitializeHandshakeIsServed(t *testing.T) {
	tr := testTransport()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` +
		`"protocolVersion":"2025-06-18","clientInfo":{"name":"old","version":"1"},"capabilities":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Result struct {
			ProtocolVersion string         `json:"protocolVersion"`
			ServerInfo      map[string]any `json:"serverInfo"`
			Capabilities    map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Result.ProtocolVersion != "2025-06-18" {
		t.Errorf("protocolVersion = %q, want the client's own version echoed",
			out.Result.ProtocolVersion)
	}
	if out.Result.ServerInfo["name"] == nil {
		t.Error("the handshake carries no serverInfo")
	}
	if _, ok := out.Result.Capabilities["tools"]; !ok {
		t.Error("the handshake does not advertise tools")
	}
}

// A legacy client asking for a revision this server does not know still gets
// a usable answer: it has no way to fall forward, so refusing leaves its user
// with nothing to act on.
func TestLegacyInitializeWithUnknownVersionStillAnswers(t *testing.T) {
	tr := testTransport()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !supported(out.Result.ProtocolVersion) {
		t.Errorf("protocolVersion = %q, want a version this server actually speaks",
			out.Result.ProtocolVersion)
	}
}

// The post-handshake notification has no id and must produce no response
// body at all.
func TestNotificationGets202AndNoBody(t *testing.T) {
	tr := testTransport()
	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a notification produced a body: %s", rec.Body)
	}
}

func TestToolsListIsDeterministicAndComplete(t *testing.T) {
	tr := testTransport()
	tr.Server.Tools.MustAdd(Tool{
		Name: "aaa", Description: "First alphabetically.",
		InputSchema: NoArguments(),
		Handler:     func(context.Context, json.RawMessage) (Result, error) { return Text("ok"), nil },
	})

	_, out := post(t, tr, methodToolsList, nil)
	res := out["result"].(map[string]any)
	if res["resultType"] != "complete" {
		t.Errorf("resultType = %v", res["resultType"])
	}
	tools := res["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("got %d tools", len(tools))
	}
	if tools[0].(map[string]any)["name"] != "aaa" {
		t.Errorf("tools are not in deterministic order: %v", tools)
	}
	// Every tool must carry a schema, or a client cannot call it.
	for _, raw := range tools {
		tool := raw.(map[string]any)
		if tool["inputSchema"] == nil {
			t.Errorf("tool %v has no inputSchema", tool["name"])
		}
	}
}

func TestToolsCallReturnsStructuredAndTextContent(t *testing.T) {
	tr := testTransport()
	_, out := post(t, tr, methodToolsCall, map[string]any{
		"name": "echo", "arguments": map[string]any{"text": "hello"},
	})
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", out)
	}
	if res["isError"] != false {
		t.Errorf("isError = %v", res["isError"])
	}
	content := res["content"].([]any)
	if len(content) == 0 || content[0].(map[string]any)["type"] != "text" {
		t.Errorf("content = %v; a structured result still carries text for clients that cannot read the structure", content)
	}
	structured := res["structuredContent"].(map[string]any)
	if structured["text"] != "hello" {
		t.Errorf("structuredContent = %v", structured)
	}
	// The identity comes from the transport, never from the request body.
	if structured["caller"] != "agent:test" {
		t.Errorf("caller = %v, want the authorized identity", structured["caller"])
	}
}

// An unknown tool is a protocol error: no retry with better arguments fixes
// a tool that does not exist.
func TestUnknownToolIsAProtocolError(t *testing.T) {
	tr := testTransport()
	_, out := post(t, tr, methodToolsCall, map[string]any{"name": "nope"})
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil || int(errObj["code"].(float64)) != CodeInvalidParams {
		t.Errorf("error = %v, want %d", errObj, CodeInvalidParams)
	}
}

// A handler's internal error must not be relayed: it can carry
// infrastructure detail, and an agent is not a trusted audience for it.
func TestHandlerErrorDoesNotLeakItsMessage(t *testing.T) {
	tr := testTransport()
	tr.Server.Tools.MustAdd(Tool{
		Name: "breaks", Description: "Always fails.",
		InputSchema: NoArguments(),
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			return Result{}, errNoteworthy
		},
	})
	_, out := post(t, tr, methodToolsCall, map[string]any{"name": "breaks"})
	errObj, _ := out["error"].(map[string]any)
	if errObj == nil {
		t.Fatal("no error returned")
	}
	if msg, _ := errObj["message"].(string); strings.Contains(msg, "postgres") {
		t.Errorf("the handler's internal detail reached the agent: %q", msg)
	}
}

var errNoteworthy = &Error{Message: "postgres at 10.0.0.5 refused the connection"}

// A tool error is not a protocol error. A denied proposal is something the
// model should read and act on, and a JSON-RPC error is likely to be
// swallowed by the client rather than shown to it.
func TestToolErrorIsReportedInTheResult(t *testing.T) {
	tr := testTransport()
	tr.Server.Tools.MustAdd(Tool{
		Name: "denied", Description: "Always denied.",
		InputSchema: NoArguments(),
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			return ToolError("policy denied this: rule %s", "isolate-critical"), nil
		},
	})
	rec, out := post(t, tr, methodToolsCall, map[string]any{"name": "denied"})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: a tool error is a successful call", rec.Code)
	}
	res := out["result"].(map[string]any)
	if res["isError"] != true {
		t.Errorf("isError = %v, want true", res["isError"])
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "isolate-critical") {
		t.Errorf("the reason did not reach the model: %q", text)
	}
}

func TestRegistrationRefusesMalformedTools(t *testing.T) {
	handler := func(context.Context, json.RawMessage) (Result, error) { return Text("ok"), nil }
	for _, tc := range []struct {
		name string
		tool Tool
	}{
		{"a name with a space", Tool{Name: "bad name", Description: "d", InputSchema: NoArguments(), Handler: handler}},
		{"no description", Tool{Name: "ok", InputSchema: NoArguments(), Handler: handler}},
		{"no schema", Tool{Name: "ok", Description: "d", Handler: handler}},
		{"no handler", Tool{Name: "ok", Description: "d", InputSchema: NoArguments()}},
		{"empty name", Tool{Name: "", Description: "d", InputSchema: NoArguments(), Handler: handler}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := NewToolSet().Add(tc.tool); err == nil {
				t.Error("registration was accepted")
			}
		})
	}

	// A duplicate name would shadow a tool silently.
	s := NewToolSet()
	good := Tool{Name: "dup", Description: "d", InputSchema: NoArguments(), Handler: handler}
	if err := s.Add(good); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := s.Add(good); err == nil {
		t.Error("a duplicate tool name was accepted")
	}
}

func TestOversizedBodyIsRefusedRatherThanRead(t *testing.T) {
	tr := testTransport()
	huge := strings.Repeat("a", maxBodyBytes+4096)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + huge + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", VersionCurrent)
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("an oversized body was processed")
	}
}

func TestMalformedJSONIsAParseError(t *testing.T) {
	tr := testTransport()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var out struct {
		Error struct{ Code int } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Error.Code != CodeParseError {
		t.Errorf("code = %d, want %d", out.Error.Code, CodeParseError)
	}
}

func TestWrongJSONRPCVersionIsRefused(t *testing.T) {
	tr := testTransport()
	body := `{"jsonrpc":"1.0","id":1,"method":"server/discover"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	tr.ServeHTTP(rec, req)
	var out struct {
		Error struct{ Code int } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Error.Code != CodeInvalidRequest {
		t.Errorf("code = %d, want %d", out.Error.Code, CodeInvalidRequest)
	}
}
