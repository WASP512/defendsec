package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"defendsec/internal/mcp"
	"defendsec/internal/storepg"
)

// The MCP tool surface (roadmap 4.1).
//
// # Read freely, propose, never act
//
// The tools below divide cleanly. Everything except one is a read, and the
// one exception proposes. There is no tool that issues a command, because
// there is no code path from here to the signer that does not pass through a
// human approval — see Server.Propose.
//
// # Why tools rather than resources
//
// MCP offers resources as well as tools, and exposing fleet state as
// resources would have been a closer fit to their intended use. Tools are
// used instead so every read goes through one path that can be attributed and
// audited. A resource read that leaves no trace of which agent read what is a
// gap in exactly the record this phase exists to produce.
//
// # What an agent is told
//
// The instructions below state the bounds up front. An agent that discovers
// its limits by hitting them wastes an operator's time, and one that does not
// know a human must approve its proposals will write as though it were acting.

const mcpInstructions = `This is DefendSec, a self-hosted host security control plane.

You may read fleet state freely: hosts, alerts, advisories, detection
coverage, policy, and the audit ledger.

You may not act. The only tool that changes anything is
defendsec.propose_response, and it does not execute — it records an unsigned
proposal that a human operator must approve before any command is signed.
This is enforced cryptographically, not by convention: a proposal has no
signature field, and the signing key is never reachable from a proposal.

When you propose, state your reasoning and cite the DefendSec record ids you
relied on. A human will read both before deciding, and an unexplained
recommendation is one they will reject.

Policy may refuse a proposal outright. A refusal names the rule that decided
and is not something to retry with different wording — it is the operator's
configured boundary, and working around it is not your task.`

// mcpToolSet builds the tool surface.
func (s *Server) mcpToolSet() *mcp.ToolSet {
	tools := mcp.NewToolSet()

	tools.MustAdd(mcp.Tool{
		Name:        "defendsec.list_hosts",
		Title:       "List hosts",
		Description: "Every enrolled host with its platform, connection state, isolation state and posture. Start here: a device id from this list is what every other tool takes.",
		InputSchema: mcp.NoArguments(),
		Handler:     s.toolListHosts,
	})

	tools.MustAdd(mcp.Tool{
		Name:        "defendsec.get_host",
		Title:       "Host detail",
		Description: "Full detail for one host: inventory, pending updates, file-integrity state, and posture. Use this before proposing anything that targets a host.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"deviceId": map[string]any{
					"type":        "string",
					"description": "The host's device id, as returned by defendsec.list_hosts.",
				},
			},
			"required":             []string{"deviceId"},
			"additionalProperties": false,
		},
		Handler: s.toolGetHost,
	})

	tools.MustAdd(mcp.Tool{
		Name:        "defendsec.list_alerts",
		Title:       "List alerts",
		Description: "Alerts, newest first. Filter by status (open, acknowledged, resolved), kind, or device id.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"status":   map[string]any{"type": "string", "description": "open, acknowledged or resolved."},
				"kind":     map[string]any{"type": "string", "description": "Alert kind, such as detection, fim or sca."},
				"deviceId": map[string]any{"type": "string", "description": "Restrict to one host."},
				"limit":    map[string]any{"type": "integer", "description": "Maximum alerts to return. Default 50."},
			},
			"additionalProperties": false,
		},
		Handler: s.toolListAlerts,
	})

	tools.MustAdd(mcp.Tool{
		Name:        "defendsec.detection_coverage",
		Title:       "Detection coverage",
		Description: "What the behavioural rules can and cannot see, blind spots first. Read this before concluding that the absence of an alert means the absence of activity — it often means no sensor reports that event kind.",
		InputSchema: mcp.NoArguments(),
		Handler:     s.toolDetectionCoverage,
	})

	tools.MustAdd(mcp.Tool{
		Name:        "defendsec.get_policy",
		Title:       "Response policy",
		Description: "The response policy in force: which commands are permitted against which host classes, what needs approval, and the blast-radius limits. Read this before proposing, so you propose something that can actually be approved.",
		InputSchema: mcp.NoArguments(),
		Handler:     s.toolGetPolicy,
	})

	tools.MustAdd(mcp.Tool{
		Name:        "defendsec.propose_response",
		Title:       "Propose a response",
		Description: "Records an unsigned proposal for a human to approve. This does NOT execute: the proposal has no signature and cannot acquire one without a human approval. Policy is evaluated immediately, so a proposal the policy forbids is refused here and now with the rule that decided.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"commandType": map[string]any{
					"type":        "string",
					"enum":        proposableCommands,
					"description": "The response to propose. run_script and agent_update are deliberately not proposable.",
				},
				"deviceId": map[string]any{
					"type":        "string",
					"description": "The host to act on.",
				},
				"payload": map[string]any{
					"type":        "object",
					"description": "Command-specific arguments, such as the pid for kill_process or the path for quarantine_path.",
				},
				"reasoning": map[string]any{
					"type":        "string",
					"description": "Your case for this response, written for the operator who will decide. Required: an unexplained proposal cannot be reviewed on its merits.",
				},
				"evidence": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "The DefendSec record ids you relied on — alert ids, advisory ids, host ids. Recorded in the ledger so an auditor can reconstruct what the recommendation rested on.",
				},
				"prompt": map[string]any{
					"type":        "string",
					"description": "What you were asked to do, if you can say. Recorded as provenance so the ledger can answer who set you on this task.",
				},
			},
			"required":             []string{"commandType", "deviceId", "reasoning"},
			"additionalProperties": false,
		},
		Handler: s.toolProposeResponse,
	})

	return tools
}

// MCPTransport builds the HTTP handler for the MCP endpoint.
func (s *Server) MCPTransport(allowedOrigins []string) *mcp.Transport {
	return &mcp.Transport{
		Server: &mcp.Server{
			Name: "defendsec",
			// The protocol treats serverInfo as display-only and explicitly
			// unverified, so there is nothing to gain from a precise build
			// string here and nothing to lose from a coarse one.
			Version:      "1",
			Instructions: mcpInstructions,
			Tools:        s.mcpToolSet(),
		},
		Log:            s.log,
		AllowedOrigins: allowedOrigins,
		Authorize: func(r *http.Request) (string, bool) {
			agent, ok := s.agentPrincipal(r)
			if !ok {
				return "", false
			}
			return agent.Identity(), true
		},
	}
}

// agentFor recovers the calling principal inside a tool handler.
//
// The identity comes from the context, which the transport set from the
// credential. A tool cannot choose who it acts as, and this re-reads the
// principal from the database rather than trusting a string, so a revocation
// that lands mid-conversation takes effect on the next call.
func (s *Server) agentFor(ctx context.Context) (storepg.AgentPrincipal, bool) {
	identity := mcp.IdentityFrom(ctx)
	name := strings.TrimPrefix(identity, "agent:")
	if name == "" || name == identity || s.pg == nil {
		return storepg.AgentPrincipal{}, false
	}
	agent, err := s.pg.GetAgentPrincipal(ctx, name)
	if err != nil || !agent.Active() {
		return storepg.AgentPrincipal{}, false
	}
	return agent, true
}

func (s *Server) toolListHosts(ctx context.Context, _ json.RawMessage) (mcp.Result, error) {
	devices := s.store.List()
	rows := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		rows = append(rows, map[string]any{
			"deviceId":  d.ID,
			"hostname":  d.Hostname,
			"platform":  d.Platform,
			"osName":    d.OSName,
			"osVersion": d.OSVersion,
			"connected": d.Connected,
			"isolated":  d.Isolated,
			"lastSeen":  d.LastSeen,
			"classes":   s.hostClasses(ctx, d.ID),
		})
	}
	return mcp.Structured(
		fmt.Sprintf("%d enrolled host(s).", len(rows)),
		map[string]any{"hosts": rows}), nil
}

// hostClasses reads a host's policy classes, which an agent needs in order to
// propose something policy can actually permit.
func (s *Server) hostClasses(ctx context.Context, deviceID string) []string {
	if s.pg == nil {
		return nil
	}
	classes, err := s.pg.DeviceClasses(ctx, deviceID)
	if err != nil {
		return nil
	}
	return classes
}

func (s *Server) toolGetHost(ctx context.Context, args json.RawMessage) (mcp.Result, error) {
	var in struct {
		DeviceID string `json:"deviceId"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return mcp.ToolError("deviceId is required and must be a string."), nil
	}
	dev, ok := s.store.Get(strings.TrimSpace(in.DeviceID))
	if !ok {
		return mcp.ToolError("No enrolled host has device id %q. Call defendsec.list_hosts for the current list.", in.DeviceID), nil
	}
	return mcp.Structured(
		fmt.Sprintf("%s (%s)", dev.Hostname, dev.ID),
		map[string]any{
			"host":    dev,
			"classes": s.hostClasses(ctx, dev.ID),
		}), nil
}

func (s *Server) toolListAlerts(ctx context.Context, args json.RawMessage) (mcp.Result, error) {
	var in struct {
		Status   string `json:"status"`
		Kind     string `json:"kind"`
		DeviceID string `json:"deviceId"`
		Limit    int    `json:"limit"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &in); err != nil {
			return mcp.ToolError("arguments must be an object."), nil
		}
	}
	if in.Limit <= 0 || in.Limit > 200 {
		in.Limit = 50
	}

	var rows []map[string]any
	if s.pg != nil {
		alerts, err := s.pg.ListAlerts(ctx, storepg.AlertFilters{
			Status: in.Status, Kind: in.Kind, DeviceID: in.DeviceID, Limit: in.Limit,
		})
		if err != nil {
			return mcp.Result{}, err
		}
		for _, a := range alerts {
			rows = append(rows, alertToMap(a))
		}
	} else {
		for _, a := range s.store.ListAlerts(in.Status, in.Kind, in.DeviceID, in.Limit) {
			rows = append(rows, alertToMap(storeAlert(a)))
		}
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	return mcp.Structured(
		fmt.Sprintf("%d alert(s).", len(rows)),
		map[string]any{"alerts": rows}), nil
}

func (s *Server) toolDetectionCoverage(ctx context.Context, _ json.RawMessage) (mcp.Result, error) {
	report := s.DetectionCoverageReport()
	summary := fmt.Sprintf("%d rules loaded. %d event kind(s) have no sensor reporting them.",
		report.Rules, len(report.UnobservedKinds))
	return mcp.Structured(summary, report), nil
}

func (s *Server) toolGetPolicy(ctx context.Context, _ json.RawMessage) (mcp.Result, error) {
	doc := s.policy.Document()
	if doc == nil {
		return mcp.Structured(
			"No response policy is loaded, so every command is denied.",
			map[string]any{
				"loaded": false,
				"detail": "DefendSec denies by default. With no policy document, nothing can be proposed successfully — an operator must configure one.",
			}), nil
	}
	return mcp.Structured(
		fmt.Sprintf("Policy %q with %d rule(s).", doc.Name, len(doc.Rules)),
		map[string]any{"loaded": true, "policy": doc}), nil
}

func (s *Server) toolProposeResponse(ctx context.Context, args json.RawMessage) (mcp.Result, error) {
	agent, ok := s.agentFor(ctx)
	if !ok {
		// Not a tool error: an unattributed proposal must not be recorded at
		// all, because the ledger entry would name no proposer.
		return mcp.ToolError("This call is not attributed to a live agent principal, so no proposal can be recorded. The principal may have been revoked."), nil
	}

	var in struct {
		CommandType string          `json:"commandType"`
		DeviceID    string          `json:"deviceId"`
		Payload     json.RawMessage `json:"payload"`
		Reasoning   string          `json:"reasoning"`
		Evidence    []string        `json:"evidence"`
		Prompt      string          `json:"prompt"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return mcp.ToolError("arguments must be an object with commandType, deviceId and reasoning."), nil
	}

	outcome, err := s.Propose(ctx, agent, Proposal{
		CommandType: in.CommandType,
		DeviceID:    in.DeviceID,
		Payload:     in.Payload,
		Reasoning:   in.Reasoning,
		Evidence:    in.Evidence,
		Prompt:      in.Prompt,
	})
	if err != nil {
		s.log.Error("record agent proposal", "err", err, "agent", agent.Name)
		return mcp.Result{}, err
	}

	// A denial or a rejection is a tool error, so the model reads it rather
	// than the client swallowing it. It is still a successful call: the
	// system worked exactly as intended.
	res := mcp.Structured(outcome.Detail, outcome)
	switch outcome.Status {
	case "awaiting-approval":
	default:
		res.IsError = true
	}
	return res, nil
}
