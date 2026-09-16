package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/cmdlog"
	"defendsec/internal/playbook"
	"defendsec/internal/policy"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// Playbook execution (roadmap 2.5) and opt-in automatic response (2.6).
//
// A playbook is not an authority. Each step goes through the same
// authorise-then-sign path a single command does, at the moment it runs,
// against the host it targets. A sequence that could execute three commands on
// one policy decision would be a way to smuggle past the engine.

// SetPlaybooks installs the loaded set.
func (s *Server) SetPlaybooks(set *playbook.Set) { s.playbooks = set }

// autoRunCooldown is how long an automatic run of the same playbook on the
// same host is suppressed.
//
// A second brake, independent of policy's blast-radius limits, because the
// loop it stops is specific: a playbook that triggers on a finding it also
// causes. FIM detects a change, the playbook quarantines the file,
// quarantining changes the filesystem, FIM detects that. Policy limits would
// stop it eventually — after spending the fleet-wide budget a real incident
// needs.
const autoRunCooldown = time.Hour

// HandlePlaybooks lists playbooks and runs, and starts a run.
func (s *Server) HandlePlaybooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.adminOK(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		body := map[string]any{"playbooks": s.playbooks.All()}
		if s.pg != nil {
			if runs, err := s.pg.ListPlaybookRuns(r.Context(), 50); err == nil {
				body["runs"] = runs
			} else {
				s.log.Warn("list playbook runs", "err", err)
			}
		}
		writeJSON(w, http.StatusOK, body)

	case http.MethodPost:
		actor := s.resolveActor(r)
		if !s.requireAdminActor(w, r) {
			return
		}
		var req struct {
			PlaybookID string `json:"playbookId"`
			DeviceID   string `json:"deviceId"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		pb, ok := s.playbooks.Get(strings.TrimSpace(req.PlaybookID))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such playbook"})
			return
		}
		dev, found := s.store.Get(strings.TrimSpace(req.DeviceID))
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown device"})
			return
		}
		run, err := s.runPlaybook(r.Context(), pb, playbook.Alert{
			DeviceID: dev.ID, Hostname: dev.Hostname,
		}, actor.Identity(), "manual")
		if err != nil {
			s.log.Error("run playbook", "err", err)
			http.Error(w, "could not run the playbook", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, run)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// runPlaybook executes a sequence, checking policy before every step.
func (s *Server) runPlaybook(ctx context.Context, pb *playbook.Playbook, alert playbook.Alert, actor, origin string) (*storepg.PlaybookRun, error) {
	runID, err := newDeviceID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	run := &storepg.PlaybookRun{
		ID: runID, PlaybookID: pb.ID, PlaybookHash: pb.Hash,
		DeviceID: alert.DeviceID, Hostname: alert.Hostname,
		StartedAt: now, Status: "running", Origin: origin,
		Actor: actor, AlertID: alert.ID,
	}
	if s.pg != nil {
		if err := s.pg.StartPlaybookRun(ctx, *run); err != nil {
			return nil, err
		}
	}
	s.audit(actor, "playbook_run_start", alert.DeviceID, map[string]any{
		"runId": runID, "playbookId": pb.ID, "playbookHash": pb.Hash,
		"origin": origin, "alertId": alert.ID, "steps": len(pb.Steps),
	})

	status, detail := "completed", ""
	for i, step := range pb.Steps {
		outcome := s.runStep(ctx, pb, step, i, alert, actor, runID)
		run.Steps = append(run.Steps, outcome)

		if outcome.Status == "issued" || step.ContinueOnFailure {
			continue
		}
		// A playbook whose step was refused or is waiting is operating on
		// assumptions that no longer hold, so the rest is not run. Halting
		// loudly beats completing a sequence whose middle is missing.
		status = "halted"
		detail = fmt.Sprintf("Stopped at step %q (%s): %s", step.ID, outcome.Status, outcome.Detail)
		break
	}

	finished := time.Now().UTC()
	run.Status, run.Detail, run.FinishedAt = status, detail, &finished
	if s.pg != nil {
		if err := s.pg.FinishPlaybookRun(ctx, runID, status, detail, finished); err != nil {
			s.log.Warn("finish playbook run", "err", err)
		}
	}
	s.audit(actor, "playbook_run_finish", alert.DeviceID, map[string]any{
		"runId": runID, "playbookId": pb.ID, "status": status, "detail": detail,
	})
	return run, nil
}

// runStep authorises, signs and sends one step.
func (s *Server) runStep(ctx context.Context, pb *playbook.Playbook, step playbook.Step, position int, alert playbook.Alert, actor, runID string) storepg.PlaybookRunStep {
	at := time.Now().UTC()
	out := storepg.PlaybookRunStep{
		Position: position, StepID: step.ID, CommandType: step.Command, At: at,
	}
	record := func() storepg.PlaybookRunStep {
		if s.pg != nil {
			if err := s.pg.RecordPlaybookStep(ctx, runID, out); err != nil {
				s.log.Warn("record playbook step", "err", err)
			}
		}
		return out
	}

	bound, err := playbook.Bind(step.Payload, alert)
	if err != nil {
		out.Status, out.Detail = "failed", err.Error()
		return record()
	}
	payload, err := json.Marshal(bound)
	if err != nil {
		out.Status, out.Detail = "failed", err.Error()
		return record()
	}
	if len(bound) == 0 {
		payload = []byte("{}")
	}
	// The command's own payload rules run again here: a bound value is not
	// known until now, so validating only at load would check a template
	// rather than the thing that will be signed.
	if err := validateCommandPayload(step.Command, payload); err != nil {
		out.Status, out.Detail = "failed", err.Error()
		return record()
	}

	polReq := policy.Request{
		Actor: actor, Role: "admin", CommandType: step.Command,
		DeviceID: alert.DeviceID, Hostname: alert.Hostname, At: at,
		Approvals: []string{actor},
	}
	if s.pg != nil {
		if classes, err := s.pg.DeviceClasses(ctx, alert.DeviceID); err == nil {
			polReq.HostClasses = classes
		}
		if bg, err := s.pg.ActiveBreakGlass(ctx, at); err == nil {
			polReq.BreakGlass = bg
		}
	}

	decision, err := s.authorise(ctx, polReq)
	if err != nil {
		out.Status, out.Detail = "failed", err.Error()
		return record()
	}

	switch decision.Effect {
	case policy.EffectDeny:
		s.recordDecision(ctx, polReq, decision, "")
		out.Status, out.Detail = "denied", decision.Reason
		return record()

	case policy.EffectRequireApproval:
		// A step needing a second person pauses the run rather than being
		// skipped. Skipping would quietly turn a four-step response into a
		// three-step one, and the missing step is the dangerous one.
		pending, err := s.createPendingCommand(ctx, polReq, decision, payload)
		if err != nil {
			out.Status, out.Detail = "failed", err.Error()
			return record()
		}
		s.recordDecision(ctx, polReq, decision, "")
		out.Status, out.PendingID = "awaiting-approval", pending.ID
		out.Detail = fmt.Sprintf(
			"Needs %d approvals and has %d. The run stopped here; approve it to continue.",
			decision.RequiredApprovals, len(pending.Approvals))
		return record()
	}

	id, err := newDeviceID()
	if err != nil {
		out.Status, out.Detail = "failed", err.Error()
		return record()
	}
	env := sign.Envelope{
		DeviceID: alert.DeviceID, CommandID: id, Type: step.Command,
		IssuedUnix: at.Unix(), ExpiresUnix: at.Add(2 * time.Minute).Unix(),
		Payload: payload,
	}
	signature := s.signer.Sign(env)
	s.recordDecision(ctx, polReq, decision, id)

	rec := cmdlog.Record{
		ID: id, DeviceID: alert.DeviceID, Hostname: alert.Hostname,
		Type: step.Command, Payload: string(payload),
		Status: "queued", Message: "queued by playbook " + pb.ID,
		CreatedAt: at.Format(time.RFC3339), UpdatedAt: at.Format(time.RFC3339),
		Signature:    base64.StdEncoding.EncodeToString(signature),
		SigningKeyID: s.signer.KeyID(),
		IssuedUnix:   env.IssuedUnix, ExpiresUnix: env.ExpiresUnix,
		ActorIdentity: actor,
	}
	if err := s.commands.Append(rec); err != nil {
		out.Status, out.Detail = "failed", err.Error()
		return record()
	}
	s.syncCommand(rec)
	s.audit(actor, "command_issue", alert.DeviceID, map[string]any{
		"type": step.Command, "commandId": id,
		"playbookId": pb.ID, "runId": runID, "stepId": step.ID,
	})
	if s.pushSigned(env, signature) {
		_ = s.commands.Update(id, func(r *cmdlog.Record) {
			r.Status = "sent"
			r.Message = "signed command pushed on mTLS stream"
		})
	}
	out.Status, out.CommandID = "issued", id
	return record()
}

// maybeAutorun considers a finding against the automatic playbooks.
//
// Three independent gates have to agree before anything happens: the playbook
// opts in, the trigger matches, and policy permits each step. Any one of them
// refusing stops it, which is what makes "automatic" safe to offer at all —
// the human confirmation is replaced by policy, not removed.
func (s *Server) maybeAutorun(alert playbook.Alert, hostClasses []string) {
	if s.playbooks == nil || s.pg == nil {
		return
	}
	for _, pb := range s.playbooks.All() {
		if !pb.Automatic || !pb.Matches(alert, hostClasses) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		n, err := s.pg.CountRecentAutomaticRuns(ctx, pb.ID, alert.DeviceID, time.Now().UTC().Add(-autoRunCooldown))
		if err != nil {
			s.log.Warn("count automatic runs", "err", err, "playbook", pb.ID)
			cancel()
			continue
		}
		if n > 0 {
			// Suppressed rather than silent: an operator needs to know a
			// response did not fire, and why.
			s.log.Info("automatic playbook suppressed by cooldown",
				"playbook", pb.ID, "device", alert.DeviceID, "recentRuns", n)
			s.audit("system:automatic-response", "playbook_autorun_suppressed", alert.DeviceID, map[string]any{
				"playbookId": pb.ID, "alertId": alert.ID, "recentRuns": n,
				"reason": "an automatic run of this playbook already happened on this host within the cooldown",
			})
			cancel()
			continue
		}
		if _, err := s.runPlaybook(ctx, pb, alert, "system:automatic-response", "automatic"); err != nil {
			s.log.Error("automatic playbook run", "err", err, "playbook", pb.ID)
		}
		cancel()
	}
}
