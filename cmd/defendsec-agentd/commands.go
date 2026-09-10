package main

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"defendsec/internal/agentcmd"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/sign"
)

type replayCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newReplay() *replayCache {
	return &replayCache{seen: map[string]struct{}{}}
}

func (c *replayCache) remember(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[id]; ok {
		return false
	}
	c.seen[id] = struct{}{}
	if len(c.seen) > 256 {
		c.seen = map[string]struct{}{id: {}}
	}
	return true
}

func executeCommand(log *slog.Logger, pub ed25519.PublicKey, deviceID, stateDir string, replay *replayCache, cmd *defendsecv1.ControlCommand) *defendsecv1.CommandAck {
	ack := &defendsecv1.CommandAck{CommandId: cmd.GetCommandId(), Accepted: false}
	if cmd.GetDeviceId() != "" && cmd.GetDeviceId() != deviceID {
		ack.Message = "command device_id does not match this agent"
		return ack
	}
	env := sign.Envelope{
		DeviceID:    cmd.GetDeviceId(),
		CommandID:   cmd.GetCommandId(),
		Type:        cmd.GetType(),
		IssuedUnix:  cmd.GetIssuedUnix(),
		ExpiresUnix: cmd.GetExpiresUnix(),
		Payload:     cmd.GetPayload(),
	}
	if env.DeviceID == "" {
		env.DeviceID = deviceID
	}
	if err := sign.Verify(pub, env, cmd.GetSignature(), time.Now()); err != nil {
		ack.Message = err.Error()
		log.Warn("rejected command", "id", cmd.GetCommandId(), "err", err)
		return ack
	}
	if !replay.remember(cmd.GetCommandId()) {
		ack.Message = "replayed command id"
		return ack
	}
	switch cmd.GetType() {
	case agentcmd.TypeIsolate:
		st, err := agentcmd.Isolate(stateDir)
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		ack.Accepted = true
		ack.Message = st.Message
		if st.Isolated {
			ack.Message = "isolated: " + st.Message
		}
	case agentcmd.TypeRelease:
		st, err := agentcmd.Release(stateDir)
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		ack.Accepted = true
		ack.Message = st.Message
	case agentcmd.TypeKillProcess:
		p, err := agentcmd.ParseKillPayload(cmd.GetPayload())
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		n, err := agentcmd.KillByName(p.Name)
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		ack.Accepted = true
		ack.Message = fmt.Sprintf("signaled %d process(es) named %s", n, p.Name)
	case agentcmd.TypeLiveQuery:
		p, err := agentcmd.ParseLiveQueryPayload(cmd.GetPayload())
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		out, err := agentcmd.RunLiveQuery(p.Query)
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		ack.Accepted = true
		ack.Message = out
	case agentcmd.TypeAgentUpdate:
		p, err := agentcmd.ParseAgentUpdatePayload(cmd.GetPayload())
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		msg, err := agentcmd.StageAgentUpdate(stateDir, p)
		if err != nil {
			ack.Message = err.Error()
			return ack
		}
		ack.Accepted = true
		ack.Message = msg
	default:
		ack.Message = "unknown command type"
	}
	return ack
}
