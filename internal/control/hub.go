package control

import (
	"sync"

	defendsecv1 "defendsec/internal/gen/defendsec/v1"
)

type Hub struct {
	mu      sync.Mutex
	streams map[string]chan *defendsecv1.ServerToAgent
}

func NewHub() *Hub {
	return &Hub{streams: map[string]chan *defendsecv1.ServerToAgent{}}
}

func (h *Hub) Register(id string) chan *defendsecv1.ServerToAgent {
	ch := make(chan *defendsecv1.ServerToAgent, 16)
	h.mu.Lock()
	h.streams[id] = ch
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unregister(id string, ch chan *defendsecv1.ServerToAgent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streams[id] == ch {
		delete(h.streams, id)
	}
}

func (h *Hub) Send(id string, msg *defendsecv1.ServerToAgent) bool {
	if h == nil {
		// No hub means no connected agents, which is the same answer as an
		// agent that is not connected: false. Returned rather than
		// dereferenced because Send runs on the command-issuing path, and a
		// panic there takes the control plane down — the one thing worse than
		// a command that cannot be delivered.
		return false
	}
	h.mu.Lock()
	ch, ok := h.streams[id]
	h.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- msg:
		return true
	default:
		return false
	}
}

func (h *Hub) Connected(id string) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.streams[id]
	return ok
}
