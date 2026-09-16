package control

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"defendsec/internal/alertmeta"
	"defendsec/internal/controls"
	"defendsec/internal/events"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/presence"
	"defendsec/internal/sigma"
)

// Behavioural detection (roadmap 3.2-3.5).
//
// Events arrive on the existing mTLS stream, are matched against the loaded
// Sigma rules, and a match becomes an alert carrying the process lineage that
// led to it. That last part is what state-based tools cannot do: by the time a
// file-integrity check notices a change, the process that made it has usually
// exited.

// SetDetection installs the rule engine.
func (s *Server) SetDetection(engine *sigma.Engine) {
	s.detection = engine
	if s.trees == nil {
		s.trees = map[string]*events.Tree{}
	}
}

// DetectionEngine returns the engine, which may be nil.
func (s *Server) DetectionEngine() *sigma.Engine { return s.detection }

// treeFor returns the process tree for a device, creating it on first use.
//
// Server-side rather than agent-side because an alert is raised here, and the
// lineage has to be attached at that moment. Asking the agent for it would
// mean a round trip during alerting, to a host that may be the one under
// attack.
func (s *Server) treeFor(deviceID string) *events.Tree {
	s.treeMu.Lock()
	defer s.treeMu.Unlock()
	if s.trees == nil {
		s.trees = map[string]*events.Tree{}
	}
	tree, ok := s.trees[deviceID]
	if !ok {
		tree = events.NewTree(0, 0)
		s.trees[deviceID] = tree
	}
	return tree
}

// eventGap records what a device has lost, so the console can say so.
type eventGap struct {
	DroppedTotal uint64    `json:"droppedTotal"`
	LastGap      uint64    `json:"lastGap,omitempty"`
	LastGapAt    time.Time `json:"lastGapAt,omitempty"`
	Received     uint64    `json:"received"`
	LastEventAt  time.Time `json:"lastEventAt,omitempty"`
	Sensor       string    `json:"sensor,omitempty"`
}

// HandleEventBatch processes a batch from an agent.
func (s *Server) HandleEventBatch(deviceID, hostname string, batch *defendsecEventBatch) {
	if batch == nil {
		return
	}

	// The gap is recorded before anything else, because it is the fact most
	// likely to matter later: a clean console during an incident that
	// overwhelmed the pipeline is the worst possible outcome, and the only
	// defence is saying plainly that events were lost.
	if batch.DroppedSinceLast > 0 {
		s.log.Warn("agent dropped events",
			"device", deviceID, "dropped", batch.DroppedSinceLast,
			"total", batch.DroppedTotal, "sensor", batch.Sensor)
		s.audit("system:sensor", "event_gap", deviceID, map[string]any{
			"dropped": batch.DroppedSinceLast, "droppedTotal": batch.DroppedTotal,
			"sensor": batch.Sensor,
			"detail": "The agent's event buffer overflowed. Detections covering this window may be incomplete.",
		})
	}
	s.recordGap(deviceID, batch)

	tree := s.treeFor(deviceID)
	for _, ev := range batch.Events {
		if ev == nil {
			continue
		}
		// Lineage is recorded for every event, not only matching ones: the
		// parent of a process that alerts later is usually itself unremarkable.
		if ev.Kind == events.KindProcess && ev.PID > 0 {
			tree.Observe(ev.PID, ev.PPID,
				ev.String(events.FieldImage), ev.String(events.FieldCommandLine),
				ev.String(events.FieldUser), ev.At)
		}
		s.evaluateEvent(ev, tree)
	}
}

// defendsecEventBatch is the decoded form of a wire batch, so this file does
// not depend on the generated types.
type defendsecEventBatch struct {
	Events           []*events.Event
	DroppedSinceLast uint64
	DroppedTotal     uint64
	Sensor           string
}

func (s *Server) recordGap(deviceID string, batch *defendsecEventBatch) {
	s.treeMu.Lock()
	defer s.treeMu.Unlock()
	if s.gaps == nil {
		s.gaps = map[string]*eventGap{}
	}
	gap, ok := s.gaps[deviceID]
	if !ok {
		gap = &eventGap{}
		s.gaps[deviceID] = gap
	}
	gap.Received += uint64(len(batch.Events))
	gap.DroppedTotal = batch.DroppedTotal
	gap.Sensor = batch.Sensor
	if len(batch.Events) > 0 {
		gap.LastEventAt = batch.Events[len(batch.Events)-1].At
	}
	if batch.DroppedSinceLast > 0 {
		gap.LastGap = batch.DroppedSinceLast
		gap.LastGapAt = time.Now().UTC()
	}
}

// EventGaps reports per-device loss, for the coverage view.
func (s *Server) EventGaps() map[string]eventGap {
	s.treeMu.Lock()
	defer s.treeMu.Unlock()
	out := make(map[string]eventGap, len(s.gaps))
	for id, g := range s.gaps {
		out[id] = *g
	}
	return out
}

// evaluateEvent matches one event and raises alerts for what fires.
func (s *Server) evaluateEvent(ev *events.Event, tree *events.Tree) {
	if s.detection == nil {
		return
	}
	for _, match := range s.detection.Match(ev) {
		s.raiseDetectionAlert(match, tree)
	}
}

// raiseDetectionAlert turns a rule match into an alert with its context.
func (s *Server) raiseDetectionAlert(match sigma.Match, tree *events.Tree) {
	ev := match.Event
	id, err := newDeviceID()
	if err != nil {
		s.log.Warn("allocate detection alert id", "err", err)
		return
	}

	// The process lineage: what ran, what ran it, and what ran that. This is
	// the single thing an analyst needs first, and the thing a state-based
	// tool cannot provide at all.
	ancestry := tree.Ancestry(ev.PID)

	detail := alertmeta.BaseDetail(ev.Hostname)
	detail["rule.title"] = match.RuleTitle
	detail["rule.id"] = match.RuleID
	detail["rule.hash"] = match.RuleHash
	detail["rule.level"] = string(match.Level)
	detail["event.id"] = ev.ID
	detail["event.kind"] = string(ev.Kind)
	detail["attack.techniques"] = match.Techniques
	detail["attack.tactics"] = match.Tactics
	if len(match.FalsePositives) > 0 {
		detail["rule.falsePositives"] = match.FalsePositives
	}
	if match.Description != "" {
		detail["rule.description"] = match.Description
	}
	for name, value := range ev.Fields {
		detail["event."+name] = value
	}
	if len(ancestry) > 0 {
		detail["process.ancestry"] = ancestry
		detail["process.ancestryText"] = renderAncestry(ancestry)
	}

	alert := presence.Alert{
		ID:         id,
		DetectedAt: ev.At.Format(time.RFC3339),
		DeviceID:   ev.DeviceID,
		Hostname:   ev.Hostname,
		Kind:       "detection",
		Severity:   severityFor(match.Level),
		Title:      match.RuleTitle,
		Summary:    ev.Describe(),
		SourceType: "sigma_rule",
		// Keyed on the rule and the process, so the same rule firing
		// repeatedly on one process does not open a new alert each time,
		// while the same rule on a different process does.
		SourceID:         match.RuleID + ":" + fmt.Sprint(ev.PID),
		GeneratorID:      "defendsec.detection",
		GeneratorVersion: alertmeta.GeneratorVersion,
		Detail:           detail,
		Signal:           string(controls.SignalDetection),
		ControlIDs:       controls.Tag(controls.SignalDetection),
	}
	s.recordAlert(alert)

	// A detection can drive a playbook (roadmap 2.6): policy still decides
	// every step, so this widens what can trigger a response without widening
	// what a response may do.
	s.considerAutomaticResponse(alert)
}

// renderAncestry writes the lineage as one line an analyst can read at a
// glance, newest first.
func renderAncestry(chain []events.Ancestor) string {
	parts := make([]string, 0, len(chain))
	for _, a := range chain {
		label := a.Image
		if label == "" {
			label = "(unknown)"
		}
		parts = append(parts, fmt.Sprintf("%s[%d]", label, a.PID))
	}
	return strings.Join(parts, " ← ")
}

// severityFor maps a Sigma level onto DefendSec's alert severities.
func severityFor(level sigma.Level) string {
	switch level {
	case sigma.LevelCritical:
		return "critical"
	case sigma.LevelHigh:
		return "high"
	case sigma.LevelMedium:
		return "medium"
	case sigma.LevelLow:
		return "low"
	default:
		return "low"
	}
}

// DetectionCoverage is the honest coverage matrix (roadmap 3.4).
type DetectionCoverage struct {
	// Loaded describes the rules in force.
	Rules      int                 `json:"rules"`
	Skipped    []sigma.SkippedRule `json:"skipped,omitempty"`
	ByLevel    map[string]int      `json:"byLevel"`
	ByCategory map[string]int      `json:"byCategory"`
	Techniques []string            `json:"techniques"`
	Tactics    []string            `json:"tactics"`
	// ObservedKinds are the event kinds any agent has actually reported. A
	// rule for a kind nothing produces is a rule that will never fire, and
	// showing coverage without that distinction is the dishonest half.
	ObservedKinds []string `json:"observedKinds"`
	// UnobservedKinds are the ones no agent has reported.
	UnobservedKinds []string `json:"unobservedKinds"`
	// Gaps are per-device event loss.
	Gaps map[string]eventGap `json:"gaps,omitempty"`
	// Caveats say what this does not tell you.
	Caveats []string `json:"caveats"`
}

// DetectionCoverageReport builds the coverage matrix.
func (s *Server) DetectionCoverageReport() DetectionCoverage {
	out := DetectionCoverage{
		ByLevel:    map[string]int{},
		ByCategory: map[string]int{},
		Gaps:       s.EventGaps(),
	}
	if s.detection != nil {
		c := s.detection.Describe()
		out.Rules = c.Rules
		out.Skipped = c.Skipped
		out.ByLevel = c.ByLevel
		out.ByCategory = c.ByCategory
		out.Techniques = c.Techniques
		out.Tactics = c.Tactics
	}

	s.treeMu.Lock()
	observed := map[events.Kind]bool{}
	for kind := range s.observedKinds {
		observed[kind] = true
	}
	s.treeMu.Unlock()

	for _, kind := range events.Kinds() {
		if observed[kind] {
			out.ObservedKinds = append(out.ObservedKinds, string(kind))
		} else {
			out.UnobservedKinds = append(out.UnobservedKinds, string(kind))
		}
	}
	sort.Strings(out.ObservedKinds)
	sort.Strings(out.UnobservedKinds)

	out.Caveats = append(out.Caveats,
		"A technique listed here has at least one rule. It does not mean every way of performing that technique is detected — ATT&CK techniques are broad, and a rule covers a behaviour, not a technique.")
	if len(out.UnobservedKinds) > 0 {
		out.Caveats = append(out.Caveats, fmt.Sprintf(
			"No agent has reported these event kinds: %s. Rules depending on them cannot fire, whatever the technique coverage below says.",
			strings.Join(out.UnobservedKinds, ", ")))
	}
	if len(out.Skipped) > 0 {
		out.Caveats = append(out.Caveats, fmt.Sprintf(
			"%d rules failed to load and are not running. Their reasons are listed; an unimplemented feature is the usual cause.",
			len(out.Skipped)))
	}
	var lostDevices int
	for _, g := range out.Gaps {
		if g.DroppedTotal > 0 {
			lostDevices++
		}
	}
	if lostDevices > 0 {
		out.Caveats = append(out.Caveats, fmt.Sprintf(
			"%d hosts have dropped events because their buffer overflowed. Detection over those windows is incomplete.",
			lostDevices))
	}
	if s.detection == nil {
		out.Caveats = append(out.Caveats,
			"No rules are loaded, so no behavioural detection is running at all. Set DEFENDSEC_SIGMA_DIR.")
	}
	return out
}

// noteObservedKind records that a kind has actually been seen.
func (s *Server) noteObservedKind(kind events.Kind) {
	s.treeMu.Lock()
	defer s.treeMu.Unlock()
	if s.observedKinds == nil {
		s.observedKinds = map[events.Kind]bool{}
	}
	s.observedKinds[kind] = true
}

// receiveEvents decodes a wire batch and processes it.
//
// The device id comes from the mTLS identity of the stream, never from the
// message: an agent that could name any device id could attribute its events
// to another host, and the whole attribution chain would be worthless.
func (s *Server) receiveEvents(deviceID string, batch *defendsecv1.EventBatch) {
	if batch == nil {
		return
	}
	dev, _ := s.store.Get(deviceID)
	decoded := &defendsecEventBatch{
		DroppedSinceLast: batch.GetDroppedSinceLast(),
		DroppedTotal:     batch.GetDroppedTotal(),
		Sensor:           batch.GetSensor(),
	}
	for _, raw := range batch.GetEvents() {
		ev := events.FromProto(raw, deviceID, dev.Hostname)
		if ev == nil {
			continue
		}
		s.noteObservedKind(ev.Kind)
		decoded.Events = append(decoded.Events, ev)
	}
	s.HandleEventBatch(deviceID, dev.Hostname, decoded)
}

// HandleDetectionCoverage serves the honest coverage matrix (roadmap 3.4).
//
// The rare and valuable part of a coverage map is what it says you cannot see.
// A matrix showing only green squares is a marketing asset; one that names the
// event kinds no sensor reports, the rules that failed to load, and the hosts
// that dropped events is something an operator can plan against.
func (s *Server) HandleDetectionCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, s.DetectionCoverageReport())
}
