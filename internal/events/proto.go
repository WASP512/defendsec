package events

import (
	"time"

	defendsecv1 "defendsec/internal/gen/defendsec/v1"
)

// Conversion between the event model and the wire format.
//
// Fields cross the wire as strings, with multi-valued attributes in a separate
// map. The alternative — a protobuf message per event kind — would mean a
// protocol change every time a sensor learns a new field, and every rule that
// wants that field would wait for a release on both sides.

// ToProto renders an event for transmission.
func (e *Event) ToProto() *defendsecv1.BehaviourEvent {
	out := &defendsecv1.BehaviourEvent{
		Id:         e.ID,
		Kind:       string(e.Kind),
		AtUnixNano: e.At.UnixNano(),
		Pid:        e.PID,
		Ppid:       e.PPID,
		Fields:     map[string]string{},
	}
	for name, value := range e.Fields {
		switch value.(type) {
		case []string, []any:
			values := Values(value)
			if out.RepeatedFields == nil {
				out.RepeatedFields = map[string]*defendsecv1.RepeatedValue{}
			}
			out.RepeatedFields[name] = &defendsecv1.RepeatedValue{Values: values}
		default:
			out.Fields[name] = toString(value)
		}
	}
	return out
}

// FromProto rebuilds an event.
//
// DeviceID is supplied by the caller rather than trusted from the wire: the
// server knows which mTLS identity sent the batch, and an agent that could
// name any device id could attribute its events to another host.
func FromProto(in *defendsecv1.BehaviourEvent, deviceID, hostname string) *Event {
	if in == nil {
		return nil
	}
	e := &Event{
		ID: in.Id, DeviceID: deviceID, Hostname: hostname,
		Kind: Kind(in.Kind), At: time.Unix(0, in.AtUnixNano).UTC(),
		PID: in.Pid, PPID: in.Ppid,
	}
	for name, value := range in.Fields {
		e.Set(name, value)
	}
	for name, value := range in.RepeatedFields {
		if value != nil && len(value.Values) > 0 {
			e.Set(name, value.Values)
		}
	}
	return e
}

// BatchToProto renders a drained batch.
func BatchToProto(b Batch, sensorName string) *defendsecv1.EventBatch {
	out := &defendsecv1.EventBatch{
		DroppedSinceLast: b.DroppedSinceLast,
		DroppedTotal:     b.DroppedTotal,
		Sensor:           sensorName,
	}
	for _, e := range b.Events {
		out.Events = append(out.Events, e.ToProto())
	}
	return out
}
