package etw

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

const (
	wnodeFlagTracedGUID         = 0x00020000
	eventTraceRealTimeMode      = 0x00000100
	eventTraceControlStop       = 1
	eventControlCodeEnable      = 1
	traceLevelInformation       = 4
	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000
	errorAlreadyExists          = 183
	invalidProcessTraceHandle   = ^uint64(0)
)

// SessionName is the real-time session the agent owns. A fixed name means a
// session leaked by a crashed agent is found and stopped on the next start,
// rather than accumulating (Windows allows only 64).
const SessionName = "DefendSec-Process"

// Session is a running real-time trace.
type Session struct {
	handle  uint64
	trace   uint64
	name    []uint16
	onStart func(ProcessStart)
	once    sync.Once
}

// current is the session the callback delivers to. ETW calls back on the
// ProcessTrace thread with no user pointer this code can rely on across
// versions, so one session per process is the model.
var (
	currentMu sync.Mutex
	current   *Session
)

var callback = windows.NewCallback(func(rec *eventRecord) uintptr {
	if rec == nil || rec.EventHeader.ProviderID != KernelProcessProvider ||
		rec.EventHeader.EventDescriptor.ID != EventProcessStart || rec.UserData == nil {
		return 0
	}
	data := unsafe.Slice((*byte)(rec.UserData), int(rec.UserDataLength))
	ps, err := ParseProcessStart(data)
	if err != nil {
		return 0
	}
	currentMu.Lock()
	s := current
	currentMu.Unlock()
	if s != nil && s.onStart != nil {
		s.onStart(ps)
	}
	return 0
})

func newProperties(name []uint16) (*traceProperties, []byte) {
	size := unsafe.Sizeof(traceProperties{}) + uintptr(len(name)*2) + 2
	buf := make([]byte, size)
	p := (*traceProperties)(unsafe.Pointer(&buf[0]))
	p.Wnode.BufferSize = uint32(size)
	p.Wnode.Flags = wnodeFlagTracedGUID
	p.Wnode.ClientContext = 1 // QPC timestamps
	var g [16]byte
	_, _ = rand.Read(g[:])
	p.Wnode.GUID = *(*GUID)(unsafe.Pointer(&g[0]))
	p.LogFileMode = eventTraceRealTimeMode
	p.LoggerNameOffset = uint32(unsafe.Sizeof(traceProperties{}))
	return p, buf
}

// Start opens the session and begins delivering ProcessStart events to
// onStart on a dedicated goroutine. It requires administrator or SYSTEM.
func Start(onStart func(ProcessStart)) (*Session, error) {
	currentMu.Lock()
	defer currentMu.Unlock()
	if current != nil {
		return nil, errors.New("etw: a session is already running in this process")
	}
	name, _ := windows.UTF16FromString(SessionName)
	s := &Session{name: name, onStart: onStart}

	props, buf := newProperties(name)
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(props)))
	if r == errorAlreadyExists {
		// Left over from a previous run: stop it and start clean.
		stopByName(name)
		props, buf = newProperties(name)
		r, _, _ = procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(props)))
	}
	runtime.KeepAlive(buf)
	if r != 0 {
		return nil, fmt.Errorf("etw: StartTrace: %w", windows.Errno(r))
	}

	r, _, _ = procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&KernelProcessProvider)),
		eventControlCodeEnable, traceLevelInformation, KeywordProcess, 0, 0, 0)
	if r != 0 {
		stopByName(name)
		return nil, fmt.Errorf("etw: EnableTraceEx2: %w", windows.Errno(r))
	}

	lf := traceLogfile{
		LoggerName:          &name[0],
		ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: callback,
	}
	th, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&lf)))
	if uint64(th) == invalidProcessTraceHandle {
		stopByName(name)
		return nil, fmt.Errorf("etw: OpenTrace failed")
	}
	s.trace = uint64(th)
	current = s

	go func() {
		// Blocks until the session is stopped or closed.
		procProcessTrace.Call(uintptr(unsafe.Pointer(&s.trace)), 1, 0, 0)
	}()
	return s, nil
}

// Close stops the session.
func (s *Session) Close() error {
	s.once.Do(func() {
		procCloseTrace.Call(uintptr(s.trace))
		stopByName(s.name)
		currentMu.Lock()
		if current == s {
			current = nil
		}
		currentMu.Unlock()
	})
	return nil
}

func stopByName(name []uint16) {
	props, _ := newProperties(name)
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(props)), eventTraceControlStop)
}

// DeviceMap returns the NT device behind each drive letter, for DOSPath.
func DeviceMap() map[string]string {
	out := map[string]string{}
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		d, _ := windows.UTF16PtrFromString(drive)
		n, err := windows.QueryDosDevice(d, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		out[windows.UTF16ToString(buf[:n])] = drive
	}
	return out
}
