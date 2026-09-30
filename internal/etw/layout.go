// Package etw consumes process-start events from Event Tracing for Windows
// (roadmap 5.1), so a Windows host sees every execution rather than the ones
// a poller happens to sample.
//
// # What is verified where
//
// The structures below mirror the Win32 definitions and their sizes are
// asserted in tests on amd64, which catches a misplaced field without a
// Windows machine. The payload parser is pure and tested against synthetic
// records built to the provider's manifest. The session code that calls
// advapi32 compiles for Windows in CI but has not been exercised on a
// Windows host by DefendSec's tests; the agent therefore enables it only
// when DEFENDSEC_ETW=1 is set, and falls back to the process-table poller on
// any error.
package etw

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unsafe"
)

// KernelProcessProvider is Microsoft-Windows-Kernel-Process.
var KernelProcessProvider = GUID{0x22FB2CD6, 0x0E7B, 0x422B, [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}

// KeywordProcess is WINEVENT_KEYWORD_PROCESS on that provider.
const KeywordProcess = 0x10

// EventProcessStart is the provider's ProcessStart event id.
const EventProcessStart = 1

// GUID matches the Win32 GUID layout.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// wnodeHeader is WNODE_HEADER.
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              GUID
	ClientContext     uint32
	Flags             uint32
}

// traceProperties is EVENT_TRACE_PROPERTIES.
type traceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceHeader is EVENT_TRACE_HEADER.
type eventTraceHeader struct {
	Size          uint16
	FieldTypeFlag uint16
	Version       uint32
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	GUID          GUID
	ProcessorTime uint64
}

// eventTrace is EVENT_TRACE.
type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

// systemTime is SYSTEMTIME.
type systemTime struct {
	Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds uint16
}

// timeZoneInformation is TIME_ZONE_INFORMATION.
type timeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate systemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate systemTime
	DaylightBias int32
}

// traceLogfileHeader is TRACE_LOGFILE_HEADER.
type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGUID    GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           timeZoneInformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// traceLogfile is EVENT_TRACE_LOGFILEW.
type traceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// eventDescriptor is EVENT_DESCRIPTOR.
type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// eventHeader is EVENT_HEADER.
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      GUID
}

// eventRecord is EVENT_RECORD.
type eventRecord struct {
	EventHeader       eventHeader
	ProcessorNumber   uint8
	Alignment         uint8
	LoggerID          uint16
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          unsafe.Pointer
	UserContext       uintptr
}

// ProcessStart is the part of a ProcessStart event the sensor uses.
type ProcessStart struct {
	PID        uint32
	PPID       uint32
	CreateTime uint64
	SessionID  uint32
	// ImageName is an NT device path, e.g.
	// \Device\HarddiskVolume3\Windows\System32\cmd.exe.
	ImageName string
}

// ErrShortRecord is returned for a payload too small to be a ProcessStart.
var ErrShortRecord = errors.New("etw: process start payload too short")

// ParseProcessStart decodes a ProcessStart payload. Every manifest version
// (0 to 4) begins ProcessID, CreateTime, ParentProcessID, SessionID, Flags,
// ImageName; later fields are ignored, so a newer version still parses.
func ParseProcessStart(data []byte) (ProcessStart, error) {
	const fixed = 4 + 8 + 4 + 4 + 4
	if len(data) < fixed+2 {
		return ProcessStart{}, ErrShortRecord
	}
	le := binary.LittleEndian
	ps := ProcessStart{
		PID:        le.Uint32(data[0:]),
		CreateTime: le.Uint64(data[4:]),
		PPID:       le.Uint32(data[12:]),
		SessionID:  le.Uint32(data[16:]),
	}
	var units []uint16
	for i := fixed; i+1 < len(data); i += 2 {
		u := le.Uint16(data[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	ps.ImageName = string(utf16.Decode(units))
	return ps, nil
}

// DOSPath maps an NT device path onto a drive letter using a table of
// device → drive ("\Device\HarddiskVolume3" → "C:"). A path on no mapped
// device is returned unchanged rather than guessed at.
func DOSPath(nt string, devices map[string]string) string {
	for dev, drive := range devices {
		if strings.HasPrefix(strings.ToLower(nt), strings.ToLower(dev)+`\`) {
			return drive + nt[len(dev):]
		}
	}
	return nt
}
