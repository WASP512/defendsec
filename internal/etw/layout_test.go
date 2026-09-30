package etw

import (
	"encoding/binary"
	"runtime"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// Sizes of the Win32 structures on x64, from the Windows SDK. A wrong field
// here would corrupt every call into advapi32, and this is the only place it
// can be caught without a Windows machine.
func TestStructureSizesMatchTheSDK(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("sizes are for 64-bit targets")
	}
	for name, got := range map[string]uintptr{
		"EVENT_TRACE_PROPERTIES": unsafe.Sizeof(traceProperties{}),
		"EVENT_TRACE_LOGFILEW":   unsafe.Sizeof(traceLogfile{}),
		"TRACE_LOGFILE_HEADER":   unsafe.Sizeof(traceLogfileHeader{}),
		"TIME_ZONE_INFORMATION":  unsafe.Sizeof(timeZoneInformation{}),
		"EVENT_TRACE":            unsafe.Sizeof(eventTrace{}),
		"EVENT_HEADER":           unsafe.Sizeof(eventHeader{}),
		"EVENT_RECORD":           unsafe.Sizeof(eventRecord{}),
	} {
		want := map[string]uintptr{
			"EVENT_TRACE_PROPERTIES": 120, "EVENT_TRACE_LOGFILEW": 448,
			"TRACE_LOGFILE_HEADER": 280, "TIME_ZONE_INFORMATION": 172,
			"EVENT_TRACE": 88, "EVENT_HEADER": 80, "EVENT_RECORD": 112,
		}[name]
		if got != want {
			t.Errorf("%s is %d bytes, want %d", name, got, want)
		}
	}
	if off := unsafe.Offsetof(eventRecord{}.UserData); off != 96 {
		t.Errorf("EVENT_RECORD.UserData at %d, want 96", off)
	}
	if off := unsafe.Offsetof(traceLogfile{}.EventRecordCallback); off != 424 {
		t.Errorf("EVENT_TRACE_LOGFILEW.EventRecordCallback at %d, want 424", off)
	}
}

func startPayload(pid, ppid uint32, image string, trailing ...byte) []byte {
	b := make([]byte, 24)
	le := binary.LittleEndian
	le.PutUint32(b[0:], pid)
	le.PutUint64(b[4:], 133000000000000000)
	le.PutUint32(b[12:], ppid)
	le.PutUint32(b[16:], 1)
	for _, u := range utf16.Encode([]rune(image)) {
		b = le.AppendUint16(b, u)
	}
	b = append(b, 0, 0)
	return append(b, trailing...)
}

func TestParseProcessStart(t *testing.T) {
	img := `\Device\HarddiskVolume3\Windows\System32\cmd.exe`
	ps, err := ParseProcessStart(startPayload(4242, 1000, img, 1, 2, 3, 4, 5, 6, 7, 8))
	if err != nil {
		t.Fatal(err)
	}
	if ps.PID != 4242 || ps.PPID != 1000 || ps.SessionID != 1 || ps.ImageName != img {
		t.Errorf("%+v", ps)
	}
	if _, err := ParseProcessStart(make([]byte, 10)); err == nil {
		t.Error("short payload must fail")
	}
	// Unterminated name: take what is there.
	raw := startPayload(1, 2, "abc")
	ps, err = ParseProcessStart(raw[:len(raw)-2])
	if err != nil || ps.ImageName != "abc" {
		t.Errorf("unterminated: %+v %v", ps, err)
	}
}

func TestDOSPath(t *testing.T) {
	dev := map[string]string{`\Device\HarddiskVolume3`: "C:"}
	if got := DOSPath(`\Device\HarddiskVolume3\Windows\notepad.exe`, dev); got != `C:\Windows\notepad.exe` {
		t.Error(got)
	}
	if got := DOSPath(`\Device\HarddiskVolume30\x.exe`, dev); got != `\Device\HarddiskVolume30\x.exe` {
		t.Error("prefix must end at a path separator:", got)
	}
}
