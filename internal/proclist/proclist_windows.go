package proclist

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// List walks a toolhelp snapshot. Full image paths need a process handle,
// which protected processes refuse even to SYSTEM; those keep the short name
// from the snapshot rather than being dropped.
func List() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var out []Proc
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		name := windows.UTF16ToString(entry.ExeFile[:])
		p := Proc{PID: int32(entry.ProcessID), PPID: int32(entry.ParentProcessID), Name: name, Image: name, UID: -1}
		if h, herr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID); herr == nil {
			buf := make([]uint16, windows.MAX_LONG_PATH)
			size := uint32(len(buf))
			if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
				p.Image = windows.UTF16ToString(buf[:size])
			}
			var created, exited, kernel, user windows.Filetime
			if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
				p.Start = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
			}
			windows.CloseHandle(h)
		}
		out = append(out, p)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, err
	}
	return out, nil
}

// Terminate ends a process. Windows has no SIGTERM; this is the equivalent
// of kill -9, which is why kill_process refuses protected names first.
func Terminate(pid int32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
