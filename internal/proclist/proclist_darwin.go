package proclist

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// List reads kern.proc.all. The kernel gives the first 16 bytes of the
// executable name, not its path; the full path needs libproc (cgo), which the
// agent does not link. Image is therefore the short name on macOS, and the
// sensor says so.
func List() ([]Proc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]Proc, 0, len(kps))
	for _, kp := range kps {
		if kp.Proc.P_pid <= 0 {
			continue
		}
		name := unix.ByteSliceToString(kp.Proc.P_comm[:])
		st := kp.Proc.P_starttime
		out = append(out, Proc{
			PID: kp.Proc.P_pid, PPID: kp.Eproc.Ppid,
			Start: uint64(st.Sec)*1_000_000 + uint64(st.Usec),
			Image: name, Name: name, UID: int(kp.Eproc.Ucred.Uid),
		})
	}
	return out, nil
}

// Terminate sends SIGTERM.
func Terminate(pid int32) error { return syscall.Kill(int(pid), syscall.SIGTERM) }
