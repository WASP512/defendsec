//go:build linux

package hostinv

import (
	"os"

	"golang.org/x/sys/unix"
)

// memKeyring returns a seekable, anonymous in-memory file holding data, for
// gpgv to read as a keyring. gpgv cannot read a pipe (it reports every key as
// missing), and writing the dearmored key to disk would put a file on the host;
// a memfd is neither. The caller closes it.
func memKeyring(data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("defendsec-keyring", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "defendsec-keyring")
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
