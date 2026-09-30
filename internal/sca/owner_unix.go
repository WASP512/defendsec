//go:build !windows

package sca

import (
	"os"
	"syscall"
)

type ownership struct{ Uid, Gid uint32 }

func fileOwner(info os.FileInfo) (ownership, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ownership{}, false
	}
	return ownership{Uid: st.Uid, Gid: st.Gid}, true
}
