package sca

import "os"

type ownership struct{ Uid, Gid uint32 }

// fileOwner has no numeric-uid answer on Windows, whose owners are SIDs. A
// file_mode ownership check reports that rather than guessing.
func fileOwner(os.FileInfo) (ownership, bool) { return ownership{}, false }
