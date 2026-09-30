package proclist

import (
	"encoding/binary"
	"strings"
)

// parseProcArgs2 decodes macOS's kern.procargs2: a little-endian argc, the
// executable path, NUL padding, then argc NUL-terminated arguments (followed
// by the environment, which is ignored). Kept platform-neutral so it is
// tested everywhere.
func parseProcArgs2(raw []byte) string {
	if len(raw) < 4 {
		return ""
	}
	argc := int(binary.LittleEndian.Uint32(raw))
	rest := raw[4:]
	// Skip the exec path and its padding.
	i := 0
	for i < len(rest) && rest[i] != 0 {
		i++
	}
	for i < len(rest) && rest[i] == 0 {
		i++
	}
	var args []string
	for len(args) < argc && i < len(rest) {
		j := i
		for j < len(rest) && rest[j] != 0 {
			j++
		}
		args = append(args, string(rest[i:j]))
		i = j + 1
	}
	return strings.Join(args, " ")
}
