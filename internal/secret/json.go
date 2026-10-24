package secret

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxJSONFile bounds a JSON credential file: a Google service account key is about
// 2.4 KB, and a larger file is the wrong file.
const maxJSONFile = 16 * 1024

// ReadJSONFile reads a JSON credential (a Google service account key) from a file.
// It applies the same rules as ReadPEMFile: a regular file, not writable by group or
// others, never an error message that holds the content. It only checks that the file
// looks like a JSON object; the caller parses it.
//
// It returns a warning, not an error, for a file readable by group or others.
func ReadJSONFile(path string) (data []byte, warning string, err error) {
	if strings.TrimSpace(path) == "" {
		return nil, "", errors.New("no credential file is configured")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("credential file %s: %w", path, unwrapPath(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, "", fmt.Errorf("credential file %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, "", fmt.Errorf("credential file %s is writable by group or others (mode %04o); make it 0600", path, fi.Mode().Perm())
	}
	if fi.Size() == 0 || fi.Size() > maxJSONFile {
		return nil, "", fmt.Errorf("credential file %s is empty or larger than %d bytes", path, maxJSONFile)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("credential file %s: %w", path, unwrapPath(err))
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, "", fmt.Errorf("credential file %s is not a JSON object", path)
	}
	if fi.Mode().Perm()&0o044 != 0 {
		warning = fmt.Sprintf("credential file %s is readable by group or others (mode %04o); 0600 is safer", path, fi.Mode().Perm())
	}
	return raw, warning, nil
}
