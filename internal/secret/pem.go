package secret

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxPEMFile bounds a PEM credential file: a certificate and its RSA key are a
// few kilobytes, and a larger file is the wrong file.
const maxPEMFile = 32 * 1024

// ReadPEMFile reads a PEM credential (a private key, with or without its
// certificate) from a file. It applies the same rules as ReadFile: a regular
// file, not writable by group or others, never an error message that holds the
// content. Unlike ReadFile the content has lines, so it only checks that the
// file looks like PEM; the caller parses it.
//
// It returns a warning, not an error, for a file readable by group or others.
func ReadPEMFile(path string) (data []byte, warning string, err error) {
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
	if fi.Size() == 0 || fi.Size() > maxPEMFile {
		return nil, "", fmt.Errorf("credential file %s is empty or larger than %d bytes", path, maxPEMFile)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("credential file %s: %w", path, unwrapPath(err))
	}
	if !bytes.Contains(raw, []byte("-----BEGIN ")) {
		return nil, "", fmt.Errorf("credential file %s is not a PEM file (no BEGIN line)", path)
	}
	if fi.Mode().Perm()&0o044 != 0 {
		warning = fmt.Sprintf("credential file %s is readable by group or others (mode %04o); 0600 is safer", path, fi.Mode().Perm())
	}
	return raw, warning, nil
}
