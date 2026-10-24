package secret

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxCredentialFile bounds a credential file: keys and secrets are a few dozen
// characters, and a larger file is the wrong file.
const maxCredentialFile = 4096

// ReadFile reads one credential (an API key or secret) from a file, so the value
// lives in a file with its own permissions and never in an environment variable
// that a process listing or a crash report would show, a settings table or a log.
//
// It refuses a file that is not a regular file, is empty or large, holds more
// than one token, or is writable by group or others. It returns a warning, not an
// error, for a file readable by group or others: the operator should tighten it,
// but a deployment that shares the file with the service account through a group
// is legitimate. The value is never part of an error message.
func ReadFile(path string) (value, warning string, err error) {
	if strings.TrimSpace(path) == "" {
		return "", "", errors.New("no credential file is configured")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("credential file %s: %w", path, unwrapPath(err))
	}
	if !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("credential file %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return "", "", fmt.Errorf("credential file %s is writable by group or others (mode %04o); make it 0600", path, fi.Mode().Perm())
	}
	if fi.Size() == 0 || fi.Size() > maxCredentialFile {
		return "", "", fmt.Errorf("credential file %s is empty or larger than %d bytes", path, maxCredentialFile)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("credential file %s: %w", path, unwrapPath(err))
	}
	v := strings.TrimSpace(string(raw))
	if v == "" || strings.ContainsAny(v, " \t\r\n\x00") {
		return "", "", fmt.Errorf("credential file %s must hold one value and nothing else", path)
	}
	if fi.Mode().Perm()&0o044 != 0 {
		warning = fmt.Sprintf("credential file %s is readable by group or others (mode %04o); 0600 is safer", path, fi.Mode().Perm())
	}
	return v, warning, nil
}

func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
