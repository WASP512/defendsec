//go:build !windows && !darwin

package proclist

// List is not implemented here; Linux reads /proc directly.
func List() ([]Proc, error) { return nil, ErrUnsupported }

// Terminate is not implemented here.
func Terminate(int32) error { return ErrUnsupported }

// CommandLine is not implemented here.
func CommandLine(int32) string { return "" }
