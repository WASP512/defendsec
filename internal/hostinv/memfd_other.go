//go:build !linux

package hostinv

import (
	"errors"
	"os"
)

func memKeyring([]byte) (*os.File, error) {
	return nil, errors.New("in-memory keyrings need Linux")
}
