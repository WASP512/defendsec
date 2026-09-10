package secret

import (
	"fmt"
	"os"
	"strings"
)

func ResolveAdmin(explicit, tokenPath string) (string, error) {
	if s := strings.TrimSpace(explicit); s != "" {
		return s, nil
	}
	if s := strings.TrimSpace(os.Getenv("KEEL_ADMIN_TOKEN")); s != "" {
		return s, nil
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("admin token: %w", err)
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "", fmt.Errorf("admin token file empty")
	}
	return s, nil
}
