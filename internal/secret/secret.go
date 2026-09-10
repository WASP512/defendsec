package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func Resolve(explicit, keelJSONPath string) (string, error) {
	if s := strings.TrimSpace(explicit); s != "" {
		return s, nil
	}
	if s := strings.TrimSpace(os.Getenv("KEEL_ENROLL_SECRET")); s != "" {
		return s, nil
	}
	raw, err := os.ReadFile(keelJSONPath)
	if err != nil {
		return "", fmt.Errorf("read enroll secret: %w", err)
	}
	var doc struct {
		EnrollSecret string `json:"enrollSecret"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("parse keel.json: %w", err)
	}
	if strings.TrimSpace(doc.EnrollSecret) == "" {
		return "", fmt.Errorf("enroll secret missing in %s", keelJSONPath)
	}
	return doc.EnrollSecret, nil
}
