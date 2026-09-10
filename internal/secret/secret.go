package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func Resolve(explicit, storeJSONPath string) (string, error) {
	if s := strings.TrimSpace(explicit); s != "" {
		return s, nil
	}
	if s := strings.TrimSpace(os.Getenv("DEFENDSEC_ENROLL_SECRET")); s != "" {
		return s, nil
	}
	raw, err := os.ReadFile(storeJSONPath)
	if err != nil {
		return "", fmt.Errorf("read enroll secret: %w", err)
	}
	var doc struct {
		EnrollSecret string `json:"enrollSecret"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("parse defendsec.json: %w", err)
	}
	if strings.TrimSpace(doc.EnrollSecret) == "" {
		return "", fmt.Errorf("enroll secret missing in %s", storeJSONPath)
	}
	return doc.EnrollSecret, nil
}
