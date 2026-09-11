package migrations

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsContainRequiredSchema(t *testing.T) {
	names, err := fs.Glob(files, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 4 {
		t.Fatalf("embedded migrations = %v, want 4 files", names)
	}

	var schema strings.Builder
	for _, name := range names {
		body, err := files.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		schema.Write(body)
	}
	for _, relation := range []string{"meta", "devices", "audit_log", "advisories", "alerts", "saved_queries"} {
		if !strings.Contains(schema.String(), "CREATE TABLE IF NOT EXISTS "+relation) {
			t.Errorf("embedded migrations do not create %s", relation)
		}
	}
}
