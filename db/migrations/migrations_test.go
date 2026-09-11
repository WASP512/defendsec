package migrations

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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

func TestApplyCreatesSchema(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for attempt := 0; attempt < 2; attempt++ {
		if err := Apply(ctx, pool); err != nil {
			t.Fatalf("apply attempt %d: %v", attempt+1, err)
		}
	}

	var version string
	if err := pool.QueryRow(ctx, "SELECT value FROM meta WHERE key = 'schema_version'").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "4" {
		t.Fatalf("schema version = %q, want 4", version)
	}
	for _, relation := range []string{"devices", "audit_log", "advisories", "alerts", "saved_queries"} {
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", relation).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("relation %s was not created", relation)
		}
	}
}
