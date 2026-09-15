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
	// Pin the exact set rather than a count, so a migration that is renamed
	// or dropped fails loudly instead of being replaced by a new one.
	want := []string{
		"001_init.sql",
		"002_alerts.sql",
		"003_saved_queries.sql",
		"004_alert_provenance.sql",
		"005_command_proof.sql",
		"006_audit_chain.sql",
		"007_ack_proof.sql",
	}
	if len(names) != len(want) {
		t.Fatalf("embedded migrations = %v, want %v", names, want)
	}
	for i, name := range want {
		if names[i] != name {
			t.Fatalf("embedded migrations = %v, want %v", names, want)
		}
	}

	var schema strings.Builder
	for _, name := range names {
		body, err := files.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		schema.Write(body)
	}
	for _, relation := range []string{"meta", "devices", "audit_log", "advisories", "alerts", "saved_queries", "audit_checkpoints"} {
		if !strings.Contains(schema.String(), "CREATE TABLE IF NOT EXISTS "+relation) {
			t.Errorf("embedded migrations do not create %s", relation)
		}
	}

	// Phase 1 proof columns. These carry the signature and chain that make a
	// stored record verifiable rather than merely asserted.
	for _, col := range []string{"signature", "signing_key_id", "issued_unix", "expires_unix", "actor_identity"} {
		if !strings.Contains(schema.String(), "ALTER TABLE commands ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("embedded migrations do not add commands.%s", col)
		}
	}
	for _, col := range []string{"seq", "prev_hash", "entry_hash"} {
		if !strings.Contains(schema.String(), "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("embedded migrations do not add audit_log.%s", col)
		}
	}
	// Phase 1.3 acknowledgement proof.
	for _, col := range []string{"ack_signature", "ack_result_hash", "ack_executed_unix", "ack_verified"} {
		if !strings.Contains(schema.String(), "ALTER TABLE commands ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("embedded migrations do not add commands.%s", col)
		}
	}
	if !strings.Contains(schema.String(), "ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_public_key_pem") {
		t.Error("embedded migrations do not add devices.agent_public_key_pem")
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
