package migrations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Tests for 019_advisory_ranges.sql against a real Postgres. Each test makes
// its own throwaway database from TEST_DATABASE_URL so it can start from an
// empty schema, or from the schema as it stood before 019.

func tempDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name := "defendsec_mig_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") //nolint:errcheck
		admin.Close()
	})
	return pool
}

// applyBefore applies every embedded migration whose name sorts before stop,
// in order, as Apply would: the schema as an existing install has it.
func applyBefore(t *testing.T, pool *pgxpool.Pool, stop string) {
	t.Helper()
	names, err := fs.Glob(files, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name >= stop {
			break
		}
		body, err := files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestAdvisoryRangesFreshDatabase(t *testing.T) {
	pool := tempDatabase(t)
	ctx := context.Background()
	for attempt := 1; attempt <= 2; attempt++ {
		if err := Apply(ctx, pool); err != nil {
			t.Fatalf("apply attempt %d: %v", attempt, err)
		}
	}
	for _, idx := range []string{"advisory_ranges_distro_idx", "advisory_ranges_package_idx", "advisory_ranges_identity_idx"} {
		if count(t, pool, "SELECT count(*) FROM pg_indexes WHERE indexname = $1", idx) != 1 {
			t.Errorf("index %s missing", idx)
		}
	}
	if n := count(t, pool, "SELECT count(*) FROM advisory_ranges"); n != 0 {
		t.Errorf("fresh database has %d ranges, want 0", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM feed_snapshots"); n != 0 {
		t.Errorf("fresh database has %d snapshots, want 0", n)
	}
}

func TestAdvisoryRangesUpgradeKeepsExistingAdvisories(t *testing.T) {
	pool := tempDatabase(t)
	ctx := context.Background()

	// An install at 018 with legacy single-floor rows, written the old way.
	applyBefore(t, pool, "019")
	if _, err := pool.Exec(ctx, `
		INSERT INTO advisories (id, cve, package, below, severity, summary, source) VALUES
		  ('osv-1', 'CVE-2022-0001', 'openssl', '1.1.1k', 'high', 'one', 'osv'),
		  ('osv-2', 'CVE-2022-0002', 'openssl', '3.0.2',  'critical', 'two', 'osv'),
		  ('osv-3', 'CVE-2022-0003', 'curl',    '',       'low', 'no floor', 'local')`); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt <= 3; attempt++ { // re-runs must not duplicate
		if err := Apply(ctx, pool); err != nil {
			t.Fatalf("apply attempt %d: %v", attempt, err)
		}
		if n := count(t, pool, "SELECT count(*) FROM advisories"); n != 3 {
			t.Fatalf("attempt %d: advisories = %d, want 3 (rows must survive)", attempt, n)
		}
		if n := count(t, pool, "SELECT count(*) FROM advisory_ranges"); n != 2 {
			t.Fatalf("attempt %d: ranges = %d, want 2 (osv-3 has no floor to mirror)", attempt, n)
		}
	}

	// Each old (package, below) became one distro-less 'fixed' range.
	rows, err := pool.Query(ctx, `
		SELECT advisory_id, package, fixed, fix_state, ecosystem, distro IS NULL, release IS NULL, introduced IS NULL
		FROM advisory_ranges ORDER BY advisory_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]string{"osv-1": "1.1.1k", "osv-2": "3.0.2"}
	seen := 0
	for rows.Next() {
		var id, pkg, fixed, state, eco string
		var noDistro, noRelease, noIntroduced bool
		if err := rows.Scan(&id, &pkg, &fixed, &state, &eco, &noDistro, &noRelease, &noIntroduced); err != nil {
			t.Fatal(err)
		}
		if want[id] != fixed || pkg != "openssl" || state != "fixed" || eco != "legacy" || !noDistro || !noRelease || !noIntroduced {
			t.Errorf("range for %s = pkg %s fixed %s state %s eco %s distroNULL %v releaseNULL %v introducedNULL %v",
				id, pkg, fixed, state, eco, noDistro, noRelease, noIntroduced)
		}
		seen++
	}
	if seen != 2 {
		t.Fatalf("saw %d ranges, want 2", seen)
	}

	// New columns default sensibly on the old rows, and the legacy columns are untouched.
	var kev bool
	var cwe []string
	var epss *float64
	var snapshot *int64
	var below string
	if err := pool.QueryRow(ctx, `SELECT kev, cwe, epss, snapshot_id, below FROM advisories WHERE id = 'osv-1'`).
		Scan(&kev, &cwe, &epss, &snapshot, &below); err != nil {
		t.Fatal(err)
	}
	if kev || len(cwe) != 0 || epss != nil || snapshot != nil || below != "1.1.1k" {
		t.Errorf("osv-1 new columns = kev %v cwe %v epss %v snapshot %v below %q", kev, cwe, epss, snapshot, below)
	}

	// The old writer (scripts/ingest-osv.py's upsert) keeps working and the
	// mirrored range follows it.
	if _, err := pool.Exec(ctx, `
		INSERT INTO advisories (id, cve, package, below, severity, summary, source, updated_at)
		VALUES ('osv-1', 'CVE-2022-0001', 'openssl', '1.1.1n', 'high', 'one', 'osv', now())
		ON CONFLICT (id) DO UPDATE SET cve=EXCLUDED.cve, package=EXCLUDED.package, below=EXCLUDED.below,
		  severity=EXCLUDED.severity, summary=EXCLUDED.summary, source=EXCLUDED.source, updated_at=now()`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, "SELECT count(*) FROM advisory_ranges WHERE advisory_id = 'osv-1' AND fixed = '1.1.1n'"); n != 1 {
		t.Errorf("mirrored range did not follow the legacy upsert (matching ranges = %d)", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM advisory_ranges WHERE advisory_id = 'osv-1'"); n != 1 {
		t.Errorf("osv-1 has %d ranges after legacy upsert, want 1", n)
	}

	// Deleting an advisory removes its ranges.
	if _, err := pool.Exec(ctx, `DELETE FROM advisories WHERE id = 'osv-2'`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, "SELECT count(*) FROM advisory_ranges WHERE advisory_id = 'osv-2'"); n != 0 {
		t.Errorf("ranges of a deleted advisory remain: %d", n)
	}
}

func TestAdvisoryRangesConstraints(t *testing.T) {
	pool := tempDatabase(t)
	ctx := context.Background()
	if err := Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisories (id, severity) VALUES ('c-1', 'high')`); err != nil {
		t.Fatalf("an advisory with only id and severity must insert (package/below default to ''): %v", err)
	}
	const ins = `INSERT INTO advisory_ranges (advisory_id, package, fix_state, fixed) VALUES ('c-1', 'p', $1, $2)`
	if _, err := pool.Exec(ctx, ins, "affected", nil); err != nil {
		t.Fatalf("valid affected range rejected: %v", err)
	}
	for _, c := range []struct {
		name, state string
		fixed       any
	}{
		{"unknown fix_state", "patched", nil},
		{"fixed without a version", "fixed", nil},
	} {
		if _, err := pool.Exec(ctx, ins, c.state, c.fixed); err == nil {
			t.Errorf("%s accepted", c.name)
		}
	}
	for _, state := range []string{"fixed", "will_not_fix", "not_affected", "under_investigation"} {
		// A distinct package per state: identical bounds with different states
		// is a contradiction the identity index rightly refuses.
		if _, err := pool.Exec(ctx, `INSERT INTO advisory_ranges (advisory_id, package, fix_state, fixed, release, distro)
			VALUES ('c-1', 'q-' || $1::text, $1, CASE WHEN $1 = 'fixed' THEN '1' END, '9', 'rocky')`, state); err != nil {
			t.Errorf("fix_state %s rejected: %v", state, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_ranges (advisory_id, package, fix_state, release, distro)
		VALUES ('c-1', 'q-will_not_fix', 'affected', '9', 'rocky')`); err == nil {
		t.Error("same bounds with a different fix_state accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_ranges (advisory_id, package, fix_state) VALUES ('c-1', 'p', 'affected')`); err == nil {
		t.Error("identical range accepted twice (unique identity index missing)")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO advisory_ranges (advisory_id, package, fix_state) VALUES ('nope', 'p', 'affected')`); err == nil ||
		!strings.Contains(err.Error(), "foreign key") {
		t.Errorf("range for a missing advisory: err = %v, want foreign key violation", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE advisories SET epss = 1.5 WHERE id = 'c-1'`); err == nil {
		t.Error("epss 1.5 accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE advisories SET cvss_score = 10.5 WHERE id = 'c-1'`); err == nil {
		t.Error("cvss_score 10.5 accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO feed_snapshots (feeds) VALUES ('{"a":1}'::jsonb)`); err == nil {
		t.Error("non-array feeds accepted")
	}
}
