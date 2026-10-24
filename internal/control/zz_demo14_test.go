package control

// Local-only (listed in .git/info/exclude, never committed): serves /v1/autotask/
// for the console from a demo database, with the fake Autotask service behind it,
// so the page can be shown. It runs only when DEMO14_DB is set, and blocks until
// the test times out or the process is killed.

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/autotask"
	"defendsec/internal/autotask/atest"
	"defendsec/internal/autotask/client"
	"defendsec/internal/m365"
	"defendsec/internal/storepg"
)

func TestZZDemo14(t *testing.T) {
	name := os.Getenv("DEMO14_DB")
	if name == "" {
		t.Skip("DEMO14_DB not set")
	}
	url := os.Getenv("TEST_DATABASE_URL")
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	s := &Server{adminToken: "admin-token", viewerToken: "viewer-token", log: slog.New(slog.DiscardHandler)}
	s.SetPostgres(storepg.New(pool))
	srv := atest.New()
	defer srv.Close()
	s.SetAutotaskDesk(func(set autotask.Settings) (autotask.Desk, error) {
		return client.New(client.Config{BaseURL: srv.BaseURL(), UserName: atest.User, Secret: atest.Secret, IntegrationCode: atest.IntegrationCode,
			Sleep: func(context.Context, time.Duration) error { return nil }})
	})

	for _, h := range []string{"web-01", "web-02", "db-01"} {
		atkSeedVuln(t, s.pg, h, true)
	}
	now := time.Now().UTC()
	if _, err := s.pg.RecordIdentityRun(ctx, "m365", "tenant.example.com", "manual", &m365.Report{
		StartedAt: now, FinishedAt: now.Add(time.Second), Requests: 3, Counts: m365.Counts{Users: 3},
		Checks: []m365.CheckResult{{Check: "mfa", Assessed: true, Observed: map[string]any{}, Findings: []m365.Finding{
			{ID: "mfa.not_registered", Subject: "u1", SubjectLabel: "ann@example.com", Severity: m365.SevCritical, Title: "No MFA registered for a Global Administrator", Detail: "The account has no MFA method.", Fix: "Register MFA for this account.", Evidence: map[string]any{}},
			{ID: "mfa.not_registered", Subject: "u2", SubjectLabel: "bob@example.com", Severity: m365.SevMedium, Title: "No MFA registered", Detail: "The account has no MFA method.", Fix: "Register MFA for this account.", Evidence: map[string]any{}},
		}}},
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/autotask/", s.HandleAutotask)
	mux.HandleFunc("/demo/complete", func(w http.ResponseWriter, r *http.Request) {
		for _, tk := range srv.Tickets() {
			srv.Complete(tk.ID)
		}
	})
	hs := &http.Server{Addr: "127.0.0.1:49271", Handler: mux}
	go hs.ListenAndServe() //nolint:errcheck
	t.Log("serving", name)
	time.Sleep(25 * time.Minute)
	hs.Close()
}
