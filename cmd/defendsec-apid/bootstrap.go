package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"defendsec/db/migrations"
	"defendsec/internal/control"
	"defendsec/internal/db"
	"defendsec/internal/storepg"
)

// runBootstrapAdmin implements `defendsec-apid bootstrap-admin`: print a
// one-time link that creates the first administrator.
//
// Running a command on the server is the proof of ownership, so this works
// whether or not the setup window after start is still open. It replaces
// "restart the service to reopen setup", which proved the same thing less
// directly and interrupted every connected agent to do it.
func runBootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	dbURL := fs.String("db-url", "", "Postgres URL (default: DATABASE_URL, DEFENDSEC_DATABASE_URL, or /etc/defendsec/apid.env)")
	consoleURL := fs.String("console-url", "", "the console's URL (default: DEFENDSEC_PUBLIC_CONSOLE_URL, or /etc/defendsec/console.env)")
	_ = fs.Parse(args)

	// A packaged install keeps these in env files that a login shell does not
	// load; reading them saves the operator from sourcing them first.
	loadEnvFile("/etc/defendsec/apid.env")
	loadEnvFile("/etc/defendsec/console.env")

	u := db.ResolveURL(*dbURL)
	if u == "" {
		return errors.New("no database configured: pass -db-url or set DEFENDSEC_DATABASE_URL. Without a database there are no accounts; sign in with the admin token instead")
	}
	base := strings.TrimRight(strings.TrimSpace(*consoleURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(os.Getenv("DEFENDSEC_PUBLIC_CONSOLE_URL")), "/")
	}
	if base == "" {
		host, _ := os.Hostname()
		base = "https://" + host + ":47261"
	}
	if p, err := url.Parse(base); err != nil || p.Host == "" {
		return fmt.Errorf("console URL %q is not a URL", base)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, u)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		return fmt.Errorf("postgres migrations: %w", err)
	}
	token, expires, err := control.IssueSetupInvite(ctx, storepg.New(pool), time.Now().UTC())
	if errors.Is(err, storepg.ErrAccountsExist) {
		return errors.New("an administrator already exists, so there is nothing to set up. Sign in with that account; an administrator can create more on the Accounts page")
	}
	if err != nil {
		return err
	}
	fmt.Printf("Open this link to create the first DefendSec administrator:\n\n  %s/login?invite=%s\n\n", base, token)
	fmt.Printf("It works once and expires at %s (in %s).\nRunning this command again replaces it.\n",
		expires.Local().Format("15:04 MST"), control.InviteTTL)
	return nil
}

// loadEnvFile sets variables from KEY=VALUE lines that are not already set.
// A missing or unreadable file is not an error: it is only a convenience.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
}
