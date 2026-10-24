// Command defendsec-feeds mirrors authoritative vulnerability feeds (CISA KEV,
// EPSS, Ubuntu/Debian/Red Hat/SUSE advisories, optionally OSV) into the
// DefendSec advisory schema, and moves them onto air-gapped installs as signed
// bundles.
//
//	defendsec-feeds sync   [--dry-run] [--only a,b] [--force]
//	defendsec-feeds export [--only a,b] <bundle.tar>
//	defendsec-feeds import [--dry-run] [--force] [--trust-key pub.pem] <bundle.tar>
//	defendsec-feeds match  [--json] [--all] <inventory.json>
//	defendsec-feeds status
//	defendsec-feeds list
//
// It downloads whole published files and nothing else. No package name, host
// name or any other fleet data is ever sent anywhere; the inventory is only
// ever matched against these files locally.
//
// Configuration comes from the environment, and from /etc/defendsec/feeds.env
// when that file exists (real environment variables win). See
// docs/FEEDS.md and packaging/systemd/feeds.env.example.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"defendsec/db/migrations"
	"defendsec/internal/db"
	"defendsec/internal/feeds/fetch"
	"defendsec/internal/feeds/runner"
	"defendsec/internal/storepg"
)

// buildCommit is stamped by scripts/build-release.sh (-X main.buildCommit=...).
var buildCommit = "unknown"

const defaultEnvFile = "/etc/defendsec/feeds.env"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "defendsec-feeds:", err)
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

const usage = `usage: defendsec-feeds [--env-file FILE] <command> [flags]

commands:
  sync     fetch every enabled feed (conditionally) and load what changed
  export   write a signed bundle of the cached feeds for an air-gapped install
  import   verify a signed bundle and load it
  match    match a package inventory against the loaded feeds (read-only)
  status   show per-feed state
  list     show every known feed and which are enabled
  version  print the build commit

run "defendsec-feeds <command> -h" for a command's flags`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	global := flag.NewFlagSet("defendsec-feeds", flag.ContinueOnError)
	global.SetOutput(stderr)
	envFile := global.String("env-file", "", "KEY=VALUE file to read before the environment ("+defaultEnvFile+" if it exists)")
	global.Usage = func() { fmt.Fprintln(stderr, usage) }
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, usage)
		return errors.New("no command given")
	}
	cmd, cargs := rest[0], rest[1:]
	if cmd == "version" {
		fmt.Fprintln(stdout, buildCommit)
		return nil
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		fmt.Fprintln(stdout, usage)
		return nil
	}

	if err := loadEnv(*envFile); err != nil {
		return err
	}
	cfg, err := runner.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}

	switch cmd {
	case "sync":
		return cmdSync(ctx, cfg, cargs, stdout, stderr)
	case "export":
		return cmdExport(cfg, cargs, stdout, stderr)
	case "import":
		return cmdImport(ctx, cfg, cargs, stdout, stderr)
	case "match":
		return cmdMatch(ctx, cargs, stdout, stderr)
	case "status":
		return cmdStatus(ctx, cfg, cargs, stdout, stderr)
	case "list":
		return cmdList(cfg, stdout)
	}
	fmt.Fprintln(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

func loadEnv(explicit string) error {
	path := explicit
	if path == "" {
		path = defaultEnvFile
	}
	err := runner.LoadEnvFile(path, os.LookupEnv, os.Setenv)
	if errors.Is(err, os.ErrNotExist) && explicit == "" {
		return nil
	}
	return err
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// openStore connects to Postgres and applies migrations (they are idempotent
// and serialized by an advisory lock, so this is safe beside a running apid).
func openStore(ctx context.Context, explicit string) (*storepg.Store, func(), error) {
	url := db.ResolveURL(explicit)
	if url == "" {
		return nil, nil, errors.New("no database configured: set DEFENDSEC_DATABASE_URL (or DATABASE_URL, or --db-url), or use --dry-run")
	}
	pool, err := db.Open(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: %w", err)
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("postgres migrations: %w", err)
	}
	return storepg.New(pool), pool.Close, nil
}

func selectFeeds(cfg runner.Config, only string) ([]runner.Spec, error) {
	specs, err := runner.Select(cfg)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range strings.Split(only, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return runner.Only(specs, names)
}

func cmdSync(ctx context.Context, cfg runner.Config, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", false, "download and parse every feed and print counts; write nothing to the database")
	only := fs.String("only", "", "comma list of feeds to sync (KEV and EPSS are re-applied to new advisories only when included)")
	force := fs.Bool("force", false, "load a feed even if it shrank to under half its previous size")
	dbURL := fs.String("db-url", "", "Postgres URL (default: DEFENDSEC_DATABASE_URL or DATABASE_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	specs, err := selectFeeds(cfg, *only)
	if err != nil {
		return err
	}
	var store *storepg.Store
	if !*dry {
		s, closeDB, err := openStore(ctx, *dbURL)
		if err != nil {
			return err
		}
		defer closeDB()
		store = s
	}
	r := runner.New(cfg, specs, store, newLogger(stderr))
	r.Force = *force
	results, err := r.Sync(ctx)
	printResults(stdout, results, store == nil)
	if err != nil {
		return err
	}
	return failures(results)
}

func cmdExport(cfg runner.Config, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	only := fs.String("only", "", "comma list of feeds to include")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: defendsec-feeds export [--only a,b] <bundle.tar>")
	}
	specs, err := selectFeeds(cfg, *only)
	if err != nil {
		return err
	}
	r := runner.New(cfg, specs, nil, newLogger(stderr))
	names, err := r.Export(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s (%d feeds: %s), signed with the control key\n", fs.Arg(0), len(names), strings.Join(names, ", "))
	return nil
}

func cmdImport(ctx context.Context, cfg runner.Config, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", false, "verify the bundle and parse every feed in it; write nothing to the database")
	force := fs.Bool("force", false, "accept feeds older than the cached copy, and load a feed that shrank sharply")
	var keys multiFlag
	fs.Var(&keys, "trust-key", "PEM public key to accept as a bundle signer (repeatable; also DEFENDSEC_FEEDS_TRUSTED_KEYS)")
	dbURL := fs.String("db-url", "", "Postgres URL (default: DEFENDSEC_DATABASE_URL or DATABASE_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: defendsec-feeds import [--dry-run] [--force] [--trust-key pub.pem] <bundle.tar>")
	}
	specs, err := runner.Select(cfg)
	if err != nil {
		return err
	}
	var store *storepg.Store
	if !*dry {
		s, closeDB, err := openStore(ctx, *dbURL)
		if err != nil {
			return err
		}
		defer closeDB()
		store = s
	}
	r := runner.New(cfg, specs, store, newLogger(stderr))
	r.Force = *force
	results, err := r.Import(ctx, fs.Arg(0), keys, *force)
	if len(results) > 0 {
		printResults(stdout, results, store == nil)
	}
	if err != nil {
		return err
	}
	return failures(results)
}

func cmdStatus(ctx context.Context, cfg runner.Config, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbURL := fs.String("db-url", "", "Postgres URL (default: DEFENDSEC_DATABASE_URL or DATABASE_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	specs, err := runner.Select(cfg)
	if err != nil {
		return err
	}
	var rows map[string]storepg.FeedStatus
	if db.ResolveURL(*dbURL) != "" {
		store, closeDB, err := openStore(ctx, *dbURL)
		if err != nil {
			return err
		}
		defer closeDB()
		list, err := store.ListFeedStatus(ctx)
		if err != nil {
			return err
		}
		rows = map[string]storepg.FeedStatus{}
		for _, f := range list {
			rows[f.Name] = f
		}
	}
	cache := fetch.Cache{Dir: cfg.CacheDir}
	now := time.Now()
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "FEED\tCACHED\tCACHE AGE\tLOADED\tLOAD AGE\tRECORDS\tSNAPSHOT\tLAST ERROR")
	for _, s := range specs {
		cached, age := "-", "-"
		if m, ok, _ := cache.LoadMeta(s.Name); ok {
			cached, age = fmt.Sprintf("%s %s", human(m.Size), m.SHA256[:12]), since(now, m.FetchedAt)
		}
		loaded, loadAge, recs, snap, lerr := "-", "-", "-", "-", ""
		if rows != nil {
			if st, ok := rows[s.Name]; ok {
				if st.LastSuccess != nil {
					loaded, loadAge = st.SHA256[:min(12, len(st.SHA256))], since(now, *st.LastSuccess)
				}
				recs = fmt.Sprint(st.RecordCount)
				if st.SnapshotID != nil {
					snap = fmt.Sprint(*st.SnapshotID)
				}
				lerr = oneLine(st.LastError, 60)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, cached, age, loaded, loadAge, recs, snap, lerr)
	}
	if rows == nil {
		fmt.Fprintln(stderr, "no database configured: showing the cache only")
	}
	return tw.Flush()
}

func cmdList(cfg runner.Config, stdout io.Writer) error {
	enabled := map[string]bool{}
	if specs, err := runner.Select(cfg); err == nil {
		for _, s := range specs {
			enabled[s.Name] = true
		}
	} else {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "FEED\tENABLED\tKIND\tTARGET\tURL")
	for _, s := range runner.Catalog(cfg) {
		target := s.Distro
		if s.Release != "" {
			target += " " + s.Release
		}
		if s.Kind == runner.KindDebian {
			target = "debian " + strings.Join(releaseList(s), ",")
		}
		if s.Kind == runner.KindOSV {
			target = s.Ecosystem
		}
		on := "no"
		if enabled[s.Name] {
			on = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Name, on, s.Kind, target, fetch.RedactURL(s.URL))
	}
	return tw.Flush()
}

func releaseList(s runner.Spec) []string {
	var out []string
	for _, v := range s.Releases {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ---- output ----------------------------------------------------------------

func printResults(w io.Writer, results []runner.Result, dry bool) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "FEED\tSTATUS\tRECORDS\tADVISORIES\tSIZE\tSHA256\tSECONDS")
	for _, r := range results {
		adv := "-"
		if r.Advisories > 0 {
			adv = fmt.Sprint(r.Advisories)
		}
		rec := "-"
		if r.Records > 0 {
			rec = fmt.Sprint(r.Records)
		}
		sum := "-"
		if len(r.SHA256) >= 12 {
			sum = r.SHA256[:12]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%.1f\n", r.Name, r.Status, rec, adv, human(r.Size), sum, r.Duration.Seconds())
	}
	tw.Flush()
	if dry {
		fmt.Fprintln(w, "\ndry run: feeds were downloaded and parsed; nothing was written to the database")
	}
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(w, "\n%s: %s\n", r.Name, oneLine(r.Err.Error(), 400))
		}
		if r.Note != "" {
			fmt.Fprintf(w, "%s: %s\n", r.Name, r.Note)
		}
		if len(r.Skipped) > 0 {
			var ks []string
			for k := range r.Skipped {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			var parts []string
			for _, k := range ks {
				parts = append(parts, fmt.Sprintf("%s=%d", k, r.Skipped[k]))
			}
			fmt.Fprintf(w, "%s: skipped: %s\n", r.Name, strings.Join(parts, "; "))
		}
	}
}

func failures(results []runner.Result) error {
	var bad []string
	for _, r := range results {
		if r.Status == runner.StatusFailed {
			bad = append(bad, r.Name)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d feed(s) failed: %s", len(bad), strings.Join(bad, ", "))
	}
	return nil
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func since(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
