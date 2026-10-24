package runner

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"defendsec/internal/feeds"
	"defendsec/internal/feeds/alma"
	"defendsec/internal/feeds/bundle"
	"defendsec/internal/feeds/debian"
	"defendsec/internal/feeds/epss"
	"defendsec/internal/feeds/fetch"
	"defendsec/internal/feeds/kev"
	"defendsec/internal/feeds/osv"
	"defendsec/internal/feeds/rhel"
	"defendsec/internal/feeds/rocky"
	"defendsec/internal/feeds/suse"
	"defendsec/internal/feeds/ubuntu"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// Result statuses.
const (
	StatusLoaded    = "loaded"    // parsed and committed to Postgres
	StatusUnchanged = "unchanged" // confirmed current; nothing new to load
	StatusParsed    = "parsed"    // dry run: parsed and counted, nothing written
	StatusFailed    = "failed"
	StatusSkipped   = "skipped"
)

// Result is what happened to one feed in a run.
type Result struct {
	Name       string
	Kind       Kind
	URL        string
	Status     string
	Err        error
	SHA256     string
	Size       int64
	FetchedAt  time.Time
	Records    int64 // distinct ranges (range feeds), KEV entries, EPSS rows
	Advisories int   // distinct advisories touched (range feeds)
	Skipped    map[string]int
	Note       string
	Duration   time.Duration
	SnapshotID int64
}

// Runner fetches, parses and loads feeds. A nil Store makes every run a dry run:
// feeds are still downloaded into the cache and fully parsed, and counts are
// reported, but nothing is written to a database.
type Runner struct {
	Cfg     Config
	Specs   []Spec // enabled feeds in run order (see Select)
	Cache   fetch.Cache
	Fetcher *fetch.Fetcher
	Store   *storepg.Store
	Log     *slog.Logger
	Now     func() time.Time
	// Force loads a feed even if it shrank to under half its previous size.
	Force bool
}

// New builds a Runner for cfg with the given store (nil for a dry run).
func New(cfg Config, specs []Spec, store *storepg.Store, log *slog.Logger) *Runner {
	cache := fetch.Cache{Dir: cfg.CacheDir}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Runner{
		Cfg: cfg, Specs: specs, Cache: cache, Store: store, Log: log, Now: time.Now,
		Fetcher: &fetch.Fetcher{Cache: cache, MaxBytes: cfg.MaxBytes, Agent: "defendsec-feeds"},
	}
}

func (r *Runner) now() time.Time { return r.Now().UTC() }

type item struct {
	idx  int
	spec Spec
	meta fetch.Meta
	path string
}

// Sync downloads every enabled feed (conditionally), then loads what changed.
// It returns one Result per feed, in run order. A feed that fails to download
// or parse does not stop the others; its previous data stays loaded and its
// status row records the failure without touching its last-success time.
func (r *Runner) Sync(ctx context.Context) ([]Result, error) {
	results := make([]Result, len(r.Specs))
	var items []*item
	// A downloaded file only replaces the cached copy for good if it loads: see settle.
	defer func() { r.settle(items, results) }()
	for i, spec := range r.Specs {
		res := &results[i]
		res.Name, res.Kind, res.URL = spec.Name, spec.Kind, fetch.RedactURL(spec.URL)
		start := time.Now()
		if err := r.Cache.Stash(spec.Name); err != nil {
			r.Log.Warn("could not stash the cached copy", "feed", spec.Name, "err", err)
		}
		fctx, cancel := context.WithTimeout(ctx, r.Cfg.FetchTimeout)
		got, err := r.fetchSpec(fctx, spec)
		cancel()
		res.Duration = time.Since(start)
		if err != nil {
			r.Cache.Discard(spec.Name) // the cache was not touched
			r.fail(ctx, res, spec, err)
			continue
		}
		r.Log.Info("fetched", "feed", spec.Name, "bytes", got.Size, "not_modified", got.NotModified, "seconds", res.Duration.Seconds())
		items = append(items, &item{idx: i, spec: spec, meta: got.Meta, path: got.Path})
	}
	return r.process(ctx, items, results)
}

// fetchSpec downloads one feed. Rocky's errata service is paged, so it is
// walked and stored as one file; every other feed is a single file.
func (r *Runner) fetchSpec(ctx context.Context, spec Spec) (fetch.Result, error) {
	if spec.Kind == KindRocky {
		return r.Fetcher.FetchPaged(ctx, spec.Name, spec.URL, rocky.Pager(spec.URL, spec.Release))
	}
	return r.Fetcher.Fetch(ctx, spec.Name, spec.URL)
}

// settle decides, once a run is over, whether each downloaded file stays in the
// cache. A file that could not be parsed or loaded is replaced by the copy it
// displaced, so the cache (and therefore `export`) only ever holds files that
// loaded; the bad download is retried on the next run.
func (r *Runner) settle(items []*item, results []Result) {
	for _, it := range items {
		if results[it.idx].Status == StatusFailed {
			if err := r.Cache.Restore(it.spec.Name); err != nil {
				r.Log.Error("could not restore the previous cached copy", "feed", it.spec.Name, "err", err)
			}
			continue
		}
		r.Cache.Discard(it.spec.Name)
	}
}

func (r *Runner) fail(ctx context.Context, res *Result, spec Spec, err error) {
	res.Status, res.Err = StatusFailed, err
	r.Log.Error("feed failed", "feed", spec.Name, "err", err)
	if r.Store != nil {
		if serr := r.Store.RecordFeedFailure(ctx, spec.Name, string(spec.Kind), fetch.RedactURL(spec.URL), r.now(), err.Error()); serr != nil {
			r.Log.Error("could not record feed failure", "feed", spec.Name, "err", serr)
		}
	}
}

// process loads the fetched items. Range feeds go first, then KEV, then EPSS:
// enrichment is applied last so it lands on advisories this run created.
func (r *Runner) process(ctx context.Context, items []*item, results []Result) ([]Result, error) {
	for _, it := range items {
		res := &results[it.idx]
		res.Name, res.Kind, res.URL = it.spec.Name, it.spec.Kind, fetch.RedactURL(it.meta.URL)
		if res.URL == "" {
			res.URL = fetch.RedactURL(it.spec.URL)
		}
		res.SHA256, res.Size, res.FetchedAt = it.meta.SHA256, it.meta.Size, it.meta.FetchedAt
	}

	status := map[string]storepg.FeedStatus{}
	if r.Store != nil {
		release, ok, err := r.Store.TryFeedLock(ctx)
		if err != nil {
			return results, fmt.Errorf("feed lock: %w", err)
		}
		if !ok {
			return results, errors.New("another defendsec-feeds run holds the feed lock; try again when it finishes")
		}
		defer release()
		list, err := r.Store.ListFeedStatus(ctx)
		if err != nil {
			return results, fmt.Errorf("read feed status: %w", err)
		}
		for _, f := range list {
			status[f.Name] = f
		}
	}

	needs := func(it *item) bool {
		if r.Store == nil {
			return true // a dry run parses everything
		}
		st, ok := status[it.spec.Name]
		return !ok || st.SHA256 != it.meta.SHA256
	}
	rangesLoaded := false // set once a range feed commits: KEV/EPSS then re-apply to what it wrote
	anyChange := false
	for _, it := range items {
		if needs(it) {
			anyChange = true
		}
	}

	var snapID int64
	if r.Store != nil && anyChange {
		snap, err := r.Store.RecordFeedSnapshot(ctx, r.snapshotRefs(items, results, status))
		if err != nil {
			return results, fmt.Errorf("record snapshot: %w", err)
		}
		snapID = snap.ID
		r.Log.Info("snapshot created", "id", snapID)
	}

	ordered := make([]*item, len(items))
	copy(ordered, items)
	sort.SliceStable(ordered, func(i, j int) bool { return phase(ordered[i].spec) < phase(ordered[j].spec) })

	for _, it := range ordered {
		res := &results[it.idx]
		res.SnapshotID = snapID
		start := time.Now()
		st, had := status[it.spec.Name]
		changed := needs(it)
		enrich := it.spec.Kind == KindKEV || it.spec.Kind == KindEPSS
		if !changed && !(enrich && rangesLoaded) {
			// Confirmed current and already loaded: only refresh the status row.
			res.Status, res.Records = StatusUnchanged, st.RecordCount
			r.refreshStatus(ctx, it, st, snapID)
			continue
		}
		if !changed {
			res.Note = "re-applied to advisories loaded this run"
		}
		var err error
		switch it.spec.Kind {
		case KindKEV:
			err = r.loadKEV(ctx, it, res, st, had, snapID)
		case KindEPSS:
			err = r.loadEPSS(ctx, it, res, st, had, snapID)
		default:
			err = r.loadRanges(ctx, it, res, st, had, snapID)
		}
		res.Duration += time.Since(start)
		if err != nil {
			r.fail(ctx, res, it.spec, err)
			continue
		}
		if r.Store == nil {
			res.Status = StatusParsed
		} else {
			res.Status = StatusLoaded
			if serr := r.Store.RecordFeedSuccess(ctx, r.statusRow(it, res, snapID)); serr != nil {
				res.Status, res.Err = StatusFailed, fmt.Errorf("loaded but could not record status: %w", serr)
				continue
			}
		}
		r.Log.Info("feed done", "feed", it.spec.Name, "status", res.Status, "records", res.Records,
			"advisories", res.Advisories, "skipped", res.Skipped, "seconds", res.Duration.Seconds())
		if it.spec.HasRanges() {
			rangesLoaded = true
		}
	}

	if snapID != 0 {
		if err := r.Store.FinalizeFeedSnapshot(ctx, snapID, r.snapshotRefs(items, results, status)); err != nil {
			return results, fmt.Errorf("finalize snapshot: %w", err)
		}
	}
	return results, nil
}

func phase(s Spec) int {
	switch s.Kind {
	case KindKEV:
		return 1
	case KindEPSS:
		return 2
	}
	return 0
}

func (r *Runner) statusRow(it *item, res *Result, snapID int64) storepg.FeedStatus {
	ft := it.meta.FetchedAt
	row := storepg.FeedStatus{
		Name: it.spec.Name, Kind: string(it.spec.Kind), URL: res.URL, LastSuccess: &ft,
		RecordCount: res.Records, SHA256: it.meta.SHA256, ETag: it.meta.ETag, LastModified: it.meta.LastModified,
	}
	if snapID != 0 {
		row.SnapshotID = &snapID
	}
	return row
}

func (r *Runner) refreshStatus(ctx context.Context, it *item, st storepg.FeedStatus, snapID int64) {
	if r.Store == nil {
		return
	}
	row := r.statusRow(it, &Result{URL: st.URL, Records: st.RecordCount}, snapID)
	if row.URL == "" {
		row.URL = fetch.RedactURL(it.spec.URL)
	}
	if snapID == 0 {
		row.SnapshotID = st.SnapshotID
	}
	if err := r.Store.RecordFeedSuccess(ctx, row); err != nil {
		r.Log.Error("could not refresh feed status", "feed", it.spec.Name, "err", err)
	}
}

// snapshotRefs lists every feed whose data is present: the ones fetched this
// run, plus feeds that failed this run but have an earlier good load (with that
// load's time and digest, not a fresh time).
func (r *Runner) snapshotRefs(items []*item, results []Result, status map[string]storepg.FeedStatus) []storepg.FeedRef {
	var refs []storepg.FeedRef
	have := map[string]bool{}
	for _, it := range items {
		res := results[it.idx]
		if res.Status == StatusFailed {
			continue // represented below from its last good load, if any
		}
		count := res.Records  // set once loaded or confirmed unchanged
		if res.Status == "" { // not processed yet: carry the previous count
			count = status[it.spec.Name].RecordCount
		}
		url := res.URL
		if url == "" {
			url = fetch.RedactURL(it.spec.URL)
		}
		have[it.spec.Name] = true
		refs = append(refs, storepg.FeedRef{Name: it.spec.Name, URL: url, FetchedAt: it.meta.FetchedAt, SHA256: it.meta.SHA256, RecordCount: int(count)})
	}
	for _, spec := range r.Specs {
		if have[spec.Name] {
			continue
		}
		if st, ok := status[spec.Name]; ok && st.SHA256 != "" && st.LastSuccess != nil {
			url := st.URL
			if url == "" {
				url = fetch.RedactURL(spec.URL)
			}
			refs = append(refs, storepg.FeedRef{Name: spec.Name, URL: url, FetchedAt: *st.LastSuccess, SHA256: st.SHA256, RecordCount: int(st.RecordCount)})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs
}

// ---- loading ---------------------------------------------------------------

// sink receives advisories from a parser.
type sink interface {
	Add(ctx context.Context, a storepg.Advisory) error
}

// countSink is the dry-run sink: it counts distinct advisories and ranges
// exactly as the database loader would, without storing anything.
type countSink struct {
	advs, rngs map[[16]byte]struct{}
}

func newCountSink() *countSink {
	return &countSink{advs: map[[16]byte]struct{}{}, rngs: map[[16]byte]struct{}{}}
}

func key(parts ...string) [16]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (c *countSink) Add(_ context.Context, a storepg.Advisory) error {
	if strings.TrimSpace(a.ID) == "" {
		return fmt.Errorf("%w: advisory without id", storepg.ErrInvalidRecord)
	}
	c.advs[key(a.ID)] = struct{}{}
	for _, r := range a.Ranges {
		c.rngs[key(a.ID, r.Ecosystem, r.Distro, r.Release, r.Package, r.Introduced, r.Fixed)] = struct{}{}
	}
	return nil
}

func toStore(a feeds.Advisory) storepg.Advisory {
	out := storepg.Advisory{
		ID: a.ID, CVE: a.CVE, Summary: a.Summary, Severity: a.Severity,
		CVSSVector: a.CVSSVector, CVSSScore: a.CVSSScore, CWE: a.CWE,
	}
	for _, r := range a.Ranges {
		out.Ranges = append(out.Ranges, storepg.AdvisoryRange{
			Ecosystem: r.Ecosystem, Distro: r.Distro, Release: r.Release, Package: r.Package,
			SourcePackage: r.SourcePackage, Introduced: r.Introduced, Fixed: r.Fixed,
			FixState: storepg.FixState(r.State), Issued: r.Issued,
		})
	}
	return out
}

// magic-byte detection so a mirror serving decompressed files still works.
func openDecompressed(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	head, _ := br.Peek(3)
	var rd io.Reader = br
	switch {
	case len(head) >= 3 && string(head) == "BZh":
		rd = bzip2.NewReader(br)
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, err
		}
		rd = zr
	}
	return struct {
		io.Reader
		io.Closer
	}{rd, f}, nil
}

func (r *Runner) loadRanges(ctx context.Context, it *item, res *Result, prev storepg.FeedStatus, had bool, snapID int64) error {
	var snk sink
	var load *storepg.FeedLoad
	count := newCountSink()
	if r.Store != nil {
		var err error
		load, err = r.Store.BeginFeedLoad(ctx, it.spec.Name, it.spec.Scopes(), snapID)
		if err != nil {
			return err
		}
		defer load.Rollback(ctx)
		snk = load
	} else {
		snk = count
	}

	rejected := map[string]int{}
	emit := func(a feeds.Advisory) error {
		err := snk.Add(ctx, toStore(a))
		if errors.Is(err, storepg.ErrInvalidRecord) {
			rejected["rejected: "+firstLine(err.Error())]++
			return nil
		}
		return err
	}
	ovalOpen := func() (io.ReadCloser, error) { return openDecompressed(it.path) }

	var st feeds.Stats
	var err error
	switch it.spec.Kind {
	case KindUbuntu:
		st, err = ubuntu.Parse(ovalOpen, it.spec.Release, emit)
	case KindRHEL:
		st, err = rhel.Parse(ovalOpen, it.spec.Release, emit)
	case KindRocky:
		var raw []byte
		if raw, err = os.ReadFile(it.path); err == nil {
			st, err = rocky.Parse(raw, it.spec.Release, emit)
		}
	case KindAlma:
		var f io.ReadCloser
		if f, err = openDecompressed(it.path); err == nil {
			st, err = alma.Parse(f, it.spec.Release, emit)
			f.Close()
		}
	case KindSUSE:
		st, err = suse.Parse(ovalOpen, it.spec.Distro, it.spec.Release, emit)
	case KindDebian:
		var f io.ReadCloser
		if f, err = openDecompressed(it.path); err == nil {
			st, err = debian.Parse(f, it.spec.Releases, emit)
			f.Close()
		}
	case KindOSV:
		var f *os.File
		if f, err = os.Open(it.path); err == nil {
			var fi os.FileInfo
			if fi, err = f.Stat(); err == nil {
				st, err = osv.Parse(f, fi.Size(), it.spec.Ecosystem, emit)
			}
			f.Close()
		}
	default:
		err = fmt.Errorf("feed kind %q is not a range feed", it.spec.Kind)
	}
	if err != nil {
		return fmt.Errorf("parse %s: %w", it.spec.Name, err)
	}
	for k, n := range rejected {
		if st.Skipped == nil {
			st.Skipped = map[string]int{}
		}
		st.Skipped[k] += n
	}
	res.Skipped = st.Skipped

	var advisories, ranges int
	if load == nil {
		advisories, ranges = len(count.advs), len(count.rngs)
		if ranges == 0 {
			return fmt.Errorf("parse %s: no ranges found; refusing to treat an empty parse as data", it.spec.Name)
		}
		res.Advisories, res.Records = advisories, int64(ranges)
		return r.shrinkGuard(it.spec.Name, res.Records, prev, had)
	}
	// Guard before Commit: Commit replaces the feed's whole scope.
	pending := load.Pending()
	if pending.Ranges == 0 {
		return fmt.Errorf("parse %s: no ranges found; refusing to replace the loaded data with nothing", it.spec.Name)
	}
	if err := r.shrinkGuard(it.spec.Name, int64(pending.Ranges), prev, had); err != nil {
		return err
	}
	out, err := load.Commit(ctx)
	if err != nil {
		return fmt.Errorf("load %s: %w", it.spec.Name, err)
	}
	res.Advisories, res.Records = out.Advisories, int64(out.Ranges)
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	// keep the reason, drop the advisory id that makes every message unique
	if i := strings.Index(s, ": "); i >= 0 && strings.HasPrefix(s, "invalid feed record") {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// shrinkGuard refuses a load that would drop a substantial feed to under half
// its previous size: that pattern is a truncated or error-page download that
// happened to parse, and replacing a feed's scope with it silently hides real
// exposure. --force overrides.
func (r *Runner) shrinkGuard(name string, now int64, prev storepg.FeedStatus, had bool) error {
	if r.Force || !had || prev.RecordCount < 1000 {
		return nil
	}
	if now*2 < prev.RecordCount {
		return fmt.Errorf("%s shrank from %d to %d records; refusing to replace it (rerun with --force if upstream really shrank)", name, prev.RecordCount, now)
	}
	return nil
}

func (r *Runner) loadKEV(ctx context.Context, it *item, res *Result, prev storepg.FeedStatus, had bool, snapID int64) error {
	f, err := openDecompressed(it.path)
	if err != nil {
		return err
	}
	defer f.Close()
	cat, err := kev.Parse(f)
	if err != nil {
		return fmt.Errorf("parse kev: %w", err)
	}
	res.Skipped = cat.Stats.Skipped
	res.Records = int64(len(cat.Entries))
	if len(cat.Entries) == 0 {
		return errors.New("parse kev: catalog has no entries; refusing to clear every KEV flag")
	}
	if err := r.shrinkGuard("kev", res.Records, prev, had); err != nil {
		return err
	}
	if r.Store == nil {
		return nil
	}
	rows := make([]storepg.KEVRow, len(cat.Entries))
	for i, e := range cat.Entries {
		rows[i] = storepg.KEVRow{CVE: e.CVE, Added: e.DateAdded, Name: e.Name}
	}
	out, err := r.Store.ApplyKEV(ctx, rows, snapID)
	if err != nil {
		return fmt.Errorf("apply kev: %w", err)
	}
	res.Note = strings.TrimSpace(res.Note + fmt.Sprintf(" flagged=%d new_stubs=%d cleared=%d", out.Marked, out.Created, out.Cleared))
	return nil
}

func (r *Runner) loadEPSS(ctx context.Context, it *item, res *Result, prev storepg.FeedStatus, had bool, snapID int64) error {
	var rows []storepg.EPSSRow
	collect := func(s epss.Score) error { rows = append(rows, storepg.EPSSRow{CVE: s.CVE, Score: s.EPSS}); return nil }
	// openDecompressed handles gzip and plain CSV alike.
	rc, err := openDecompressed(it.path)
	if err != nil {
		return err
	}
	defer rc.Close()
	meta, err := epss.Parse(rc, collect)
	if err != nil {
		return fmt.Errorf("parse epss: %w", err)
	}
	res.Skipped = meta.Stats.Skipped
	res.Records = int64(meta.Rows)
	if err := r.shrinkGuard("epss", res.Records, prev, had); err != nil {
		return err
	}
	if r.Store == nil {
		res.Note = strings.TrimSpace(res.Note + " score_date=" + meta.ScoreDate.Format("2006-01-02") + " model=" + meta.ModelVersion)
		return nil
	}
	n, err := r.Store.ApplyEPSS(ctx, meta.ScoreDate, rows)
	if err != nil {
		return fmt.Errorf("apply epss: %w", err)
	}
	res.Note = strings.TrimSpace(res.Note + fmt.Sprintf(" score_date=%s model=%s advisories_updated=%d", meta.ScoreDate.Format("2006-01-02"), meta.ModelVersion, n))
	return nil
}

// ---- export / import -------------------------------------------------------

// Export writes a signed bundle of the cached copy of every enabled feed.
// Run `sync` first; export never fetches.
func (r *Runner) Export(outPath string) ([]string, error) {
	key, err := sign.Load(filepath.Join(r.Cfg.DataDir, "pki"))
	if err != nil {
		return nil, fmt.Errorf("export needs the control key: %w", err)
	}
	var inputs []bundle.Input
	var missing []string
	for _, spec := range r.Specs {
		meta, ok, err := r.Cache.LoadMeta(spec.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, spec.Name)
			continue
		}
		meta.URL = fetch.RedactURL(meta.URL) // never put a mirror token in a bundle manifest
		inputs = append(inputs, bundle.Input{Name: spec.Name, Kind: string(spec.Kind), Path: r.Cache.Path(spec.Name), Meta: meta})
	}
	if len(inputs) == 0 {
		return nil, errors.New("nothing is cached; run `defendsec-feeds sync` first")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("these enabled feeds are not cached yet: %s (run `sync`, or narrow the export with --only)", strings.Join(missing, ", "))
	}
	if err := bundle.Write(outPath, key, inputs, r.now()); err != nil {
		return nil, err
	}
	names := make([]string, len(inputs))
	for i, in := range inputs {
		names[i] = in.Name
	}
	return names, nil
}

// TrustedKeys returns the public keys an imported bundle may be signed by: the
// PEM files named in cfg.TrustedKeys and extra, plus this install's own control
// key if one exists.
func (r *Runner) TrustedKeys(extra []string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, p := range append(append([]string(nil), r.Cfg.TrustedKeys...), extra...) {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", p, err)
		}
		pub, err := sign.ParsePublicPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", p, err)
		}
		keys = append(keys, pub)
	}
	if own, err := sign.Load(filepath.Join(r.Cfg.DataDir, "pki")); err == nil {
		keys = append(keys, own.Public)
	}
	return keys, nil
}

// Import verifies a bundle against the trusted keys and loads the feeds in it
// that this install has enabled. A feed older than the copy already cached is
// skipped unless force is set, so replaying an old bundle cannot roll the data
// back. Imported feeds are recorded with the bundle's fetch time, so their age
// in the console is the age of the data, not of the import.
func (r *Runner) Import(ctx context.Context, bundlePath string, extraKeys []string, force bool) ([]Result, error) {
	keys, err := r.TrustedKeys(extraKeys)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.Cache.Dir, 0o700); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(r.Cache.Dir, ".import-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	v, err := bundle.Read(bundlePath, keys, stage)
	if err != nil {
		return nil, err
	}
	r.Log.Info("bundle verified", "signer", v.SignerID, "created", v.Manifest.CreatedAt.Format(time.RFC3339), "feeds", len(v.Manifest.Feeds))

	byName := map[string]Spec{}
	for _, s := range r.Specs {
		byName[s.Name] = s
	}
	results := make([]Result, 0, len(v.Manifest.Feeds))
	var items []*item
	defer func() { r.settle(items, results) }()
	for _, mf := range v.Manifest.Feeds {
		res := Result{Name: mf.Name, URL: mf.URL, SHA256: mf.SHA256, Size: mf.Size, FetchedAt: mf.FetchedAt}
		spec, ok := byName[mf.Name]
		if !ok {
			res.Status, res.Note = StatusSkipped, "not an enabled feed on this install"
			results = append(results, res)
			continue
		}
		res.Kind = spec.Kind
		if cur, ok, _ := r.Cache.LoadMeta(mf.Name); ok && cur.FetchedAt.After(mf.FetchedAt) && cur.SHA256 != mf.SHA256 && !force {
			res.Status = StatusSkipped
			res.Note = fmt.Sprintf("bundle copy (fetched %s) is older than the cached copy (fetched %s); use --force to roll back", mf.FetchedAt.Format(time.RFC3339), cur.FetchedAt.Format(time.RFC3339))
			results = append(results, res)
			continue
		}
		meta := fetch.Meta{URL: mf.URL, SHA256: mf.SHA256, Size: mf.Size, FetchedAt: mf.FetchedAt}
		if err := r.Cache.Stash(mf.Name); err != nil {
			r.Log.Warn("could not stash the cached copy", "feed", mf.Name, "err", err)
		}
		if err := r.Cache.Install(mf.Name, v.FilePaths[mf.Name], meta); err != nil {
			r.Cache.Restore(mf.Name) //nolint:errcheck
			res.Status, res.Err = StatusFailed, fmt.Errorf("install into cache: %w", err)
			results = append(results, res)
			continue
		}
		results = append(results, res)
		items = append(items, &item{idx: len(results) - 1, spec: spec, meta: meta, path: r.Cache.Path(mf.Name)})
	}
	return r.process(ctx, items, results)
}
