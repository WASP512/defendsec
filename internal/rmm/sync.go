// Package rmm reads a client's devices through the RMM they already run (Datto
// RMM, via its read-only API) and turns what it says into DefendSec hosts and
// findings, with nothing installed on the PCs.
//
// One instance reads one RMM site. For each Windows device in it the collector
// stores the OS, the audited software and RMM's patch summary, and the updates
// RMM lists as not installed. Each missing update (a KB number) is mapped to the
// CVEs it fixes through Microsoft's Security Update Guide (internal/feeds/msrc),
// so a missing KB that fixes an actively exploited CVE ranks first in Fix this
// week like any other KEV finding.
//
// What it will not do is claim more than it saw. A device whose last RMM audit
// is older than the threshold, or that RMM never audited, or whose patches could
// not be read, is "not assessed" with the reason, keeps the findings it had, and
// is never counted clean. Third-party application CVE matching is not done here:
// the RMM gives a name and a version, with no publisher or package identity to
// match an advisory against.
package rmm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"defendsec/internal/presence"
	"defendsec/internal/rmm/datto"
	"defendsec/internal/storepg"
	"defendsec/internal/vuln"
)

// Source is what the collector reads. *datto.Client implements it.
type Source interface {
	Devices(ctx context.Context, siteUID string) ([]datto.Device, error)
	Audit(ctx context.Context, deviceUID string) (datto.Audit, error)
	Software(ctx context.Context, deviceUID string) ([]datto.Software, error)
	Patches(ctx context.Context, deviceUID string, status datto.InstallStatus) ([]datto.Patch, error)
	RateStatus(ctx context.Context) (datto.RateStatus, error)
	Requests() int
}

// Store is what the collector writes. *storepg.Store implements it.
type Store interface {
	vuln.RangeSource
	GetRMMSettings(ctx context.Context) (storepg.RMMSettings, error)
	UpsertRMMDevice(ctx context.Context, d storepg.RMMDevice) error
	ReplaceRMMPatches(ctx context.Context, deviceID string, ps []storepg.RMMPatch) error
	RetireRMMDevices(ctx context.Context, siteUID string, keep []string) (int, error)
	AgentIdentities(ctx context.Context) ([]storepg.AgentIdentity, error)
	SetRMMMerge(ctx context.Context, deviceID, agentID, basis string) error
	OpenMSRCKBs(ctx context.Context, deviceID string) ([]string, error)
	SetHostPatchState(ctx context.Context, st storepg.HostPatchState) error
	RecordPatchFindings(ctx context.Context, deviceID string, res vuln.Result, snapshotID *int64, inv *storepg.Inventory, st storepg.HostPatchState) error
	LatestFeedSnapshot(ctx context.Context) (storepg.FeedSnapshot, bool, error)
	CountOpenRMMFindings(ctx context.Context) (int, error)
	RecordRMMSync(ctx context.Context, r storepg.RMMSync) (storepg.RMMSync, error)
}

// ErrNoSite is returned when no RMM site has been selected.
var ErrNoSite = errors.New("no Datto RMM site is selected")

// Syncer reads the selected site once per Sync call. Run one at a time.
type Syncer struct {
	Src   Source
	Store Store
	Log   *slog.Logger
	Now   func() time.Time
	// Sleep is replaceable in tests.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Syncer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (s *Syncer) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// maxConsecutiveForbidden stops a run after this many 403s in a row. Datto
// answers 403 to an address it has blocked for ignoring 429, and more requests
// make the block last, so the collector stops rather than push on.
const maxConsecutiveForbidden = 3

// Sync reads the site, stores what it found and matches the missing updates. A
// run that could not read the RMM is a result, not an error: it is recorded as
// not_assessed with its reason and the evidence already held is left as it was.
// The error return is for what stops a result being recorded at all.
func (s *Syncer) Sync(ctx context.Context, triggeredBy string) (storepg.RMMSync, error) {
	cfg, err := s.Store.GetRMMSettings(ctx)
	if err != nil {
		return storepg.RMMSync{}, err
	}
	if !cfg.Configured {
		return storepg.RMMSync{}, ErrNoSite
	}
	rec := storepg.RMMSync{SiteUID: cfg.SiteUID, TriggeredBy: triggeredBy, StartedAt: s.now(), Status: "ok", Errors: []string{}}
	finish := func() (storepg.RMMSync, error) {
		rec.FinishedAt = s.now()
		rec.Requests = s.Src.Requests()
		if n, err := s.Store.CountOpenRMMFindings(ctx); err == nil {
			rec.FindingsOpen = n
		}
		out, err := s.Store.RecordRMMSync(ctx, rec)
		if err != nil {
			return rec, err
		}
		s.log().Info("rmm sync", "status", out.Status, "devices", out.Devices, "windows", out.Windows, "stale", out.Stale,
			"unreadable", out.Unreadable, "kbsMissing", out.KBsMissing, "findingsOpen", out.FindingsOpen, "requests", out.Requests)
		return out, nil
	}
	notAssessed := func(err error) (storepg.RMMSync, error) {
		rec.Status, rec.Reason = "not_assessed", datto.Reason(err)
		return finish()
	}

	// The quota is shared by everything else on the RMM account: wait a minute if
	// it is already mostly used, rather than push it into a 429.
	if rs, err := s.Src.RateStatus(ctx); err == nil && rs.Limit > 0 && rs.Count*10 > rs.Limit*7 {
		s.log().Warn("rmm account request quota is mostly used; waiting a minute", "count", rs.Count, "limit", rs.Limit)
		if err := s.sleep(ctx, time.Minute); err != nil {
			return storepg.RMMSync{}, err
		}
	} else if err != nil && isStop(err) {
		return notAssessed(err)
	}

	devs, err := s.Src.Devices(ctx, cfg.SiteUID)
	if err != nil {
		if ctx.Err() != nil {
			return storepg.RMMSync{}, ctx.Err()
		}
		return notAssessed(err)
	}
	rec.Devices = len(devs)

	agents, err := s.Store.AgentIdentities(ctx)
	if err != nil {
		return storepg.RMMSync{}, err
	}
	var snapID *int64
	if snap, ok, err := s.Store.LatestFeedSnapshot(ctx); err != nil {
		return storepg.RMMSync{}, err
	} else if ok {
		snapID = &snap.ID
	}

	staleAfter := time.Duration(cfg.StaleAfterDays) * 24 * time.Hour
	var keep []string
	forbidden := 0
	var stop error
	var processed int
	for _, d := range devs {
		if d.Deleted {
			continue
		}
		if d.DeviceClass != "device" || !isWindows(d.OperatingSystem) {
			rec.Skipped++
			continue
		}
		rec.Windows++
		keep = append(keep, d.UID)
		if stop != nil {
			rec.Unreadable++ // the run was cut short before this device
			continue
		}
		if err := ctx.Err(); err != nil {
			return storepg.RMMSync{}, err
		}
		out, err := s.device(ctx, cfg.SiteUID, d, agents, staleAfter, snapID)
		rec.KBsMissing += out.kbs
		rec.KBsUnmapped += out.unmapped
		if out.merged {
			rec.Merged++
		}
		switch out.state {
		case "stale":
			rec.Stale++
		case "unreadable":
			rec.Unreadable++
			rec.Errors = append(rec.Errors, out.note)
		}
		if err == nil {
			processed++
			forbidden = 0
			continue
		}
		if ctx.Err() != nil {
			return storepg.RMMSync{}, ctx.Err()
		}
		kind := datto.KindOf(err)
		if kind == "" {
			return storepg.RMMSync{}, err // a database error: nothing more can be recorded
		}
		if kind == datto.KindForbidden {
			forbidden++
		} else {
			forbidden = 0
		}
		if isStop(err) && (kind != datto.KindForbidden || forbidden >= maxConsecutiveForbidden) {
			stop = err
		}
	}

	if stop != nil {
		// Part of the site was read; the rest keeps what it had.
		rec.Reason = datto.Reason(stop)
		if processed == 0 {
			rec.Status = "not_assessed"
		} else {
			rec.Status = "partial"
		}
	} else {
		if _, err := s.Store.RetireRMMDevices(ctx, cfg.SiteUID, keep); err != nil {
			return storepg.RMMSync{}, err
		}
		if rec.Unreadable > 0 {
			rec.Status = "partial"
			rec.Reason = fmt.Sprintf("%d device(s) could not be read; they keep the evidence they had and are not assessed", rec.Unreadable)
		}
	}
	return finish()
}

// isStop reports failures after which asking more would not help or would hurt:
// the credentials are refused, the user may not read, or the account is rate
// limited.
func isStop(err error) bool {
	switch datto.KindOf(err) {
	case datto.KindAuth, datto.KindForbidden, datto.KindRateLimited:
		return true
	}
	return false
}

type deviceOutcome struct {
	state    string // "covered", "stale", "no_data", "no_feed", "unreadable"
	kbs      int
	unmapped int
	merged   bool
	note     string
}

var winRe = regexp.MustCompile(`(?i)windows`)

func isWindows(os string) bool { return winRe.MatchString(os) }

var versionRe = regexp.MustCompile(`^\s*(\d+)\.(\d+)\.(\d+)`)

// NormalizeOSVersion reduces what RMM reports ("10.0.19045", "10.0.19045.5247",
// "6.3.9600") to major.minor.build, the form the Supported-OS policy reads. It
// returns the version and the build number, or "" and "" if the text has none.
func NormalizeOSVersion(v string) (version, build string) {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return "", ""
	}
	return m[1] + "." + m[2] + "." + m[3], m[3]
}

func ptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// device collects, stores and matches one device. The returned error is the
// collection error (an *datto.Error) or a database error; the outcome says what
// to count.
func (s *Syncer) device(ctx context.Context, siteUID string, d datto.Device, agents []storepg.AgentIdentity, staleAfter time.Duration, snapID *int64) (deviceOutcome, error) {
	id := storepg.RMMDeviceID(d.UID)
	now := s.now()
	row := storepg.RMMDevice{
		DeviceID: id, UID: d.UID, SiteUID: siteUID, Hostname: d.Hostname, OSCaption: d.OperatingSystem, DeviceType: d.DeviceType,
		Online: d.Online, LastSeen: ptr(d.LastSeen.Time), LastAudit: ptr(d.LastAuditDate.Time), LastReboot: ptr(d.LastReboot.Time),
		RebootRequired: d.RebootRequired, PatchStatus: d.PatchStatus, PatchesApprovedPending: d.PatchesApprovedPending,
		PatchesNotApproved: d.PatchesNotApproved, PatchesInstalled: d.PatchesInstalled,
		AntivirusProduct: d.AntivirusProduct, AntivirusStatus: d.AntivirusStatus, CollectedAt: now,
	}
	var out deviceOutcome

	coverage := func(cov, reason string, evidence *time.Time) error {
		return s.Store.SetHostPatchState(ctx, storepg.HostPatchState{DeviceID: id, Coverage: cov, Reason: reason, EvidenceAt: evidence, SnapshotID: snapID})
	}
	// A device RMM has not audited, or audited too long ago, is stored (what RMM
	// says about it is worth showing) but not assessed.
	if d.LastAuditDate.IsZero() {
		out.state = "no_data"
		row.CollectError = "RMM has never audited this device"
		if err := s.Store.UpsertRMMDevice(ctx, row); err != nil {
			return out, err
		}
		s.dedupe(ctx, id, row, agents, &out)
		return out, coverage(storepg.PatchNoData, row.CollectError, nil)
	}
	if age := now.Sub(d.LastAuditDate.Time); age > staleAfter {
		out.state = "stale"
		reason := fmt.Sprintf("the last RMM audit was %d days ago (threshold %d): software and patch evidence is missing, not clean",
			int(age.Hours()/24), int(staleAfter.Hours()/24))
		row.CollectError = reason
		if err := s.Store.UpsertRMMDevice(ctx, row); err != nil {
			return out, err
		}
		s.dedupe(ctx, id, row, agents, &out)
		return out, coverage(storepg.PatchStale, reason, ptr(d.LastAuditDate.Time))
	}

	unreadable := func(what string, err error) (deviceOutcome, error) {
		out.state = "unreadable"
		out.note = what + ": " + datto.Reason(err)
		row.CollectError = out.note
		if uerr := s.Store.UpsertRMMDevice(ctx, row); uerr != nil {
			return out, uerr
		}
		s.dedupe(ctx, id, row, agents, &out)
		if cerr := coverage(storepg.PatchNoData, out.note, ptr(d.LastAuditDate.Time)); cerr != nil {
			return out, cerr
		}
		return out, err
	}

	audit, err := s.Src.Audit(ctx, d.UID)
	if err != nil {
		return unreadable("audit", err)
	}
	row.OSCaption = firstNonEmpty(audit.OSName, d.OperatingSystem)
	row.OSVersion, row.OSBuild = NormalizeOSVersion(audit.OSVersion)
	row.OSDisplay, row.OSInstallType, row.Arch = audit.OSDisplay, audit.OSInstallType, audit.OSArchitecture
	row.Serial = strings.TrimSpace(audit.BIOSSerial)
	row.Hardware = strings.TrimSpace(audit.Manufacturer + " " + audit.Model)

	// Patches before software: they decide the findings. A software read that
	// fails does not stop the patch match; it is noted.
	var missing []vuln.MissingPatch
	var rows []storepg.RMMPatch
	var pend []presence.Update
	for _, st := range []datto.InstallStatus{datto.ApprovedPending, datto.NotApproved} {
		ps, err := s.Src.Patches(ctx, d.UID, st)
		if err != nil {
			return unreadable("patches ("+strings.ToLower(string(st))+")", err)
		}
		for _, p := range ps {
			kb := vuln.NormalizeKB(p.KBArticleID)
			status := strings.ToLower(string(p.InstallStatus))
			if p.InstallStatus == "" {
				status = strings.ToLower(string(st))
				p.InstallStatus = st
			}
			rows = append(rows, storepg.RMMPatch{
				UID: p.PatchID, KB: kb, Title: p.Title, Severity: p.Severity, Type: p.Type, Status: string(p.InstallStatus),
				ReleaseDate: ptr(p.ReleaseDate.Time), RebootRequired: p.RebootRequired,
			})
			pend = append(pend, presence.Update{Name: p.Title, Available: kb})
			if kb != "" {
				missing = append(missing, vuln.MissingPatch{KB: kb, Title: p.Title, Status: status})
			}
		}
	}
	row.Pending, row.PendingSet = pend, true

	sw, swErr := s.Src.Software(ctx, d.UID)
	if swErr == nil {
		row.Software, row.SoftwareSet = make([]presence.Software, 0, len(sw)), true
		for _, x := range sw {
			if strings.TrimSpace(x.Name) != "" {
				row.Software = append(row.Software, presence.Software{Name: x.Name, Version: x.Version})
			}
		}
	} else if isStop(swErr) {
		return unreadable("software", swErr)
	} else {
		row.CollectError = "software: " + datto.Reason(swErr)
	}

	if err := s.Store.UpsertRMMDevice(ctx, row); err != nil {
		return out, err
	}
	if err := s.Store.ReplaceRMMPatches(ctx, id, dedupePatches(rows)); err != nil {
		return out, err
	}
	s.dedupe(ctx, id, row, agents, &out)

	res, err := vuln.MatchWindows(ctx, s.Store, missing)
	if err != nil {
		return out, err
	}
	out.kbs = res.Stats.Packages
	out.unmapped = res.Stats.Packages - res.Stats.DistroMapped
	evidence := ptr(d.LastAuditDate.Time)
	if res.Coverage != vuln.CoverageFull {
		// No feed to map against: findings stay as they were, and the device is not clean.
		out.state = "no_feed"
		return out, s.Store.SetHostPatchState(ctx, storepg.HostPatchState{DeviceID: id, Coverage: storepg.PatchNoFeed,
			Reason:     "no Microsoft update feed is loaded, so missing updates cannot be mapped to CVEs",
			EvidenceAt: evidence, KBsMissing: res.Stats.Packages, SnapshotID: snapID})
	}

	inv, err := s.inventory(ctx, id, d.UID, missing)
	if err != nil {
		return out, err
	}
	reason := ""
	if out.unmapped > 0 {
		reason = fmt.Sprintf("%d of %d missing updates are not in the Microsoft feed (not security updates, or older than its window)", out.unmapped, out.kbs)
	}
	if swErr != nil {
		reason = strings.TrimSpace(reason + " software list not read")
	}
	out.state = "covered"
	return out, s.Store.RecordPatchFindings(ctx, id, res, snapID, inv, storepg.HostPatchState{
		DeviceID: id, Coverage: storepg.PatchCovered, Reason: reason, EvidenceAt: evidence,
		KBsMissing: res.Stats.Packages, KBsMapped: res.Stats.DistroMapped,
	})
}

// inventory builds what the store needs to say why a finding closed. Only a KB
// that had an open finding and is no longer missing needs an answer: the RMM is
// asked whether it is installed now.
func (s *Syncer) inventory(ctx context.Context, deviceID, uid string, missing []vuln.MissingPatch) (*storepg.Inventory, error) {
	open, err := s.Store.OpenMSRCKBs(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	still := map[string]bool{}
	for _, m := range missing {
		still[m.KB] = true
	}
	gone := false
	for _, kb := range open {
		if !still[kb] {
			gone = true
			break
		}
	}
	inv := &storepg.Inventory{InstalledKBs: map[string]bool{}}
	if !gone {
		return inv, nil
	}
	ps, err := s.Src.Patches(ctx, uid, datto.Installed)
	if err != nil {
		// Closing the finding is still right (the update is no longer listed as
		// missing); only the reason is lost.
		s.log().Warn("rmm installed patches not read; closing findings without a reason", "err", err)
		return inv, nil
	}
	for _, p := range ps {
		if kb := vuln.NormalizeKB(p.KBArticleID); kb != "" {
			inv.InstalledKBs[kb] = true
		}
	}
	return inv, nil
}

func dedupePatches(in []storepg.RMMPatch) []storepg.RMMPatch {
	seen := map[string]bool{}
	var out []storepg.RMMPatch
	for _, p := range in {
		if p.UID == "" {
			p.UID = p.KB
		}
		if p.UID == "" || seen[p.UID] {
			continue
		}
		seen[p.UID] = true
		out = append(out, p)
	}
	return out
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func (s *Syncer) dedupe(ctx context.Context, id string, row storepg.RMMDevice, agents []storepg.AgentIdentity, out *deviceOutcome) {
	agent, basis := MatchAgent(row.Serial, row.Hostname, agents)
	if err := s.Store.SetRMMMerge(ctx, id, agent, basis); err != nil {
		s.log().Warn("rmm dedupe", "err", err)
		return
	}
	out.merged = agent != ""
}

// junkSerials are the placeholders BIOSes ship when nobody set a serial number.
// Two machines with one of these are not the same machine.
var junkSerials = map[string]bool{
	"": true, "0": true, "none": true, "n/a": true, "na": true, "unknown": true, "default string": true,
	"to be filled by o.e.m.": true, "to be filled by o.e.m": true, "system serial number": true, "chassis serial number": true,
	"not specified": true, "not applicable": true, "serialnumber": true, "serial number": true, "123456789": true,
	"0123456789": true, "1234567890": true, "default": true, "o.e.m.": true, "oem": true, "xxxxxxxx": true,
}

func cleanSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if junkSerials[s] || len(s) < 4 {
		return ""
	}
	same := true
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			same = false
		}
	}
	if same {
		return ""
	}
	return s
}

func shortHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

// MatchAgent finds the enrolled Windows agent that is the same machine as an RMM
// device: by serial number when both have a real one, otherwise by host name.
// Exactly one candidate must match: two agents with one serial (a cloned image)
// or one name make the match ambiguous, and an ambiguous match is no match.
func MatchAgent(serial, hostname string, agents []storepg.AgentIdentity) (id, basis string) {
	if want := cleanSerial(serial); want != "" {
		var hits []string
		for _, a := range agents {
			if cleanSerial(a.Serial) == want {
				hits = append(hits, a.ID)
			}
		}
		if len(hits) == 1 {
			return hits[0], "serial"
		}
		if len(hits) > 1 {
			return "", ""
		}
	}
	if want := shortHost(hostname); want != "" {
		var hits []string
		for _, a := range agents {
			// An agent with a real serial that differs from the RMM device's is
			// another machine with a reused name.
			if shortHost(a.Hostname) != want {
				continue
			}
			if rs, as := cleanSerial(serial), cleanSerial(a.Serial); rs != "" && as != "" && rs != as {
				continue
			}
			hits = append(hits, a.ID)
		}
		if len(hits) == 1 {
			return hits[0], "hostname"
		}
	}
	return "", ""
}

var (
	_ Store  = (*storepg.Store)(nil)
	_ Source = (*datto.Client)(nil)
)
