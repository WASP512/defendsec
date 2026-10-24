package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"defendsec/internal/alertmeta"
	"defendsec/internal/controls"
	"defendsec/internal/presence"
	"defendsec/internal/storepg"
	"defendsec/internal/vuln"
)

// vulnMatchTimeout bounds one host's match. A full server is a few hundred
// packages; the budget is for a slow database, not for the matcher.
const vulnMatchTimeout = 60 * time.Second

// FindingsRefreshInterval is how often apid checks whether a new feed snapshot
// has landed and, if so, re-matches every host against it. Findings are
// otherwise recomputed only when a host reports inventory, which would leave a
// quiet host showing last week's exposure.
const FindingsRefreshInterval = 10 * time.Minute

// vulnState remembers, per host, what the last successful match was computed
// from, so an unchanged inventory against an unchanged feed is not re-matched
// on every report.
type vulnState struct {
	mu   sync.Mutex
	seen map[string]string
}

func (v *vulnState) unchanged(deviceID, fp string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.seen[deviceID] == fp
}

func (v *vulnState) remember(deviceID, fp string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]string{}
	}
	v.seen[deviceID] = fp
}

// vulnHost turns a device record into the matcher's input.
func vulnHost(dev presence.Device) vuln.Host {
	h := vuln.Host{Distro: dev.Distro, Release: dev.DistroRelease, PackageManager: dev.PackageManager}
	h.Packages = make([]vuln.Package, 0, len(dev.Software))
	for _, sw := range dev.Software {
		h.Packages = append(h.Packages, vuln.Package{
			Name: sw.Name, Version: sw.Version, SourcePackage: sw.SourcePackage, SourceVersion: sw.SourceVersion,
		})
	}
	return h
}

// vulnFingerprint identifies the inputs of a match: the host's identity and
// packages, and the feed snapshot it is matched against.
func vulnFingerprint(h vuln.Host, snapshotID int64) string {
	sum := sha256.New()
	fmt.Fprintf(sum, "%s\x00%s\x00%s\x00%d\x00", h.Distro, h.Release, h.PackageManager, snapshotID)
	for _, p := range h.Packages {
		fmt.Fprintf(sum, "%s\x00%s\x00%s\x00%s\x00", p.Name, p.Version, p.SourcePackage, p.SourceVersion)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// processVulnAlerts matches a host against the advisory ranges, records the
// findings, and keeps the host's vuln alerts in step. It is called after every
// inventory report.
//
// Alerts are raised only for findings that cannot wait: on the CISA KEV list
// (exploited now) or rated critical. Everything else is a finding, listed by
// the exposure views and the findings API; a host that is a few patches behind
// should not raise a hundred alerts.
func (s *Server) processVulnAlerts(dev presence.Device) {
	if s.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), vulnMatchTimeout)
	defer cancel()
	if _, err := s.matchDevice(ctx, dev); err != nil {
		s.log.Warn("vuln match", "err", err, "device", dev.ID)
	}
}

// matchDevice runs the matcher for one host and persists the outcome. It
// returns nil, nil when nothing has changed since the last match.
func (s *Server) matchDevice(ctx context.Context, dev presence.Device) (*vuln.Result, error) {
	var snapID *int64
	var fpSnap int64
	if snap, ok, err := s.pg.LatestFeedSnapshot(ctx); err != nil {
		return nil, fmt.Errorf("latest feed snapshot: %w", err)
	} else if ok {
		snapID, fpSnap = &snap.ID, snap.ID
	}
	host := vulnHost(dev)
	fp := vulnFingerprint(host, fpSnap)
	if s.vulnSeen.unchanged(dev.ID, fp) {
		return nil, nil
	}
	res, err := vuln.Match(ctx, s.pg, host)
	if err != nil {
		return nil, err
	}
	if err := s.pg.RecordFindings(ctx, dev.ID, res, snapID); err != nil {
		return nil, err
	}
	s.syncVulnAlerts(ctx, dev, res)
	s.vulnSeen.remember(dev.ID, fp)
	return &res, nil
}

// urgent reports whether a finding warrants an alert of its own: exploited in
// the wild (KEV), fixed or not, or a critical one with a fix to install. A KEV
// CVE that is fixed upstream but not yet released by the host's own distribution
// (awaiting_vendor) is exploited now whether or not there is anything to
// install yet, so it alerts too; a merely critical one does not, because it is
// not actionable.
func urgent(f vuln.Finding) bool {
	switch f.Kind {
	case vuln.KindFinding:
		return f.KEV || strings.EqualFold(f.Severity, "critical")
	case vuln.KindUnfixed, vuln.KindAwaitingVendor:
		return f.KEV
	}
	return false
}

func (s *Server) syncVulnAlerts(ctx context.Context, dev presence.Device, res vuln.Result) {
	want := map[string]vuln.Finding{}
	for _, f := range res.Findings {
		if !urgent(f) {
			continue
		}
		if prev, ok := want[f.AdvisoryID]; !ok || f.Package < prev.Package {
			want[f.AdvisoryID] = f
		}
	}
	for id, f := range want {
		f := f
		s.ensureAlert(dev.ID, "vuln", id, func() presence.Alert { return s.alertFromFinding(dev, f) })
	}
	// Close alerts for findings that are gone: patched, or no longer urgent.
	open, err := s.pg.ListAlerts(ctx, storepg.AlertFilters{Status: "open", Kind: "vuln", DeviceID: dev.ID, Limit: 1000})
	if err != nil {
		s.log.Warn("list open vuln alerts", "err", err, "device", dev.ID)
		return
	}
	for _, a := range open {
		if _, still := want[a.SourceID]; !still {
			s.resolveVulnAlert(ctx, dev.ID, a.SourceID)
		}
	}
}

func (s *Server) alertFromFinding(dev presence.Device, f vuln.Finding) presence.Alert {
	id, _ := newDeviceID()
	title := "Vulnerable package: " + f.Package
	if f.CVE != "" {
		title = f.CVE + " on " + f.Package
	}
	fixed := "no fixed version is published"
	switch {
	case f.Kind == vuln.KindAwaitingVendor:
		fixed = f.Reason
	case f.Fixed != "":
		fixed = "fixed in " + f.Fixed
	}
	summary := fmt.Sprintf("%s %s: %s", f.Package, f.Installed, fixed)
	if f.KEV {
		summary += " (CISA KEV: exploited in the wild)"
	}
	detail := alertmeta.BaseDetail(dev.Hostname)
	detail[alertmeta.KeyPackageName] = f.Package
	detail[alertmeta.KeyPackageVer] = f.Installed
	detail[alertmeta.KeyPackageFloor] = f.Fixed
	detail[alertmeta.KeyAdvisoryID] = f.AdvisoryID
	detail[alertmeta.KeyAdvisoryCVE] = f.CVE
	detail[alertmeta.KeyAdvisorySum] = f.Summary
	raw := map[string]any{
		"advisoryId": f.AdvisoryID, "cve": f.CVE, "package": f.Package, "sourcePackage": f.SourcePackage,
		"version": f.Installed, "fixed": f.Fixed, "fixState": f.FixState, "basis": string(f.Basis),
		"feed": f.Feed, "kev": f.KEV, "summary": f.Summary, "kind": string(f.Kind),
	}
	if f.RangeID != 0 {
		raw["rangeId"] = f.RangeID
	}
	if f.SnapshotID != nil {
		raw["snapshotId"] = *f.SnapshotID
	}
	if f.FeedDate != nil {
		raw["feedDate"] = f.FeedDate.Format(time.RFC3339)
	}
	detail = alertmeta.WithRaw(detail, raw)
	return presence.Alert{
		ID:               id,
		DeviceID:         dev.ID,
		Hostname:         dev.Hostname,
		Kind:             "vuln",
		Severity:         alertSeverity(f),
		Title:            title,
		Summary:          summary,
		SourceType:       "advisory",
		SourceID:         f.AdvisoryID,
		GeneratorID:      alertmeta.GeneratorVuln,
		GeneratorVersion: alertmeta.GeneratorVersion,
		Detail:           detail,
		Signal:           string(controls.SignalVulnAssessment),
		ControlIDs:       controls.Tag(controls.SignalVulnAssessment),
	}
}

// alertSeverity: a KEV listing is exploitation in the wild, so it is at least
// high whatever the vendor rated the CVE.
func alertSeverity(f vuln.Finding) string {
	sev := strings.ToLower(f.Severity)
	if f.KEV && sev != "critical" && sev != "high" {
		return "high"
	}
	switch sev {
	case "critical", "high", "medium", "low":
		return sev
	}
	return "medium"
}

func (s *Server) resolveVulnAlert(ctx context.Context, deviceID, advisoryID string) {
	_ = s.store.ResolveOpenAlerts(deviceID, "vuln", advisoryID)
	if s.pg != nil {
		if _, err := s.pg.ResolveOpenAlerts(ctx, deviceID, "vuln", advisoryID); err != nil {
			s.log.Warn("resolve vuln alert", "err", err, "device", deviceID, "advisory", advisoryID)
		}
	}
}

// RunFindingsRefresh re-matches every host whenever a new feed snapshot
// appears, until ctx ends. The first pass runs shortly after start: hosts
// loaded from the database have findings from before the restart, and the feeds
// may have moved while apid was down.
func (s *Server) RunFindingsRefresh(ctx context.Context, every time.Duration) {
	if s.pg == nil {
		return
	}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.refreshFindings(ctx)
		timer.Reset(every)
	}
}

// refreshFindings re-matches every host whose inputs changed since its last
// match (new packages, or a new feed snapshot) and reports how many it matched
// and how many failed.
func (s *Server) refreshFindings(ctx context.Context) (matched, failed int) {
	devices := s.store.List()
	for _, dev := range devices {
		if ctx.Err() != nil {
			return matched, failed
		}
		if len(dev.Software) == 0 {
			continue
		}
		mctx, cancel := context.WithTimeout(ctx, vulnMatchTimeout)
		res, err := s.matchDevice(mctx, dev)
		cancel()
		switch {
		case err != nil:
			failed++
			s.log.Warn("vuln refresh", "err", err, "device", dev.ID)
		case res != nil:
			matched++
		}
	}
	if matched > 0 || failed > 0 {
		s.log.Info("findings refresh", "devices", len(devices), "rematched", matched, "failed", failed)
	}
	return matched, failed
}
