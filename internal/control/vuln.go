package control

import (
	"context"
	"fmt"
	"time"

	"defendsec/internal/alertmeta"
	"defendsec/internal/presence"
	"defendsec/internal/vuln"
)

func (s *Server) processVulnAlerts(dev presence.Device) {
	if s.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	advisories, err := s.pg.ListAdvisories(ctx)
	if err != nil {
		s.log.Warn("vuln advisories", "err", err)
		return
	}
	for _, adv := range advisories {
		advID := adv["id"]
		if advID == "" {
			continue
		}
		vulnerable := false
		var matched presence.Software
		for _, sw := range dev.Software {
			if sw.Version == "" {
				continue
			}
			if !vuln.PackageMatches(adv["package"], sw.Name) {
				continue
			}
			if vuln.VersionOlderThan(sw.Version, adv["below"]) {
				vulnerable = true
				matched = sw
				break
			}
		}
		if vulnerable && vuln.IsHighOrCritical(adv["severity"]) {
			sw := matched
			s.ensureAlert(dev.ID, "vuln", advID, func() presence.Alert {
				return s.alertFromVuln(dev, adv, sw)
			})
		} else if !vulnerable {
			s.resolveVulnAlert(ctx, dev.ID, advID)
		}
	}
}

func (s *Server) alertFromVuln(dev presence.Device, adv map[string]string, sw presence.Software) presence.Alert {
	id, _ := newDeviceID()
	cve := adv["cve"]
	title := "Vulnerable package: " + sw.Name
	if cve != "" {
		title = cve + " on " + sw.Name
	}
	summary := fmt.Sprintf("%s %s is below patched floor %s", sw.Name, sw.Version, adv["below"])
	detail := alertmeta.BaseDetail(dev.Hostname)
	detail[alertmeta.KeyPackageName] = sw.Name
	detail[alertmeta.KeyPackageVer] = sw.Version
	detail[alertmeta.KeyPackageFloor] = adv["below"]
	detail[alertmeta.KeyAdvisoryID] = adv["id"]
	detail[alertmeta.KeyAdvisoryCVE] = cve
	detail[alertmeta.KeyAdvisorySum] = adv["summary"]
	detail = alertmeta.WithRaw(detail, map[string]any{
		"advisoryId": adv["id"], "cve": cve, "package": sw.Name,
		"version": sw.Version, "below": adv["below"], "summary": adv["summary"],
	})
	return presence.Alert{
		ID:               id,
		DeviceID:         dev.ID,
		Hostname:         dev.Hostname,
		Kind:             "vuln",
		Severity:         adv["severity"],
		Title:            title,
		Summary:          summary,
		SourceType:       "advisory",
		SourceID:         adv["id"],
		GeneratorID:      alertmeta.GeneratorVuln,
		GeneratorVersion: alertmeta.GeneratorVersion,
		Detail:           detail,
	}
}

func (s *Server) resolveVulnAlert(ctx context.Context, deviceID, advisoryID string) {
	_ = s.store.ResolveOpenAlerts(deviceID, "vuln", advisoryID)
	if s.pg != nil {
		if _, err := s.pg.ResolveOpenAlerts(ctx, deviceID, "vuln", advisoryID); err != nil {
			s.log.Warn("resolve vuln alert", "err", err, "device", deviceID, "advisory", advisoryID)
		}
	}
}
