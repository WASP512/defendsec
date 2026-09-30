package control

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/presence"
	"defendsec/internal/storepg"
)

// HandleDevices serves the fleet a page at a time, filtered on the server
// (roadmap 5.5): GET /v1/devices?q=&platform=&status=&limit=&cursor=.
// GET /v1/devices/summary returns counts without listing anything.
func (s *Server) HandleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminActor(w, r) {
		return
	}
	if strings.HasSuffix(r.URL.Path, "/summary") {
		s.deviceSummary(w, r)
		return
	}
	v := r.URL.Query()
	q := storepg.DeviceQuery{Q: v.Get("q"), Platform: v.Get("platform"), Status: v.Get("status"), Cursor: v.Get("cursor")}
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a number"})
			return
		}
		q.Limit = n
	}
	var page storepg.DevicePage
	var err error
	if s.pg != nil {
		page, err = s.pg.ListDevices(r.Context(), q)
	} else {
		page, err = FilterDevices(s.store.List(), q)
	}
	if err != nil {
		status := http.StatusBadRequest
		if !errors.Is(err, storepg.ErrBadCursor) && !isQueryError(err) {
			s.log.Error("list devices", "err", err)
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) deviceSummary(w http.ResponseWriter, r *http.Request) {
	if s.pg != nil {
		c, err := s.pg.CountDevices(r.Context(), time.Now())
		if err != nil {
			s.log.Error("count devices", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "count failed"})
			return
		}
		writeJSON(w, http.StatusOK, c)
		return
	}
	writeJSON(w, http.StatusOK, CountDevices(s.store.List(), time.Now()))
}

// isQueryError reports a validation error from DeviceQuery.Normalize, as
// opposed to a database failure.
func isQueryError(err error) bool {
	msg := err.Error()
	for _, p := range []string{"search is", "platform must", "status must", "limit must"} {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	return false
}

// FilterDevices applies a DeviceQuery to an in-memory fleet, with the same
// semantics as the Postgres listing, for deployments without a database.
func FilterDevices(devs []presence.Device, q storepg.DeviceQuery) (storepg.DevicePage, error) {
	if err := q.Normalize(); err != nil {
		return storepg.DevicePage{}, err
	}
	cutoff := q.Now.Add(-storepg.OnlineWindow)
	needle := strings.ToLower(q.Q)
	var match []storepg.DeviceSummary
	for _, d := range devs {
		seen, _ := time.Parse(time.RFC3339, d.LastSeen)
		online := !seen.Before(cutoff)
		if q.Platform != "" && d.Platform != q.Platform {
			continue
		}
		switch q.Status {
		case "online":
			if !online {
				continue
			}
		case "offline":
			if online {
				continue
			}
		case "isolated":
			if !d.Isolated {
				continue
			}
		}
		if needle != "" && !deviceMatches(d, needle) {
			continue
		}
		ips := d.IPAddresses
		if ips == nil {
			ips = []string{}
		}
		match = append(match, storepg.DeviceSummary{
			ID: d.ID, Hostname: d.Hostname, Platform: d.Platform, OSName: d.OSName, OSVersion: d.OSVersion,
			Arch: d.Arch, AgentVersion: d.AgentVersion, Serial: d.Serial, HardwareModel: d.HardwareModel,
			Username: d.Username, IPAddresses: ips, DiskEncryption: d.DiskEncryption, Firewall: d.Firewall,
			Isolated: d.Isolated, LastSeen: seen, Online: online,
			SoftwareCount: len(d.Software), PendingUpdates: len(d.PendingUpdates),
		})
	}
	sort.Slice(match, func(i, j int) bool {
		a, b := strings.ToLower(match[i].Hostname), strings.ToLower(match[j].Hostname)
		if a != b {
			return a < b
		}
		return match[i].ID < match[j].ID
	})
	page := storepg.DevicePage{Total: len(match), Devices: []storepg.DeviceSummary{}}
	start := 0
	if q.Cursor != "" {
		c, err := storepg.DecodeCursor(q.Cursor)
		if err != nil {
			return storepg.DevicePage{}, err
		}
		start = sort.Search(len(match), func(i int) bool {
			h := strings.ToLower(match[i].Hostname)
			return h > c.Host || (h == c.Host && match[i].ID > c.ID)
		})
	}
	end := start + q.Limit
	if end < len(match) {
		last := match[end-1]
		page.Next = storepg.EncodeCursor(strings.ToLower(last.Hostname), last.ID)
	} else {
		end = len(match)
	}
	page.Devices = append(page.Devices, match[start:end]...)
	return page, nil
}

func deviceMatches(d presence.Device, needle string) bool {
	for _, f := range []string{d.Hostname, d.Serial, d.Username, d.OSName} {
		if strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	for _, ip := range d.IPAddresses {
		if strings.Contains(strings.ToLower(ip), needle) {
			return true
		}
	}
	return false
}

// CountDevices is FleetCounts for an in-memory fleet.
func CountDevices(devs []presence.Device, now time.Time) storepg.FleetCounts {
	c := storepg.FleetCounts{ByPlatform: map[string]int{}}
	cutoff := now.Add(-storepg.OnlineWindow)
	for _, d := range devs {
		c.Total++
		if seen, err := time.Parse(time.RFC3339, d.LastSeen); err == nil && !seen.Before(cutoff) {
			c.Online++
		}
		if d.Isolated {
			c.Isolated++
		}
		if d.DiskEncryption != nil && !*d.DiskEncryption {
			c.Unencrypted++
		}
		if d.Firewall != nil && !*d.Firewall {
			c.FirewallOff++
		}
		c.ByPlatform[d.Platform]++
	}
	return c
}
