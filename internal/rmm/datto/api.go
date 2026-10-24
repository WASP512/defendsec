package datto

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// The types decode only the fields DefendSec uses. That is deliberate: a Datto
// site carries proxy settings with a password, and a device audit carries MAC
// and IP addresses and the logged-in user. Fields not named here are dropped
// at the decoder and never reach memory, a log or the database.

// Site is one RMM site.
type Site struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	// Devices is the site's own device count (devicesStatus.numberOfDevices).
	Devices int `json:"devices"`
}

// Device is one device record of a site.
type Device struct {
	UID             string
	Hostname        string
	OperatingSystem string
	DeviceClass     string // "device", "printer", "esxihost", ...
	DeviceType      string // category, e.g. "Laptop", "Server"
	Online          bool
	Suspended       bool
	Deleted         bool
	RebootRequired  bool
	LastSeen        Millis
	LastReboot      Millis
	LastAuditDate   Millis
	// Patch management summary, as RMM computes it.
	PatchStatus            string
	PatchesApprovedPending int
	PatchesNotApproved     int
	PatchesInstalled       int
	AntivirusProduct       string
	AntivirusStatus        string
}

type deviceWire struct {
	UID             string `json:"uid"`
	Hostname        string `json:"hostname"`
	OperatingSystem string `json:"operatingSystem"`
	DeviceClass     string `json:"deviceClass"`
	DeviceType      struct {
		Category string `json:"category"`
		Type     string `json:"type"`
	} `json:"deviceType"`
	Online         bool   `json:"online"`
	Suspended      bool   `json:"suspended"`
	Deleted        bool   `json:"deleted"`
	RebootRequired bool   `json:"rebootRequired"`
	LastSeen       Millis `json:"lastSeen"`
	LastReboot     Millis `json:"lastReboot"`
	LastAuditDate  Millis `json:"lastAuditDate"`
	Antivirus      *struct {
		Product string `json:"antivirusProduct"`
		Status  string `json:"antivirusStatus"`
	} `json:"antivirus"`
	PatchManagement *struct {
		Status          string `json:"patchStatus"`
		ApprovedPending int    `json:"patchesApprovedPending"`
		NotApproved     int    `json:"patchesNotApproved"`
		Installed       int    `json:"patchesInstalled"`
	} `json:"patchManagement"`
}

func (w deviceWire) device() Device {
	d := Device{
		UID: w.UID, Hostname: w.Hostname, OperatingSystem: w.OperatingSystem, DeviceClass: w.DeviceClass,
		DeviceType: w.DeviceType.Category, Online: w.Online, Suspended: w.Suspended, Deleted: w.Deleted,
		RebootRequired: w.RebootRequired, LastSeen: w.LastSeen, LastReboot: w.LastReboot, LastAuditDate: w.LastAuditDate,
	}
	if w.Antivirus != nil {
		d.AntivirusProduct, d.AntivirusStatus = w.Antivirus.Product, w.Antivirus.Status
	}
	if w.PatchManagement != nil {
		d.PatchStatus, d.PatchesApprovedPending = w.PatchManagement.Status, w.PatchManagement.ApprovedPending
		d.PatchesNotApproved, d.PatchesInstalled = w.PatchManagement.NotApproved, w.PatchManagement.Installed
	}
	return d
}

// Audit is the part of a device audit DefendSec reads.
type Audit struct {
	OSName         string // osInfo.osName, e.g. "Microsoft Windows 10 Pro"
	OSVersion      string // osInfo.osVersion, e.g. "10.0.19045"
	OSArchitecture string
	OSDisplay      string // osInfo.osDisplayVersion, e.g. "22H2"
	OSInstallType  string // osInfo.osInstallationType, e.g. "Client", "Server"
	Manufacturer   string
	Model          string
	BIOSSerial     string
}

type auditWire struct {
	OSInfo struct {
		OSName       string `json:"osName"`
		OSVersion    string `json:"osVersion"`
		Architecture string `json:"osArchitecture"`
		Display      string `json:"osDisplayVersion"`
		InstallType  string `json:"osInstallationType"`
	} `json:"osInfo"`
	SystemInfo struct {
		Manufacturer string `json:"manufacturer"`
		Model        string `json:"model"`
	} `json:"systemInfo"`
	Bios struct {
		SerialNumber string `json:"serialNumber"`
	} `json:"bios"`
}

// Software is one audited application. The API gives a name and a version and
// nothing else: it has no publisher field.
type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InstallStatus is how RMM classes an update on a device.
type InstallStatus string

const (
	Installed       InstallStatus = "INSTALLED"
	ApprovedPending InstallStatus = "APPROVED_PENDING"
	NotApproved     InstallStatus = "NOT_APPROVED"
)

// Patch is one update RMM lists for a device.
type Patch struct {
	PatchID        string        `json:"patchId"`
	Title          string        `json:"title"`
	Type           string        `json:"type"` // SOFTWARE or DRIVER
	Severity       string        `json:"severity"`
	KBArticleID    string        `json:"kbArticleId"`
	InstallStatus  InstallStatus `json:"installStatus"`
	ReleaseDate    Millis        `json:"releaseDate"`
	RebootRequired bool          `json:"rebootRequired"`
}

// RateStatus is the account's request count against its limit. The count is
// shared by every user and tool on the RMM account.
type RateStatus struct {
	Window int64
	Count  int64
	Limit  int64
	CutOff float64
}

type pageDetails struct {
	NextPageURL *string `json:"nextPageUrl"`
}

func next(p pageDetails) string {
	if p.NextPageURL == nil {
		return ""
	}
	return strings.TrimSpace(*p.NextPageURL)
}

// Sites lists the account's sites.
func (c *Client) Sites(ctx context.Context) ([]Site, error) {
	var out []Site
	err := c.pages(ctx, "sites", "/v2/account/sites", nil, func(raw json.RawMessage) (string, error) {
		var page struct {
			PageDetails pageDetails `json:"pageDetails"`
			Sites       []struct {
				UID           string `json:"uid"`
				Name          string `json:"name"`
				DevicesStatus *struct {
					Number int `json:"numberOfDevices"`
				} `json:"devicesStatus"`
			} `json:"sites"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		for _, s := range page.Sites {
			site := Site{UID: s.UID, Name: s.Name}
			if s.DevicesStatus != nil {
				site.Devices = s.DevicesStatus.Number
			}
			out = append(out, site)
		}
		return next(page.PageDetails), nil
	})
	return out, err
}

// Devices lists the device records of one site.
func (c *Client) Devices(ctx context.Context, siteUID string) ([]Device, error) {
	if !validUID(siteUID) {
		return nil, errors.New("datto rmm: bad site uid")
	}
	var out []Device
	err := c.pages(ctx, "devices", "/v2/site/"+url.PathEscape(siteUID)+"/devices", nil, func(raw json.RawMessage) (string, error) {
		var page struct {
			PageDetails pageDetails  `json:"pageDetails"`
			Devices     []deviceWire `json:"devices"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		for _, d := range page.Devices {
			out = append(out, d.device())
		}
		return next(page.PageDetails), nil
	})
	return out, err
}

// Audit reads one device's audit: OS, build and BIOS serial.
func (c *Client) Audit(ctx context.Context, deviceUID string) (Audit, error) {
	if !validUID(deviceUID) {
		return Audit{}, errors.New("datto rmm: bad device uid")
	}
	var w auditWire
	if err := c.get(ctx, "audit", c.apiURL("/v2/audit/device/"+url.PathEscape(deviceUID), nil), &w); err != nil {
		return Audit{}, err
	}
	return Audit{
		OSName: w.OSInfo.OSName, OSVersion: w.OSInfo.OSVersion, OSArchitecture: w.OSInfo.Architecture,
		OSDisplay: w.OSInfo.Display, OSInstallType: w.OSInfo.InstallType,
		Manufacturer: w.SystemInfo.Manufacturer, Model: w.SystemInfo.Model, BIOSSerial: w.Bios.SerialNumber,
	}, nil
}

// Software lists a device's audited software.
func (c *Client) Software(ctx context.Context, deviceUID string) ([]Software, error) {
	if !validUID(deviceUID) {
		return nil, errors.New("datto rmm: bad device uid")
	}
	var out []Software
	err := c.pages(ctx, "software", "/v2/audit/device/"+url.PathEscape(deviceUID)+"/software", nil, func(raw json.RawMessage) (string, error) {
		var page struct {
			PageDetails pageDetails `json:"pageDetails"`
			Software    []Software  `json:"software"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		out = append(out, page.Software...)
		return next(page.PageDetails), nil
	})
	return out, err
}

// Patches lists the updates RMM holds for a device with the given install
// status. The per-KB list is what lets a missing update be mapped to the CVEs it
// fixes.
func (c *Client) Patches(ctx context.Context, deviceUID string, status InstallStatus) ([]Patch, error) {
	if !validUID(deviceUID) {
		return nil, errors.New("datto rmm: bad device uid")
	}
	switch status {
	case Installed, ApprovedPending, NotApproved:
	default:
		return nil, errors.New("datto rmm: bad install status")
	}
	var out []Patch
	q := url.Values{"installStatus": {string(status)}}
	err := c.pages(ctx, "patches", "/v2/device/"+url.PathEscape(deviceUID)+"/patches", q, func(raw json.RawMessage) (string, error) {
		var page struct {
			PageDetails pageDetails `json:"pageDetails"`
			Patches     []Patch     `json:"patches"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		out = append(out, page.Patches...)
		return next(page.PageDetails), nil
	})
	return out, err
}

// RateStatus reads how much of the account's request quota is in use.
func (c *Client) RateStatus(ctx context.Context) (RateStatus, error) {
	var w struct {
		Window int64   `json:"slidingTimeWindowSizeSeconds"`
		Count  int64   `json:"accountCount"`
		Limit  int64   `json:"accountRateLimit"`
		Cut    float64 `json:"accountCutOffRatio"`
	}
	if err := c.get(ctx, "request_rate", c.apiURL("/v2/system/request_rate", nil), &w); err != nil {
		return RateStatus{}, err
	}
	return RateStatus{Window: w.Window, Count: w.Count, Limit: w.Limit, CutOff: w.Cut}, nil
}

// validUID keeps a uid from carrying a path or a query into a URL. Datto's are
// UUID-like.
func validUID(s string) bool {
	if len(s) < 4 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
