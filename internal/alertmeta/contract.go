// Package alertmeta defines the stable detection contract for DefendSec alerts.
// Rules and UI should prefer these field names inside Alert.Detail.
package alertmeta

import (
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

const (
	GeneratorFIM  = "defendsec.fim"
	GeneratorSCA  = "defendsec.sca"
	GeneratorVuln = "defendsec.vuln"
)

const GeneratorVersion = "1.0.0"

const (
	KeySchemaVersion = "contract.schemaVersion"
	KeyFilePath      = "file.path"
	KeyFileHashPrev  = "file.hash.previous"
	KeyFileHashCurr  = "file.hash.current"
	KeyEventAction   = "event.action"
	KeyHostName      = "host.name"
	KeyPackageName   = "package.name"
	KeyPackageVer    = "package.version"
	KeyPackageFloor  = "package.fixedBelow"
	KeyAdvisoryID    = "advisory.id"
	KeyAdvisoryCVE   = "advisory.cve"
	KeyAdvisorySum   = "advisory.summary"
	KeySCAPackID     = "sca.packId"
	KeySCACheckID    = "sca.checkId"
	KeySCADetail     = "sca.detail"
	KeyRaw           = "raw"
)

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// Stamp returns detectedAt (source time) and ingestedAt (engine accept time).
func Stamp(detectedAt string) (detected, ingested string) {
	ingested = Now()
	if strings.TrimSpace(detectedAt) == "" {
		return ingested, ingested
	}
	return detectedAt, ingested
}

func BaseDetail(hostname string) map[string]any {
	return map[string]any{
		KeySchemaVersion: SchemaVersion,
		KeyHostName:      hostname,
	}
}

func WithRaw(detail map[string]any, raw any) map[string]any {
	if detail == nil {
		detail = map[string]any{}
	}
	if raw != nil {
		detail[KeyRaw] = raw
	}
	return detail
}
