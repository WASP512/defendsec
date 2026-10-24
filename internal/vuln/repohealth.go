package vuln

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"defendsec/internal/repohealth"
)

// RepoAdvisoryPrefix starts the advisory id of every repository-health
// finding: "REPO:" and twelve hex digits of the repository's id. A hash, not
// the id itself, because the id is an address with slashes and spaces and the
// advisory id travels in URLs; the readable name is in RepoDetail.
const RepoAdvisoryPrefix = "REPO:"

// RepoAdvisoryID is the advisory id of the finding about repository id.
func RepoAdvisoryID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return RepoAdvisoryPrefix + hex.EncodeToString(sum[:])[:12]
}

// RepoProblem is one thing wrong with a repository, as a finding carries it.
type RepoProblem struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// RepoDetail is what a repository-health finding says beyond the fields every
// finding has.
type RepoDetail struct {
	RepoID  string `json:"repoId"`
	Label   string `json:"label"`
	URI     string `json:"uri,omitempty"`
	Suite   string `json:"suite,omitempty"`
	Manager string `json:"manager"`
	// Source is the configuration file that enables the repository.
	Source    string        `json:"source,omitempty"`
	Signature string        `json:"signature"`
	KeyID     string        `json:"keyId,omitempty"`
	SignedBy  string        `json:"signedBy,omitempty"`
	Problems  []RepoProblem `json:"problems"`
	// ReleaseDate, ValidUntil, MetadataTime, KeyExpires and LastRefresh are
	// the evidence the verdict rests on, RFC 3339; empty when the host gave
	// none. LastRefreshSource says what LastRefresh is.
	ReleaseDate       string `json:"releaseDate,omitempty"`
	ValidUntil        string `json:"validUntil,omitempty"`
	MetadataTime      string `json:"metadataTime,omitempty"`
	KeyExpires        string `json:"keyExpires,omitempty"`
	LastRefresh       string `json:"lastRefresh,omitempty"`
	LastRefreshSource string `json:"lastRefreshSource,omitempty"`
	// StaleAfterDays is the threshold the verdict used.
	StaleAfterDays int `json:"staleAfterDays"`
	// Fix says how to put the repository right.
	Fix string `json:"fix"`
}

// assessRepoHealth adds one finding per repository that has a problem. The host
// may carry the reasons it cannot be assessed (gpgv missing) in its report's
// Limits; those make the pending-updates list unreliable but are not findings,
// because "could not check" is not "broken".
func assessRepoHealth(h Host, res *Result) {
	rep := h.RepoHealth
	if rep == nil || rep.Empty() {
		return
	}
	asOf := h.AsOf
	if asOf.IsZero() {
		asOf = time.Now()
	}
	res.RepoHealthAssessed = true
	asm := repohealth.Assess(*rep, asOf, h.StaleAfter)
	res.Stats.RepoHealthChecked = asm.Checked
	staleDays := int((h.StaleAfter + 12*time.Hour) / (24 * time.Hour))
	if h.StaleAfter <= 0 {
		staleDays = int(repohealth.DefaultStaleAfter / (24 * time.Hour))
	}
	byRepo := map[string]repohealth.Repo{}
	for _, r := range rep.Repos {
		byRepo[r.ID] = r
	}
	seen := map[string]bool{}
	for _, p := range asm.Problems {
		if seen[p.RepoID] {
			continue
		}
		seen[p.RepoID] = true
		repo := byRepo[p.RepoID]
		all := asm.ForRepo(p.RepoID)
		top, _ := repohealth.Highest(all)
		f := Finding{
			AdvisoryID: RepoAdvisoryID(repo.ID), Feed: "repohealth", FeedDate: nil,
			Kind: KindRepoHealth, Basis: BasisHost,
			Package: repo.Label, SourcePackage: repo.ID,
			FixState: top.Code, Severity: top.Severity,
			Summary: repo.Label + ": " + top.Title,
			Reason:  reasonOf(all),
			Repo: &RepoDetail{
				RepoID: repo.ID, Label: repo.Label, URI: repo.URI, Suite: repo.Suite, Manager: rep.Manager,
				Source: repo.Source, Signature: string(repo.Signature), KeyID: repo.KeyID, SignedBy: repo.SignedBy,
				ReleaseDate: ts(repo.ReleaseDate), ValidUntil: ts(repo.ValidUntil), MetadataTime: ts(repo.MetadataTime),
				KeyExpires: ts(repo.KeyExpires), LastRefresh: ts(rep.LastRefresh), LastRefreshSource: rep.LastRefreshSource,
				StaleAfterDays: staleDays, Fix: repohealth.Fix(rep.Manager, top.Code),
			},
		}
		for _, q := range all {
			f.Repo.Problems = append(f.Repo.Problems, RepoProblem{Code: q.Code, Severity: q.Severity, Title: q.Title, Detail: q.Detail})
		}
		res.Findings = append(res.Findings, f)
		res.Stats.RepoHealthFindings++
	}
}

func reasonOf(ps []repohealth.Problem) string {
	var parts []string
	for _, p := range ps {
		parts = append(parts, strings.TrimSpace(p.Title+". "+p.Detail))
	}
	return strings.Join(parts, " ")
}

func ts(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
