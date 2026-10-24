package repohealth

import (
	"time"

	defendsecv1 "defendsec/internal/gen/defendsec/v1"
)

// ToProto turns a Report into its wire form.
func ToProto(r Report) *defendsecv1.RepoHealthReport {
	if r.Empty() {
		return nil
	}
	out := &defendsecv1.RepoHealthReport{
		Manager: r.Manager, LastRefreshUnix: unix(r.LastRefresh), LastRefreshSource: r.LastRefreshSource,
		Limits: r.Limits,
	}
	for _, repo := range r.Repos {
		out.Repos = append(out.Repos, &defendsecv1.RepoHealthRepo{
			Id: repo.ID, Label: repo.Label, Uri: repo.URI, Suite: repo.Suite, Source: repo.Source,
			Signature: string(repo.Signature), KeyId: repo.KeyID, Detail: repo.Detail, SignedBy: repo.SignedBy,
			ReleaseDateUnix: unix(repo.ReleaseDate), ValidUntilUnix: unix(repo.ValidUntil),
			IgnoreValidUntil: repo.IgnoreValidUntil, MetadataUnix: unix(repo.MetadataTime),
			KeyExpiresUnix: unix(repo.KeyExpires),
		})
	}
	return out
}

// FromProto reads a wire Report. A nil or manager-less message is an empty
// Report: the agent said nothing about its repositories.
func FromProto(p *defendsecv1.RepoHealthReport) Report {
	if p == nil || p.GetManager() == "" {
		return Report{}
	}
	out := Report{
		Manager: p.GetManager(), LastRefresh: fromUnix(p.GetLastRefreshUnix()), LastRefreshSource: p.GetLastRefreshSource(),
		Repos: []Repo{}, Limits: p.GetLimits(),
	}
	for _, r := range p.GetRepos() {
		out.Repos = append(out.Repos, Repo{
			ID: r.GetId(), Label: r.GetLabel(), URI: r.GetUri(), Suite: r.GetSuite(), Source: r.GetSource(),
			Signature: Sig(r.GetSignature()), KeyID: r.GetKeyId(), Detail: r.GetDetail(), SignedBy: r.GetSignedBy(),
			ReleaseDate: fromUnix(r.GetReleaseDateUnix()), ValidUntil: fromUnix(r.GetValidUntilUnix()),
			IgnoreValidUntil: r.GetIgnoreValidUntil(), MetadataTime: fromUnix(r.GetMetadataUnix()),
			KeyExpires: fromUnix(r.GetKeyExpiresUnix()),
		})
	}
	return out
}

func unix(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

func fromUnix(s int64) *time.Time {
	if s == 0 {
		return nil
	}
	t := time.Unix(s, 0).UTC()
	return &t
}
