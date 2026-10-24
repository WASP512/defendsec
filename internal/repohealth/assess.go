package repohealth

import (
	"fmt"
	"sort"
	"time"
)

// Problem codes. A repository can have several; the finding for it carries all
// of them and takes the highest severity.
const (
	CodeKeyExpired   = "key_expired"
	CodeKeyMissing   = "key_missing"
	CodeKeyRevoked   = "key_revoked"
	CodeSigBad       = "signature_bad"
	CodeUnsigned     = "unsigned"
	CodeNoIndex      = "no_index"
	CodeIndexExpired = "index_expired"
	CodeIndexStale   = "index_stale"
)

// Problem is one thing wrong with one repository.
type Problem struct {
	RepoID   string `json:"repoId"`
	Code     string `json:"code"`
	Severity string `json:"severity"`
	// Title is one line, Detail the evidence behind it.
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Reliability says whether the host's pending-updates list can be believed.
type Reliability string

const (
	// Reliable: every enabled repository was checked and passed.
	Reliable Reliability = "reliable"
	// Unreliable: some enabled repository failed a check, or a check could not
	// be made. "0 pending" from such a host means "none that apt can see", and
	// the console must say so rather than show a clean zero.
	Unreliable Reliability = "unreliable"
	// Unassessed: the agent reported no repository evidence (older than slice
	// 11, or a host whose package manager the agent does not read). Pending
	// updates are shown as before, flagged as not cross-checked.
	Unassessed Reliability = "unassessed"
)

// Assessment is the verdict on one host's Report.
type Assessment struct {
	Reliability Reliability `json:"reliability"`
	// Reasons say, one line each, why the list is unreliable; empty otherwise.
	Reasons  []string  `json:"reasons"`
	Problems []Problem `json:"problems"`
	// Checked is the number of repositories examined.
	Checked int `json:"checked"`
}

// Assess judges a Report as of asOf. An index counts as stale when it is older
// than staleAfter; a non-positive staleAfter means DefaultStaleAfter.
//
// What "older" means differs by manager, because the dates mean different
// things:
//
//   - apt: a Release file's Date: is when the publisher published, and some
//     publishers rarely do (Ubuntu's base pocket has said 2022-04-21 for years).
//     An old Date alone is not a finding. It is one when the host also has not
//     refreshed its indexes within the threshold (update-success-stamp, or the
//     lists directory when the host has none): then nothing says the old index
//     is still current. Valid-Until in the past is a finding on its own, because
//     apt itself refuses such an index.
//   - dnf, zypper: the cached repomd.xml is touched whenever the client fetches
//     or revalidates it, so its age is the age of the host's knowledge.
func Assess(r Report, asOf time.Time, staleAfter time.Duration) Assessment {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	a := Assessment{Problems: []Problem{}, Reasons: []string{}}
	if r.Empty() {
		a.Reliability = Unassessed
		return a
	}
	a.Checked = len(r.Repos)
	refreshOld := r.LastRefresh == nil || asOf.Sub(*r.LastRefresh) > staleAfter

	for _, repo := range r.Repos {
		a.Problems = append(a.Problems, assessRepo(r, repo, asOf, staleAfter, refreshOld)...)
		if repo.Signature == SigUnverified {
			note := "could not be verified"
			if repo.Detail != "" {
				note += " (" + repo.Detail + ")"
			}
			a.Reasons = append(a.Reasons, repo.Label+": "+note)
		}
	}
	sort.SliceStable(a.Problems, func(i, j int) bool {
		pi, pj := a.Problems[i], a.Problems[j]
		if pi.RepoID != pj.RepoID {
			return pi.RepoID < pj.RepoID
		}
		if pi.Severity != pj.Severity {
			return pi.Severity == SeverityHigh
		}
		return pi.Code < pj.Code
	})
	labels := map[string]string{}
	for _, repo := range r.Repos {
		labels[repo.ID] = repo.Label
	}
	for _, p := range a.Problems {
		a.Reasons = append(a.Reasons, labels[p.RepoID]+": "+p.Title)
	}
	a.Reasons = append(a.Reasons, r.Limits...)
	if len(a.Reasons) > 0 {
		a.Reliability = Unreliable
	} else {
		a.Reliability = Reliable
	}
	return a
}

func assessRepo(r Report, repo Repo, asOf time.Time, staleAfter time.Duration, refreshOld bool) []Problem {
	var out []Problem
	add := func(code, sev, title, detail string) {
		out = append(out, Problem{RepoID: repo.ID, Code: code, Severity: sev, Title: title, Detail: detail})
	}
	key := repo.KeyID
	if key != "" {
		key = " " + key
	}
	switch repo.Signature {
	case SigExpiredKey:
		add(CodeKeyExpired, SeverityHigh, "signing key"+key+" has expired",
			"The key that signs this repository has expired, so "+r.Manager+" will not accept its index: updates from it have stopped"+
				" while the host keeps using whatever it fetched earlier. "+repo.Detail)
	case SigNoPubkey:
		add(CodeKeyMissing, SeverityHigh, "signing key"+key+" is not trusted by this host",
			"The repository is signed by a key that the keyring its source uses does not contain, so "+r.Manager+" will not accept its index. "+repo.Detail)
	case SigRevoked:
		add(CodeKeyRevoked, SeverityHigh, "signing key"+key+" has been revoked",
			"The vendor revoked the key that signs this repository; its index is no longer accepted. "+repo.Detail)
	case SigBad:
		add(CodeSigBad, SeverityHigh, "signature does not verify",
			"The index's signature does not match its contents (or the signature itself has expired). "+repo.Detail)
	case SigUnsigned:
		add(CodeUnsigned, SeverityHigh, "index carries no signature the host accepts",
			"The repository is not marked trusted and its index has no valid signature, so "+r.Manager+" refuses it. "+repo.Detail)
	case SigNoIndex:
		if r.Manager == ManagerApt {
			add(CodeNoIndex, SeverityHigh, "the host has no index for this repository",
				"The repository is enabled but apt holds no Release file for it: it was never fetched, or apt fetched it and refused it. "+
					"An expired or untrusted signing key is the usual cause, and `apt-get update` names it. "+repo.Detail)
		} else {
			add(CodeNoIndex, SeverityMedium, "the host has no cached metadata for this repository",
				"The repository is enabled but "+r.Manager+" has no cached repomd.xml for it, so it cannot list pending updates from it without a refresh. "+repo.Detail)
		}
	}

	if r.Manager == ManagerApt && repo.Signature != SigNoIndex {
		if repo.ValidUntil != nil && !repo.IgnoreValidUntil && asOf.After(*repo.ValidUntil) {
			add(CodeIndexExpired, SeverityMedium, "index expired on "+day(*repo.ValidUntil),
				"The repository's Release file says Valid-Until "+day(*repo.ValidUntil)+"; apt refuses an index past that date, so the host receives nothing new from it.")
		} else if repo.ReleaseDate != nil && asOf.Sub(*repo.ReleaseDate) > staleAfter && refreshOld {
			add(CodeIndexStale, SeverityMedium, "index is "+days(asOf.Sub(*repo.ReleaseDate))+" old and has not been refreshed",
				"The Release file is dated "+day(*repo.ReleaseDate)+" and "+refreshNote(r, asOf)+": nothing says this index is still current, so pending updates computed from it may be missing newer packages.")
		}
	}
	if r.Manager != ManagerApt && repo.Signature != SigNoIndex && repo.MetadataTime != nil && asOf.Sub(*repo.MetadataTime) > staleAfter {
		add(CodeIndexStale, SeverityMedium, "cached metadata is "+days(asOf.Sub(*repo.MetadataTime))+" old",
			"The cached repository metadata was last fetched or revalidated on "+day(*repo.MetadataTime)+", so pending updates computed from it may be missing newer packages.")
	}
	return out
}

func refreshNote(r Report, asOf time.Time) string {
	if r.LastRefresh == nil {
		return "the host has no record of ever refreshing its indexes"
	}
	return "the host last refreshed its indexes on " + day(*r.LastRefresh) + " (" + days(asOf.Sub(*r.LastRefresh)) + " ago, per the " + r.LastRefreshSource + ")"
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func days(d time.Duration) string {
	n := int(d.Hours() / 24)
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// Highest returns the most severe of the problems of one repository, and
// whether there are any.
func Highest(ps []Problem) (Problem, bool) {
	var best Problem
	found := false
	for _, p := range ps {
		if !found || (p.Severity == SeverityHigh && best.Severity != SeverityHigh) {
			best, found = p, true
		}
	}
	return best, found
}

// ForRepo returns the problems of one repository.
func (a Assessment) ForRepo(id string) []Problem {
	var out []Problem
	for _, p := range a.Problems {
		if p.RepoID == id {
			out = append(out, p)
		}
	}
	return out
}

// Fix says how to put the repository right, in the words an administrator
// needs. It is the same text whatever the host, so the console can show it for
// a group of hosts.
func Fix(manager string, code string) string {
	switch manager {
	case ManagerApt:
		switch code {
		case CodeKeyExpired, CodeKeyMissing, CodeKeyRevoked, CodeSigBad, CodeUnsigned, CodeNoIndex:
			return "Get the vendor's current signing key from the vendor itself and check its fingerprint against the vendor's site. " +
				"Install it as its own keyring, for example /etc/apt/keyrings/<vendor>.gpg (or the vendor's keyring package, which installs under /usr/share/keyrings), " +
				"and name it in the repository's source line: deb [signed-by=/etc/apt/keyrings/<vendor>.gpg] <uri> <suite> <components>, " +
				"or Signed-By: in a .sources file. Do not use apt-key or drop the key into /etc/apt/trusted.gpg.d: that trusts it for every repository. " +
				"Then run apt-get update, confirm it prints no GPG warning for the repository, and check that `apt list --upgradable` now shows what you expect. " +
				"If the repository is no longer used, remove its source file instead."
		case CodeIndexExpired, CodeIndexStale:
			return "Run apt-get update and read its output for warnings. If it succeeds, check that the periodic refresh runs " +
				"(systemctl status apt-daily.timer) so the indexes do not age again; if the repository itself no longer publishes, remove its source."
		}
	case ManagerDNF, ManagerZypper:
		refresh := "dnf makecache"
		if manager == ManagerZypper {
			refresh = "zypper refresh"
		}
		switch code {
		case CodeKeyExpired, CodeKeyMissing, CodeKeyRevoked, CodeSigBad, CodeUnsigned:
			return "Get the vendor's current signing key from the vendor itself, check its fingerprint against the vendor's site, " +
				"replace the file named by the repository's gpgkey= line, and import it (rpm --import <file>). Then run " + refresh + " and confirm it reports no signature error. " +
				"If the repository is no longer used, disable or remove its .repo file."
		case CodeNoIndex, CodeIndexStale:
			return "Run " + refresh + " and read its output for errors. If it succeeds, check that the periodic refresh is enabled " +
				"(dnf-makecache.timer on dnf hosts) so the cached metadata does not age again."
		}
	}
	return ""
}
