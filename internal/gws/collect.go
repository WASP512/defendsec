package gws

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"defendsec/internal/gws/google"
	"defendsec/internal/idposture"
)

// Options tune one read.
type Options struct {
	// SuperAdminMax is the most super administrators before it is a finding (default 4).
	SuperAdminMax int
	// TrustedDomains are domains, besides the domain's own, whose addresses a filter
	// may forward to without being "outside".
	TrustedDomains []string
	// ExtraFinanceTerms add to the default finance words.
	ExtraFinanceTerms []string
	// MaxMailboxes bounds the mailboxes read in one run (default 2000); the rest are
	// counted as skipped, never as clean.
	MaxMailboxes int
	// Concurrency is how many mailboxes are read at once (default 4).
	Concurrency int
	Now         func() time.Time
}

func (o *Options) defaults() {
	if o.SuperAdminMax <= 0 {
		o.SuperAdminMax = DefaultSuperAdminMax
	}
	if o.MaxMailboxes <= 0 {
		o.MaxMailboxes = 2000
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// why turns a read failure into the sentence a check records as its reason.
func why(dataset string, err error) string {
	switch google.KindOf(err) {
	case google.KindForbidden:
		s := google.Reason(err)
		if dataset == "users" && google.CodeOf(err) != "accessNotConfigured" {
			s += " (the administrator account must be allowed to read users, and the scope " + google.ScopeDirectoryUsers + " must be delegated)"
		}
		return s
	}
	return google.Reason(err)
}

func isFatal(err error) bool {
	k := google.KindOf(err)
	return k == google.KindCredentials || k == google.KindUnauthorized
}

// Collect reads the domain and judges what it read. It never returns an error: a
// failure becomes a check that was not assessed, with the reason. The report says
// how much was covered.
func Collect(ctx context.Context, src Source, opt Options) *Report {
	opt.defaults()
	rep := &Report{StartedAt: opt.Now().UTC(), Labels: CheckLabels}
	finish := func() *Report {
		rep.FinishedAt = opt.Now().UTC()
		rep.Requests = src.Requests()
		return rep
	}
	notAll := func(reason string) *Report {
		for _, c := range CheckOrder {
			rep.Checks = append(rep.Checks, CheckResult{Check: c, Reason: reason})
		}
		rep.Fatal = reason
		rep.NotAssessed = append([]NotAssessed{}, StandingNotAssessed...)
		return finish()
	}

	users, usersErr := src.Users(ctx)
	if isFatal(usersErr) {
		return notAll(google.Reason(usersErr))
	}
	if err := ctx.Err(); err != nil {
		return notAll(google.Reason(err))
	}
	if usersErr != nil {
		reason := "the user list could not be read: " + why("users", usersErr)
		for _, c := range CheckOrder {
			rep.Checks = append(rep.Checks, CheckResult{Check: c, Reason: reason})
		}
	} else {
		rep.Counts.Users = len(users)
		two := CheckTwoStep(users)
		rep.Counts.Registrations = intOf(two.Observed["activeUsers"])
		admins, facts := CheckSuperAdmins(users, opt.SuperAdminMax)
		rep.Counts.GlobalAdmins = len(facts.SuperAdmins)
		mail := collectMail(ctx, src, users, opt, rep)
		rep.Checks = []CheckResult{two, admins, mail}
	}
	rep.NotAssessed = append([]NotAssessed{}, StandingNotAssessed...)
	for _, c := range rep.Checks {
		if !c.Assessed {
			rep.NotAssessed = append(rep.NotAssessed, NotAssessed{What: CheckLabels[c.Check] + " (this read)", Why: c.Reason})
		}
	}
	return finish()
}

func intOf(v any) int {
	n, _ := v.(int)
	return n
}

// collectMail reads each eligible mailbox's auto-forwarding setting and filters.
func collectMail(ctx context.Context, src Source, users []User, opt Options, rep *Report) CheckResult {
	res := CheckResult{Check: GroupMailConfig}
	internal := map[string]bool{}
	for _, d := range opt.TrustedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			internal[d] = true
		}
	}
	var eligible []User
	var guests, inactive, noMailbox int
	for _, u := range users {
		// A guest's address belongs to another organisation: it is outside, not internal.
		if !u.Guest {
			for _, a := range append([]string{u.Email}, u.Aliases...) {
				if d := idposture.DomainOf(a); d != "" {
					internal[d] = true
				}
			}
		}
		switch {
		case u.Guest:
			guests++
		case !u.Active():
			inactive++
		case !u.MailboxSetup:
			noMailbox++
		default:
			eligible = append(eligible, u)
		}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].Email < eligible[j].Email })
	skipped := 0
	// A mailbox past the cap is not read, so a finding already open on it is neither
	// confirmed nor cleared by this run: it goes into the unassessed prefixes.
	var notCovered []string
	if len(eligible) > opt.MaxMailboxes {
		skipped = len(eligible) - opt.MaxMailboxes
		for _, u := range eligible[opt.MaxMailboxes:] {
			notCovered = append(notCovered, u.ID+"/")
		}
		eligible = eligible[:opt.MaxMailboxes]
	}
	rep.Counts.MailboxesEligible = len(eligible) + skipped
	rep.Counts.Skipped = skipped
	rc := DefaultRuleContext(internal, opt.ExtraFinanceTerms)

	var (
		mu         sync.Mutex
		findings   []Finding
		unreadable []string
		missing    int // no mailbox (Gmail not enabled for the user)
		read       int
		filters    int
		forbidden  int
		firstErr   error
		fatal      error
		blocked    error // the whole mail read cannot work: delegation or API access
		stop       atomic.Bool
	)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	attempted := map[string]bool{}
	for _, u := range eligible {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil || stop.Load() {
			break
		}
		attempted[u.ID] = true
		wg.Add(1)
		go func(u User) {
			defer wg.Done()
			defer func() { <-sem }()
			fail := func(err error) {
				mu.Lock()
				defer mu.Unlock()
				switch k := google.KindOf(err); {
				case isFatal(err):
					if fatal == nil {
						fatal = err
					}
					stop.Store(true)
					cancel()
				case k == google.KindDelegation, k == google.KindForbidden && (google.CodeOf(err) == "accessNotConfigured" || google.CodeOf(err) == "domainPolicy"):
					// A domain-wide fact, not this mailbox's: say so once and stop asking.
					if blocked == nil {
						blocked = err
					}
					stop.Store(true)
					cancel()
				case k == google.KindNotFound:
					missing++
				default:
					unreadable = append(unreadable, u.ID)
					if k == google.KindForbidden {
						forbidden++
					}
					if firstErr == nil {
						firstErr = err
					}
				}
			}
			af, err := src.AutoForwarding(ctx, u.Email)
			if err != nil {
				fail(err)
				return
			}
			fl, err := src.Filters(ctx, u.Email)
			if err != nil {
				fail(err)
				return
			}
			mine := rc.AnalyzeAutoForwarding(u, af)
			for _, f := range fl {
				mine = append(mine, rc.AnalyzeFilter(u, f)...)
			}
			mu.Lock()
			read++
			filters += len(fl)
			findings = append(findings, mine...)
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	// A mailbox the loop never reached (the read ran out of time or was stopped) was
	// not read: findings already open on it are neither confirmed nor cleared.
	for _, u := range eligible {
		if !attempted[u.ID] {
			notCovered = append(notCovered, u.ID+"/")
			skipped++
		}
	}
	rep.Counts.Skipped = skipped

	if fatal != nil {
		res.Reason = google.Reason(fatal)
		rep.Fatal = res.Reason
		return res
	}
	rep.Counts.MailboxesRead = read
	rep.Counts.NoMailbox = noMailbox + missing
	rep.Counts.Unreadable = len(unreadable)
	rep.Counts.Rules = filters
	res.Observed = map[string]any{
		"mailboxesEligible": rep.Counts.MailboxesEligible, "mailboxesRead": read, "noMailbox": noMailbox + missing,
		"unreadable": len(unreadable), "skipped": skipped, "filtersRead": filters,
		"guestsSkipped": guests, "suspendedOrArchivedSkipped": inactive,
		"internalDomains": sortedKeys(internal),
	}
	if blocked != nil {
		res.Reason = "no mailbox could be read: " + why("gmail", blocked)
		return res
	}
	if read == 0 && len(unreadable) > 0 {
		res.Reason = "no mailbox could be read"
		if forbidden > 0 {
			res.Reason = "Google refused every mailbox read (403): the Gmail scope is not delegated to the service account, or the domain's policy blocks apps from Gmail"
		} else if firstErr != nil {
			res.Reason = "no mailbox could be read: " + google.Reason(firstErr)
		}
		return res
	}
	res.Assessed = true
	res.UnassessedPrefixes = append(res.UnassessedPrefixes, notCovered...)
	for _, id := range unreadable {
		res.UnassessedPrefixes = append(res.UnassessedPrefixes, id+"/")
	}
	sort.Strings(res.UnassessedPrefixes)
	sort.Slice(findings, func(i, j int) bool {
		if a, b := findings[i].Severity.Rank(), findings[j].Severity.Rank(); a != b {
			return a > b
		}
		if findings[i].SubjectLabel != findings[j].SubjectLabel {
			return findings[i].SubjectLabel < findings[j].SubjectLabel
		}
		return findings[i].Subject < findings[j].Subject
	})
	res.Findings = findings
	return res
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
