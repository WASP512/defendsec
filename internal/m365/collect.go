package m365

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"defendsec/internal/m365/graph"
)

// Options tune one read.
type Options struct {
	// GlobalAdminMax is the most Global Administrators before it is a finding (default 4).
	GlobalAdminMax int
	// TrustedDomains are domains, besides the tenant's own, whose addresses a
	// rule may forward to without being "outside".
	TrustedDomains []string
	// ExtraFinanceTerms add to DefaultFinanceTerms.
	ExtraFinanceTerms []string
	// ResolveFolders names the destination folder of a move rule. It needs the
	// optional Mail.ReadBasic.All permission (docs/M365.md); off by default.
	ResolveFolders bool
	// MaxMailboxes bounds the mailboxes read in one run (default 2000); the
	// rest are counted as skipped, never as clean.
	MaxMailboxes int
	// Concurrency is how many mailboxes are read at once (default 4).
	Concurrency int
	Now         func() time.Time
}

// DefaultGlobalAdminMax is the default for Options.GlobalAdminMax. Microsoft
// advises fewer than five Global Administrators.
const DefaultGlobalAdminMax = 4

func (o *Options) defaults() {
	if o.GlobalAdminMax <= 0 {
		o.GlobalAdminMax = DefaultGlobalAdminMax
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

// Permissions names the application permission each read needs, for reasons
// the console shows. The final minimal set is in docs/M365.md.
var permissionFor = map[string]string{
	"users":         "User.Read.All",
	"registrations": "AuditLog.Read.All",
	"roles":         "RoleManagement.Read.Directory",
	"policies":      "Policy.Read.All",
	"mailboxes":     "MailboxSettings.Read",
	"folders":       "Mail.ReadBasic.All",
}

// why turns a read failure into the sentence a check records as its reason.
func why(dataset string, err error) string {
	perm := permissionFor[dataset]
	switch graph.KindOf(err) {
	case graph.KindForbidden:
		s := "Microsoft refused the read (403): the application permission " + perm + " is missing or not admin-consented"
		if dataset == "registrations" {
			s += ", or the tenant has no Microsoft Entra ID P1 or P2 licence (the registration report needs one)"
		}
		if dataset == "policies" {
			s += ", or the tenant has no Microsoft Entra ID P1 licence (Conditional Access needs one)"
		}
		if code := graph.CodeOf(err); code != "" {
			s += " [" + code + "]"
		}
		return s
	case graph.KindUnauthorized, graph.KindCredentials, graph.KindNetwork, graph.KindThrottled, graph.KindServer, graph.KindNotFound, graph.KindBadResponse:
		return graph.Reason(err)
	}
	return graph.Reason(err)
}

func isFatal(err error) bool {
	k := graph.KindOf(err)
	return k == graph.KindCredentials || k == graph.KindUnauthorized
}

// Collect reads the tenant and judges what it read. It never returns an error:
// a failure becomes a check that was not assessed, with the reason. The report
// says how much was covered.
func Collect(ctx context.Context, src Source, opt Options) *Report {
	opt.defaults()
	rep := &Report{StartedAt: opt.Now().UTC()}
	finish := func() *Report {
		rep.FinishedAt = opt.Now().UTC()
		rep.Requests = src.Requests()
		return rep
	}
	notAll := func(reason string) *Report {
		for _, c := range []string{GroupMFA, GroupLegacyAuth, GroupAdminRoles, GroupInboxRules} {
			rep.Checks = append(rep.Checks, CheckResult{Check: c, Reason: reason})
		}
		rep.Fatal = reason
		rep.NotAssessed = append([]NotAssessed{}, StandingNotAssessed...)
		return finish()
	}

	// The reads. Each failure is remembered with the dataset it belongs to.
	users, usersErr := src.Users(ctx)
	if isFatal(usersErr) {
		return notAll(graph.Reason(usersErr))
	}
	regs, regsErr := src.MFARegistrations(ctx)
	if isFatal(regsErr) {
		return notAll(graph.Reason(regsErr))
	}
	defs, defsErr := src.RoleDefinitions(ctx)
	if isFatal(defsErr) {
		return notAll(graph.Reason(defsErr))
	}
	asg, asgErr := src.RoleAssignments(ctx)
	if isFatal(asgErr) {
		return notAll(graph.Reason(asgErr))
	}
	sd, sdErr := src.SecurityDefaults(ctx)
	if isFatal(sdErr) {
		return notAll(graph.Reason(sdErr))
	}
	pols, polErr := src.ConditionalAccessPolicies(ctx)
	if isFatal(polErr) {
		return notAll(graph.Reason(polErr))
	}
	if err := ctx.Err(); err != nil {
		return notAll(graph.Reason(err))
	}

	rep.Counts.Users = len(users)
	rep.Counts.Registrations = len(regs)

	// Administrator roles (and who holds them, for the MFA check).
	var roles CheckResult
	facts := RoleFacts{Known: false}
	switch {
	case defsErr != nil:
		roles = CheckResult{Check: GroupAdminRoles, Reason: "role definitions could not be read: " + why("roles", defsErr)}
	case asgErr != nil:
		roles = CheckResult{Check: GroupAdminRoles, Reason: "role assignments could not be read: " + why("roles", asgErr)}
	default:
		roles, facts = CheckAdminRoles(defs, asg, opt.GlobalAdminMax, DefaultPrivilegedRoles)
		rep.Counts.GlobalAdmins = len(facts.GlobalAdmins)
	}

	// MFA registration.
	var mfa CheckResult
	if regsErr != nil {
		mfa = CheckResult{Check: GroupMFA, Reason: why("registrations", regsErr)}
	} else {
		active := regs
		if usersErr == nil {
			enabled := make(map[string]bool, len(users))
			for _, u := range users {
				enabled[u.ID] = u.AccountEnabled
			}
			active = active[:0:0]
			for _, r := range regs {
				if on, known := enabled[r.ID]; known && !on {
					continue
				}
				active = append(active, r)
			}
		}
		mfa = CheckMFA(active, facts)
	}

	legacy := CheckLegacyAuth(sd, sdErr, pols, polErr)

	var inbox CheckResult
	if usersErr != nil {
		inbox = CheckResult{Check: GroupInboxRules, Reason: "the user list could not be read: " + why("users", usersErr)}
	} else {
		inbox = collectInboxRules(ctx, src, users, opt, rep)
	}

	rep.Checks = []CheckResult{mfa, legacy, roles, inbox}
	rep.NotAssessed = append([]NotAssessed{}, StandingNotAssessed...)
	for _, c := range rep.Checks {
		if !c.Assessed {
			rep.NotAssessed = append(rep.NotAssessed, NotAssessed{What: CheckLabels[c.Check] + " (this read)", Why: c.Reason})
		}
	}
	if n, _ := inbox.Observed["moveRulesUnresolvedFolder"].(int); n > 0 && !opt.ResolveFolders {
		rep.NotAssessed = append(rep.NotAssessed, NotAssessed{
			What: "Where a move rule sends mail",
			Why:  itoa(n) + " enabled rule(s) move mail to a folder DefendSec did not name: the optional Mail.ReadBasic.All permission is off (docs/M365.md explains why it is off by default). A rule that moves mail between ordinary folders cannot be told from one that hides it, so only those whose conditions match finance terms are reported.",
		})
	}
	return finish()
}

func collectInboxRules(ctx context.Context, src Source, users []User, opt Options, rep *Report) CheckResult {
	res := CheckResult{Check: GroupInboxRules}
	internal := map[string]bool{}
	for _, d := range opt.TrustedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			internal[d] = true
		}
	}
	var eligible []User
	var noAddress, guests, disabled int
	for _, u := range users {
		// A guest's address belongs to another organisation: it is outside, not internal.
		for _, a := range guestSafe(u) {
			if d := domainOf(a); d != "" {
				internal[d] = true
			}
		}
		switch {
		case strings.EqualFold(u.UserType, "guest"):
			guests++
		case !u.AccountEnabled:
			disabled++
		case strings.TrimSpace(u.Mail) == "":
			noAddress++
		default:
			eligible = append(eligible, u)
		}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].UPN < eligible[j].UPN })
	skipped := 0
	if len(eligible) > opt.MaxMailboxes {
		skipped = len(eligible) - opt.MaxMailboxes
		eligible = eligible[:opt.MaxMailboxes]
	}
	rep.Counts.MailboxesEligible = len(eligible) + skipped
	rep.Counts.Skipped = skipped
	rc := DefaultRuleContext(internal, opt.ExtraFinanceTerms)

	var (
		mu                sync.Mutex
		findings          []Finding
		unreadable        []string
		noMailbox, read   int
		rules, unresolved int
		forbidden         int
		firstErr          error
		fatal             error
		folderDenied      atomic.Bool
		folderErr         error
		folderCache       = map[string]string{}
	)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	for _, u := range eligible {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(u User) {
			defer wg.Done()
			defer func() { <-sem }()
			list, err := src.InboxRules(ctx, u.ID)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case isFatal(err):
					if fatal == nil {
						fatal = err
					}
					cancel()
				case graph.KindOf(err) == graph.KindNotFound:
					noMailbox++
				default:
					unreadable = append(unreadable, u.ID)
					if graph.KindOf(err) == graph.KindForbidden {
						forbidden++
					}
					if firstErr == nil {
						firstErr = err
					}
				}
				return
			}
			var mine []Finding
			nRules, nUnres := 0, 0
			for _, r := range list {
				nRules++
				if r.MoveToFolder != "" && opt.ResolveFolders && !folderDenied.Load() {
					key := u.ID + "/" + r.MoveToFolder
					mu.Lock()
					name, cached := folderCache[key]
					mu.Unlock()
					if !cached {
						n, ferr := src.FolderName(ctx, u.ID, r.MoveToFolder)
						mu.Lock()
						if ferr != nil {
							if graph.KindOf(ferr) == graph.KindForbidden {
								folderDenied.Store(true)
							}
							if folderErr == nil {
								folderErr = ferr
							}
						} else {
							folderCache[key] = n
							name = n
						}
						mu.Unlock()
					}
					r.MoveToFolderName = name
				}
				if r.MoveToFolder != "" && r.MoveToFolderName == "" && r.Enabled {
					nUnres++
				}
				mine = append(mine, rc.AnalyzeRule(u, r)...)
			}
			mu.Lock()
			read++
			rules += nRules
			unresolved += nUnres
			findings = append(findings, mine...)
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	if fatal != nil {
		res.Reason = graph.Reason(fatal)
		rep.Fatal = res.Reason
		return res
	}
	rep.Counts.MailboxesRead = read
	rep.Counts.NoMailbox = noMailbox
	rep.Counts.Unreadable = len(unreadable)
	rep.Counts.Rules = rules
	res.Observed = map[string]any{
		"mailboxesEligible": rep.Counts.MailboxesEligible, "mailboxesRead": read, "noMailbox": noMailbox,
		"unreadable": len(unreadable), "skipped": skipped, "rulesRead": rules,
		"guestsSkipped": guests, "disabledAccountsSkipped": disabled, "usersWithoutMailAddress": noAddress,
		"internalDomains": sortedKeys(internal), "moveRulesUnresolvedFolder": unresolved,
		"folderNamesResolved": opt.ResolveFolders && !folderDenied.Load(),
	}
	if opt.ResolveFolders && folderErr != nil {
		res.Observed["folderNamesNote"] = "Folder names could not be read: " + why("folders", folderErr)
	}
	if read == 0 && len(unreadable) > 0 {
		res.Reason = "no mailbox could be read"
		if forbidden > 0 {
			res.Reason = "Microsoft refused every mailbox read (403): the application permission MailboxSettings.Read is missing or not admin-consented, or an Exchange application access policy excludes the mailboxes"
		} else if firstErr != nil {
			res.Reason = "no mailbox could be read: " + graph.Reason(firstErr)
		}
		return res
	}
	res.Assessed = true
	for _, id := range unreadable {
		res.UnassessedPrefixes = append(res.UnassessedPrefixes, id+"/")
	}
	sort.Strings(res.UnassessedPrefixes)
	sort.Slice(findings, func(i, j int) bool {
		if a, b := findings[i].Severity.Rank(), findings[j].Severity.Rank(); a != b {
			return a > b
		}
		return findings[i].SubjectLabel < findings[j].SubjectLabel
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

// ErrNotConfigured is returned by a builder when credentials are missing.
var ErrNotConfigured = errors.New("Microsoft 365 is not configured")

// guestSafe lists the addresses of u that say which domains are the tenant's own:
// a member's, never a guest's.
func guestSafe(u User) []string {
	if strings.EqualFold(u.UserType, "guest") {
		return nil
	}
	return []string{u.UPN, u.Mail}
}
