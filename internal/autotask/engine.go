package autotask

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/autotask/client"
)

// Engine reconciles the remediation actions of Fix this week with the Autotask
// tickets that exist, and does it in one of two modes:
//
//   - dry run: reads (the company, the picklists, existing tickets) and writes
//     nothing to Autotask or to the tracked tickets. It returns the exact tickets
//     and notes it would send. Used by default, and a live run needs one behind
//     it with the same settings.
//   - live: creates, adds notes and (only if the operator allowed it) completes.
//
// It fails closed: settings that are incomplete or no longer match Autotask's
// picklists, refused credentials, an hour's request count past half the
// threshold, a spent budget: each stops the run with the reason, and nothing it
// could not check is assumed to be fine.
type Engine struct {
	// Desk is the Autotask client; nil makes an offline dry run (the tickets
	// are shown, marked unverified).
	Desk  Desk
	Store Store
	Now   func() time.Time
	// Actor is who the ledger names ("schedule", "manual:admin").
	Actor string
	// DryRunFingerprint is the fingerprint of the latest dry run that finished
	// without a problem; a live run needs it to equal the current settings'.
	DryRunFingerprint string
}

const (
	defaultTitleMax = 255
	defaultDescMax  = 8000
	defaultNoteMax  = 32000
	// thresholdStop: stop when the database's request count is at this share of
	// its hourly threshold. Autotask starts adding latency at 50 %.
	thresholdStop = 0.5

	kindPendingNote  = "pending-note"
	kindPendingClose = "pending-close"
)

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// plan is one decided action, before it is rendered and sent.
type plan struct {
	kind    string
	group   Group
	tracked *Tracked // the existing row (nil for a new ticket)
	gen     int
	delta   Delta
	// next is the tracked row after the action.
	next Tracked
	// reason is the flag's explanation.
	reason string
}

func sourceOf(key string) string {
	s, _, _ := strings.Cut(key, "|")
	return s
}

// env is what the execute phase needs.
type env struct {
	tf                         client.Fields
	set                        Settings
	now                        time.Time
	verified, live             bool
	psa                        map[int64]client.Ticket
	titleMax, descMax, noteMax int
}

// Run reconciles. It returns an error only for a failure of DefendSec's own
// storage; every Autotask problem is in the Result.
func (e *Engine) Run(ctx context.Context, set Settings, findings []Finding, mode string) (Result, error) {
	fp := set.Fingerprint()
	res := Result{Mode: mode, Problems: []string{}, Ops: []Op{}, Fingerprint: fp}
	live := mode == ModeLive
	if mode != ModeLive && mode != ModeDryRun {
		return res, fmt.Errorf("unknown mode %q", mode)
	}
	if live && set.Mode != ModeLive {
		res.Problems = append(res.Problems, "The settings are still in dry-run mode: tickets are shown, not opened. Switch the mode to live (after a dry run) to open them.")
		return res, nil
	}
	if live && e.DryRunFingerprint != fp {
		res.Problems = append(res.Problems, "No dry run has been shown for these exact settings. Run a dry run and look at the tickets it lists, then go live: the settings (company, queue, priorities, thresholds) changed since the last one.")
		return res, nil
	}
	if live && e.Desk == nil {
		res.Problems = append(res.Problems, "Autotask is not connected.")
		return res, nil
	}
	if miss := set.Missing(); len(miss) > 0 {
		res.Problems = append(res.Problems, "Choose "+joinAnd(miss)+" in the settings first: DefendSec does not guess an Autotask taxonomy.")
		return res, nil
	}

	groups := BuildGroups(findings, set)
	res.Groups = len(groups)
	tracked, err := e.Store.Tracked(ctx)
	if err != nil {
		return res, err
	}
	latest := map[string]*Tracked{}
	for i := range tracked {
		t := &tracked[i]
		if cur := latest[t.GroupKey]; cur == nil || t.Generation > cur.Generation {
			latest[t.GroupKey] = t
		}
	}

	// ---- what Autotask says -----------------------------------------------------------------
	v := env{set: set, now: e.now(), live: live, psa: map[int64]client.Ticket{},
		titleMax: defaultTitleMax, descMax: defaultDescMax, noteMax: defaultNoteMax}
	var tf, nf client.Fields
	if e.Desk != nil {
		var why string
		tf, nf, why = e.preflight(ctx, set, &res)
		switch {
		case why == "":
			v.verified = true
		case live:
			res.Problems = append(res.Problems, why)
			res.Requests = e.Desk.Requests()
			return res, nil
		default:
			res.UnverifiedWhy = why
		}
	} else {
		res.UnverifiedWhy = "Autotask was not read: no credentials are configured, so the company, the picklists and existing tickets are not checked. The tickets below are exactly what would be sent."
	}
	res.Verified = v.verified
	if v.verified {
		v.tf = tf
		if l := tf["title"].Length; l > 0 {
			v.titleMax = l
		}
		if l := tf["description"].Length; l > 0 {
			v.descMax = l
		}
		if l := nf["description"].Length; l > 0 {
			v.noteMax = l
		}
		var ids []int64
		for _, t := range latest {
			if t.State == StateOpen || t.State == StateResolved {
				ids = append(ids, t.TicketID)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if len(ids) > 0 {
			if v.psa, err = e.Desk.GetTickets(ctx, ids); err != nil {
				res.Problems = append(res.Problems, "Stopped while reading the tickets DefendSec follows: "+errText(err))
				res.Requests = e.Desk.Requests()
				return res, nil
			}
		}
	}

	// ---- plan -------------------------------------------------------------------------------
	plans, vanished := e.decide(groups, latest, v, &res)

	// Evidence for every member that is no longer open, one lookup per source.
	evidence, err := e.Store.Evidence(ctx, vanished)
	if err != nil {
		return res, err
	}
	var kept []*plan
	for _, p := range plans {
		e.finish(p, evidence, v)
		if p.kind == OpNote && p.delta.Empty() {
			continue
		}
		kept = append(kept, p)
	}

	// ---- execute (or show) ------------------------------------------------------------------
	creates, notes := 0, 0
	stopped := ""
	for _, p := range kept {
		if stopped != "" {
			for _, op := range e.dryOps(p, v) {
				op.Status, op.Reason = OpSkipped, stopped
				res.Ops = append(res.Ops, op)
			}
			continue
		}
		var ops []Op
		var fatal string
		switch p.kind {
		case OpCreate:
			if creates >= set.MaxCreates {
				for _, op := range e.dryOps(p, v) {
					op.Status, op.Reason = OpDeferred, fmt.Sprintf("Over this run's limit of %d new tickets; the next run opens it.", set.MaxCreates)
					res.Ops = append(res.Ops, op)
				}
				continue
			}
			creates++
			ops, fatal = e.doCreate(ctx, p, v)
		case OpNote:
			if notes >= MaxNotesPerRun {
				for _, op := range e.dryOps(p, v) {
					op.Status, op.Reason = OpDeferred, fmt.Sprintf("Over this run's limit of %d notes; the next run adds it.", MaxNotesPerRun)
					res.Ops = append(res.Ops, op)
				}
				continue
			}
			notes++
			ops, fatal = e.doNote(ctx, p, v)
		case OpComplete:
			ops, fatal = e.doComplete(ctx, p, v)
		case OpFlag:
			ops, fatal = e.doFlag(ctx, p, v)
		}
		res.Ops = append(res.Ops, ops...)
		if fatal != "" {
			stopped = "The run stopped before this: " + fatal
		}
	}
	tally(&res)
	if e.Desk != nil {
		res.Requests = e.Desk.Requests()
	}
	return res, nil
}

// decide turns groups and tracked tickets into plans, and lists the members that
// are no longer open (their evidence is looked up once).
func (e *Engine) decide(groups []Group, latest map[string]*Tracked, v env, res *Result) (plans []*plan, vanished []MemberRef) {
	set := v.set
	present := map[string]bool{}
	for _, g := range groups {
		present[g.Key] = true
	}
	for _, g := range groups {
		t := latest[g.Key]
		qualifies := UrgencyRank(g.Urgency) >= UrgencyRank(set.MinUrgency) && set.Priority(g.Urgency) != ""
		switch {
		case t == nil:
			if !qualifies {
				res.BelowThreshold++
				continue
			}
			plans = append(plans, &plan{kind: OpCreate, group: g, gen: 1})
		case t.State == StateOpen:
			pt, known := v.psa[t.TicketID]
			if v.verified && (!known || pt.Completed()) {
				next := *t
				next.State = StateClosedInPSA
				next.Members = memberStates(g.Members)
				next.Urgency = g.Urgency
				why := fmt.Sprintf("Ticket %s was completed in Autotask while %s still open in DefendSec. DefendSec leaves it alone and opens no second ticket for the same findings; a new host or finding would get a new one.", ticketName(*t), plural(len(g.Members), "member is", "members are"))
				if !known {
					why = fmt.Sprintf("Ticket %s was not found in Autotask (deleted, or the API user cannot see it) while %s still open in DefendSec. DefendSec does not recreate it; a new host or finding would get a new ticket.", ticketName(*t), plural(len(g.Members), "member is", "members are"))
				}
				plans = append(plans, &plan{kind: OpFlag, group: g, tracked: t, next: next, gen: t.Generation, reason: why})
				continue
			}
			d, gone := diffGroup(*t, g)
			d.Open = len(g.Members)
			for _, k := range gone {
				vanished = append(vanished, MemberRef{GroupKey: t.GroupKey, MemberKey: k, Since: t.CreatedAt})
			}
			plans = append(plans, &plan{kind: kindPendingNote, group: g, tracked: t, delta: d, gen: t.Generation})
		case t.State == StateClosedInPSA:
			fresh := 0
			for _, m := range g.Members {
				if _, had := t.Members[m.Key]; !had {
					fresh++
				}
			}
			if fresh > 0 && qualifies {
				plans = append(plans, &plan{kind: OpCreate, group: g, gen: t.Generation + 1})
			}
		case t.State == StateResolved:
			pt, known := v.psa[t.TicketID]
			if v.verified && !(known && !pt.Completed()) {
				// The old ticket was completed (or is gone): a new one, if it qualifies.
				if qualifies {
					plans = append(plans, &plan{kind: OpCreate, group: g, gen: t.Generation + 1})
				}
				continue
			}
			// The old ticket is still open (or an offline dry run cannot tell): say so on it.
			next := *t
			next.State = StateOpen
			next.Members = memberStates(g.Members)
			next.Urgency = g.Urgency
			next.ResolvedAt = nil
			plans = append(plans, &plan{kind: OpNote, group: g, tracked: t, gen: t.Generation, next: next,
				delta: Delta{Returned: true, Joined: g.Members, Open: len(g.Members)}})
		}
	}
	for key, t := range latest {
		if present[key] {
			continue
		}
		switch t.State {
		case StateOpen:
			pt, known := v.psa[t.TicketID]
			if v.verified && (!known || pt.Completed()) {
				next := *t
				next.State = StateResolved
				rt := v.now
				next.ResolvedAt = &rt
				next.Members = map[string]MemberState{}
				plans = append(plans, &plan{kind: OpFlag, tracked: t, next: next, gen: t.Generation,
					reason: fmt.Sprintf("Nothing of ticket %s's action is open in DefendSec any more, and the ticket is already completed in Autotask (or gone): nothing to add.", ticketName(*t))})
				continue
			}
			if len(t.Members) == 0 {
				// The note that says "all resolved" was sent by an earlier run that
				// then failed to complete the ticket.
				next := *t
				next.State = StateResolved
				rt := v.now
				next.ResolvedAt = &rt
				if set.AutoComplete {
					plans = append(plans, &plan{kind: OpComplete, tracked: t, next: next, gen: t.Generation})
				} else {
					plans = append(plans, &plan{kind: OpFlag, tracked: t, next: next, gen: t.Generation,
						reason: fmt.Sprintf("Ticket %s: auto-complete was switched off before DefendSec completed it; it stays open for a person to close.", ticketName(*t))})
				}
				continue
			}
			for _, k := range sortedKeys(t.Members) {
				vanished = append(vanished, MemberRef{GroupKey: t.GroupKey, MemberKey: k, Since: t.CreatedAt})
			}
			plans = append(plans, &plan{kind: kindPendingClose, tracked: t, gen: t.Generation})
		case StateClosedInPSA:
			next := *t
			next.State = StateResolved
			rt := v.now
			next.ResolvedAt = &rt
			plans = append(plans, &plan{kind: OpFlag, tracked: t, next: next, gen: t.Generation,
				reason: "Nothing of this action is open in DefendSec any more (its ticket was already completed in Autotask)."})
		}
	}
	// Map iteration above is random: order the plans so a run is reproducible.
	sort.SliceStable(plans, func(i, j int) bool { return planKey(plans[i]) < planKey(plans[j]) })
	return plans, vanished
}

func planKey(p *plan) string {
	key := p.group.Key
	if key == "" && p.tracked != nil {
		key = p.tracked.GroupKey
	}
	return fmt.Sprintf("%d|%s", 3-UrgencyRank(planUrgency(p)), key)
}

func planUrgency(p *plan) string {
	if p.group.Key != "" {
		return p.group.Urgency
	}
	if p.tracked != nil {
		return p.tracked.Urgency
	}
	return UrgencyLow
}

// finish completes the plans that waited for evidence.
func (e *Engine) finish(p *plan, evidence map[MemberRef]Evidence, v env) {
	switch p.kind {
	case kindPendingNote:
		t := p.tracked
		cur := indexMembers(p.group.Members)
		for _, k := range sortedKeys(t.Members) {
			if _, still := cur[k]; !still {
				p.delta.Resolved = append(p.delta.Resolved, ResolvedLine(t.Members[k].Label, evidence[MemberRef{GroupKey: t.GroupKey, MemberKey: k, Since: t.CreatedAt}]))
			}
		}
		next := *t
		next.Members = memberStates(p.group.Members)
		next.Urgency = p.group.Urgency
		p.next = next
		p.kind = OpNote
	case kindPendingClose:
		t := p.tracked
		d := Delta{AllResolved: true, Completing: v.set.AutoComplete}
		for _, k := range sortedKeys(t.Members) {
			d.Resolved = append(d.Resolved, ResolvedLine(t.Members[k].Label, evidence[MemberRef{GroupKey: t.GroupKey, MemberKey: k, Since: t.CreatedAt}]))
		}
		p.delta = d
		next := *t
		next.State = StateResolved
		rt := v.now
		next.ResolvedAt = &rt
		next.Members = map[string]MemberState{}
		p.next = next
		p.kind = OpNote
	}
}

func tally(r *Result) {
	for i := range r.Ops {
		o := &r.Ops[i]
		switch o.Status {
		case OpFailed:
			r.Failed++
			continue
		case OpDeferred:
			r.Deferred++
			continue
		case OpSkipped:
			continue
		}
		switch o.Kind {
		case OpCreate:
			r.Created++
		case OpNote:
			r.Noted++
		case OpComplete:
			r.Completed++
		case OpFlag:
			if strings.Contains(o.Reason, "was completed in Autotask while") || strings.Contains(o.Reason, "was not found in Autotask") {
				r.Flagged++
			}
		}
	}
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func ticketName(t Tracked) string {
	if t.TicketNumber != "" {
		return t.TicketNumber
	}
	return "#" + strconv.FormatInt(t.TicketID, 10)
}

func memberStates(ms []Member) map[string]MemberState {
	out := make(map[string]MemberState, len(ms))
	for _, m := range ms {
		out[m.Key] = MemberState{Label: m.Label, Digest: m.Digest}
	}
	return out
}

func indexMembers(ms []Member) map[string]Member {
	out := make(map[string]Member, len(ms))
	for _, m := range ms {
		out[m.Key] = m
	}
	return out
}

// diffGroup compares what a ticket last heard with what is open now.
func diffGroup(t Tracked, g Group) (d Delta, gone []string) {
	cur := map[string]Member{}
	for _, m := range g.Members {
		cur[m.Key] = m
		old, had := t.Members[m.Key]
		switch {
		case !had:
			d.Joined = append(d.Joined, m)
		case old.Digest != m.Digest:
			d.Changed = append(d.Changed, m)
		}
	}
	for _, k := range sortedKeys(t.Members) {
		if _, still := cur[k]; !still {
			gone = append(gone, k)
		}
	}
	if t.Urgency != "" && UrgencyRank(g.Urgency) > UrgencyRank(t.Urgency) {
		d.UrgencyFrom, d.UrgencyTo = t.Urgency, g.Urgency
	}
	return d, gone
}

// preflight reads what must be right before anything is shown as exact or sent:
// the hourly request count, the company, and the live picklists. why is empty
// when all is well.
func (e *Engine) preflight(ctx context.Context, set Settings, res *Result) (tf, nf client.Fields, why string) {
	th, err := e.Desk.Threshold(ctx)
	if err != nil {
		return nil, nil, "Autotask could not be read: " + errText(err)
	}
	if float64(th.CurrentTimeframeRequestCount) >= thresholdStop*float64(th.ExternalRequestThreshold) {
		return nil, nil, fmt.Sprintf("Autotask reports %d of %d requests used in the last %d minutes by every integration of this database. DefendSec stops at half, where Autotask starts slowing every request down, and runs again when the count is lower.",
			th.CurrentTimeframeRequestCount, th.ExternalRequestThreshold, th.RequestThresholdTimeframe)
	}
	co, err := e.Desk.Company(ctx, set.CompanyID)
	if err != nil {
		return nil, nil, "The company could not be read: " + errText(err)
	}
	if !co.IsActive {
		return nil, nil, fmt.Sprintf("The company %q (%d) is not active in Autotask.", co.CompanyName, co.ID)
	}
	res.CompanyName = co.CompanyName
	if tf, err = e.Desk.TicketFields(ctx); err != nil {
		return nil, nil, "The ticket picklists could not be read: " + errText(err)
	}
	if nf, err = e.Desk.NoteFields(ctx); err != nil {
		return nil, nil, "The note picklists could not be read: " + errText(err)
	}
	if bad := set.CheckAgainst(tf, nf); len(bad) > 0 {
		res.Problems = append(res.Problems, bad...)
		return tf, nf, "The settings no longer match Autotask: " + strings.Join(bad, "; ") + "."
	}
	return tf, nf, ""
}

func errText(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.Error()
	}
	return "unexpected failure"
}

// ---- rendering and sending ----------------------------------------------------------------

func parsePick(v string) int64 {
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func (e *Engine) payload(g Group, tag string, gen int, v env) client.TicketCreate {
	set := v.set
	q, _ := pickInt(set.QueueID)
	src, _ := pickInt(set.Source)
	it, _ := pickInt(set.IssueType)
	sub, _ := pickInt(set.SubIssueType)
	due := v.now.AddDate(0, 0, set.DueDays(g.Urgency)).Truncate(time.Second)
	return client.TicketCreate{
		CompanyID:    set.CompanyID,
		Title:        TitleWithTag(g.Title, tag, v.titleMax),
		Description:  Description(g, tag, gen, v.now, v.descMax),
		Status:       parsePick(set.Status),
		Priority:     parsePick(set.Priority(g.Urgency)),
		QueueID:      q,
		Source:       src,
		IssueType:    it,
		SubIssueType: sub,
		DueDateTime:  due.Format("2006-01-02T15:04:05.00"),
	}
}

func (e *Engine) noteOp(p *plan, v env) Op {
	t := p.tracked
	return Op{Kind: OpNote, Status: OpPlanned, GroupKey: t.GroupKey, Tag: t.Tag, Urgency: p.next.Urgency, TicketID: t.TicketID,
		TicketNumber: t.TicketNumber, Title: t.Title, Note: NoteText(p.delta, v.noteMax), Members: len(p.next.Members)}
}

func (e *Engine) createOp(p *plan, v env) Op {
	tag := Tag(p.group.Key, p.gen)
	pl := e.payload(p.group, tag, p.gen, v)
	reason := "A new ticket for this action."
	if p.gen > 1 {
		reason = fmt.Sprintf("A new ticket (number %d for this action): the earlier one was completed in Autotask.", p.gen)
	}
	return Op{Kind: OpCreate, Status: OpPlanned, GroupKey: p.group.Key, Tag: tag, Urgency: p.group.Urgency, Title: pl.Title,
		Create: &pl, Labels: pickLabels(v.tf, pl), Members: len(p.group.Members), Reason: reason}
}

// pickLabels names the picklist values of a ticket as Autotask's live lists do.
func pickLabels(tf client.Fields, pl client.TicketCreate) map[string]string {
	if tf == nil {
		return nil
	}
	out := map[string]string{}
	add := func(key, field string, val *int64) {
		if val == nil {
			return
		}
		if l := tf.Label(field, strconv.FormatInt(*val, 10)); l != "" {
			out[key] = l
		}
	}
	add("queue", "queueID", pl.QueueID)
	add("source", "source", pl.Source)
	add("issueType", "issueType", pl.IssueType)
	add("subIssueType", "subIssueType", pl.SubIssueType)
	st, pr := pl.Status, pl.Priority
	add("status", "status", &st)
	add("priority", "priority", &pr)
	return out
}

func (e *Engine) flagOp(p *plan) Op {
	t := p.tracked
	return Op{Kind: OpFlag, Status: OpPlanned, GroupKey: t.GroupKey, Tag: t.Tag, TicketID: t.TicketID, TicketNumber: t.TicketNumber, Title: t.Title, Reason: p.reason}
}

// dryOps is the content of a plan without sending it.
func (e *Engine) dryOps(p *plan, v env) []Op {
	switch p.kind {
	case OpCreate:
		return []Op{e.createOp(p, v)}
	case OpNote:
		return []Op{e.noteOp(p, v)}
	case OpComplete:
		t := p.tracked
		return []Op{{Kind: OpComplete, Status: OpPlanned, GroupKey: t.GroupKey, Tag: t.Tag, TicketID: t.TicketID, TicketNumber: t.TicketNumber, Title: t.Title}}
	}
	return []Op{e.flagOp(p)}
}

func (e *Engine) ledgerDetail(t Tracked, extra map[string]any) map[string]any {
	d := map[string]any{"groupKey": t.GroupKey, "generation": t.Generation, "tag": t.Tag, "ticketId": t.TicketID, "ticketNumber": t.TicketNumber,
		"companyId": t.CompanyID, "urgency": t.Urgency, "members": len(t.Members)}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// fail records a failed op and says whether the run must stop.
func fail(op *Op, err error) (fatal string) {
	op.Status = OpFailed
	op.Error = errText(err)
	if client.IsAmbiguous(err) {
		op.Reason = "It may have been carried out; the next run checks before doing it again."
	}
	if client.IsFatal(err) {
		return op.Error
	}
	return ""
}

// storeFail records that DefendSec's own record could not be written; the run
// stops, because every later action would be unrecorded too.
func storeFail(op *Op, what string) string {
	op.Status, op.Error = OpFailed, what
	return what
}

func (e *Engine) doCreate(ctx context.Context, p *plan, v env) ([]Op, string) {
	op := e.createOp(p, v)
	set := v.set
	if !v.live {
		if v.verified {
			if found, err := e.Desk.FindTickets(ctx, set.CompanyID, op.Tag); err == nil && len(found) > 0 {
				op.Kind, op.TicketID, op.TicketNumber = OpAdopt, found[0].ID, found[0].TicketNumber
				op.Reason = fmt.Sprintf("Autotask already has ticket %s with this tag: it would be adopted, not duplicated.", found[0].TicketNumber)
			}
		}
		return []Op{op}, ""
	}
	pl := *op.Create
	next := Tracked{GroupKey: p.group.Key, Generation: p.gen, Tag: op.Tag, CompanyID: set.CompanyID, Title: pl.Title, State: StateOpen,
		Urgency: p.group.Urgency, Members: memberStates(p.group.Members), CreatedAt: v.now, UpdatedAt: v.now}

	found, err := e.Desk.FindTickets(ctx, set.CompanyID, op.Tag)
	if err != nil {
		return []Op{op}, fail(&op, err)
	}
	if len(found) > 0 {
		sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
		tk := found[0]
		next.TicketID, next.TicketNumber = tk.ID, tk.TicketNumber
		if tk.Completed() {
			next.State = StateClosedInPSA
		}
		op.Kind, op.TicketID, op.TicketNumber = OpAdopt, tk.ID, tk.TicketNumber
		op.Reason = fmt.Sprintf("Ticket %s with this tag already existed (an earlier run stopped before it recorded it): adopted, not duplicated.", tk.TicketNumber)
		if len(found) > 1 {
			op.Reason += fmt.Sprintf(" %d tickets carry the tag; the oldest was adopted.", len(found))
		}
		if err := e.Store.Commit(ctx, e.Actor, Change{Action: "autotask_ticket_adopted", Tracked: next, Detail: e.ledgerDetail(next, nil)}); err != nil {
			return []Op{op}, storeFail(&op, "DefendSec could not record the adopted ticket")
		}
		op.Status = OpDone
		return []Op{op}, ""
	}
	id, err := e.Desk.CreateTicket(ctx, pl)
	if err != nil {
		return []Op{op}, fail(&op, err)
	}
	next.TicketID = id
	if got, gerr := e.Desk.GetTickets(ctx, []int64{id}); gerr == nil {
		next.TicketNumber = got[id].TicketNumber
	}
	op.TicketID, op.TicketNumber = next.TicketID, next.TicketNumber
	if err := e.Store.Commit(ctx, e.Actor, Change{Action: "autotask_ticket_created", Tracked: next, Detail: e.ledgerDetail(next, map[string]any{
		"title": pl.Title, "priority": pl.Priority, "queueId": pl.QueueID, "dueDateTime": pl.DueDateTime})}); err != nil {
		return []Op{op}, storeFail(&op, fmt.Sprintf("ticket #%d was created but DefendSec could not record it; the next run finds it by its tag", id))
	}
	op.Status = OpDone
	return []Op{op}, ""
}

func (e *Engine) doNote(ctx context.Context, p *plan, v env) ([]Op, string) {
	op := e.noteOp(p, v)
	set := v.set
	t := p.tracked
	completeNeeded := p.delta.AllResolved && set.AutoComplete
	complete := func() Op {
		return Op{Kind: OpComplete, Status: OpPlanned, GroupKey: t.GroupKey, Tag: t.Tag, TicketID: t.TicketID, TicketNumber: t.TicketNumber, Title: t.Title,
			Reason: "Auto-complete is on and nothing of this action is open any more."}
	}
	if !v.live {
		ops := []Op{op}
		if completeNeeded {
			ops = append(ops, complete())
		}
		return ops, ""
	}
	_, err := e.Desk.CreateNote(ctx, client.NoteCreate{TicketID: t.TicketID, Title: NoteTitle(e.now()), Description: op.Note,
		NoteType: parsePick(set.NoteType), Publish: parsePick(set.NotePublish)})
	if err != nil {
		return []Op{op}, fail(&op, err)
	}
	next := p.next
	next.UpdatedAt = e.now()
	if completeNeeded {
		// The row stays "open", with no members, until the completion is recorded:
		// a run that finds an open ticket with no members left knows the note was
		// sent and only completes, so a failed completion is retried without a
		// second note.
		next.State = StateOpen
		next.ResolvedAt = nil
	}
	if err := e.Store.Commit(ctx, e.Actor, Change{Action: "autotask_ticket_note_added", Tracked: next, Detail: e.ledgerDetail(next, map[string]any{
		"joined": len(p.delta.Joined), "changed": len(p.delta.Changed), "resolved": len(p.delta.Resolved),
		"allResolved": p.delta.AllResolved, "returned": p.delta.Returned})}); err != nil {
		return []Op{op}, storeFail(&op, "the note was added but DefendSec could not record it")
	}
	op.Status = OpDone
	ops := []Op{op}
	if !completeNeeded {
		return ops, ""
	}
	cop := complete()
	final := p.next
	final.State = StateResolved
	rt := v.now
	final.ResolvedAt = &rt
	fatal := e.completeTicket(ctx, &cop, final, v)
	return append(ops, cop), fatal
}

// completeTicket sets the completed status and records the resolution.
func (e *Engine) completeTicket(ctx context.Context, op *Op, final Tracked, v env) string {
	if err := e.Desk.SetTicketStatus(ctx, final.TicketID, parsePick(v.set.CompleteStatus)); err != nil {
		return fail(op, err)
	}
	final.UpdatedAt = e.now()
	if err := e.Store.Commit(ctx, e.Actor, Change{Action: "autotask_ticket_completed", Tracked: final, Detail: e.ledgerDetail(final, map[string]any{"status": v.set.CompleteStatus})}); err != nil {
		return storeFail(op, "the ticket was completed but DefendSec could not record it")
	}
	op.Status = OpDone
	return ""
}

// doComplete finishes an auto-completion whose note was already sent.
func (e *Engine) doComplete(ctx context.Context, p *plan, v env) ([]Op, string) {
	t := p.tracked
	op := Op{Kind: OpComplete, Status: OpPlanned, GroupKey: t.GroupKey, Tag: t.Tag, TicketID: t.TicketID, TicketNumber: t.TicketNumber, Title: t.Title,
		Reason: "Auto-complete is on, nothing of this action is open any more, and the note saying so was already added."}
	if !v.live {
		return []Op{op}, ""
	}
	return []Op{op}, e.completeTicket(ctx, &op, p.next, v)
}

func (e *Engine) doFlag(ctx context.Context, p *plan, v env) ([]Op, string) {
	op := e.flagOp(p)
	if !v.live {
		return []Op{op}, ""
	}
	next := p.next
	next.UpdatedAt = e.now()
	if err := e.Store.Commit(ctx, e.Actor, Change{Action: "autotask_ticket_state", Tracked: next, Detail: e.ledgerDetail(next, map[string]any{"state": next.State, "why": op.Reason})}); err != nil {
		return []Op{op}, storeFail(&op, "DefendSec could not record the ticket's state")
	}
	op.Status = OpDone
	return []Op{op}, ""
}
