package autotask

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// The idempotency key lives on both sides. DefendSec keeps it in its own table
// (autotask_tickets, one row per action and generation). On the Autotask side it
// is a short tag in the ticket's title, "[DS-3f9a1c0b2e]", and a footer line in
// the description. The title carries it because the title is a field Autotask lets
// a query search with "contains"; the "External" fields are not used, because
// Autotask asks integrations to leave them to the customer.
//
// So a re-run never opens a second ticket: if the local row is there it is used;
// if the row was lost (a crash between creating the ticket and saving the row) the
// ticket is found again by its tag before another is created.

// Tag is the visible key of an action's ticket. A new generation (a ticket opened
// again after the first was completed) has its own.
func Tag(groupKey string, generation int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("defendsec-autotask\x00%s\x00%d", groupKey, generation)))
	return "DS-" + hex.EncodeToString(h[:])[:10]
}

// TitleWithTag appends the tag to a title, shortening the title (never the tag)
// to fit max characters (Autotask's title field is 255).
func TitleWithTag(base, tag string, max int) string {
	suffix := " [" + tag + "]"
	room := max - utf8.RuneCountInString(suffix)
	return truncRunes(strings.Join(strings.Fields(base), " "), room) + suffix
}

func truncRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

const timeLayout = "2006-01-02 15:04 UTC"

// Description is the ticket body: what, why it ranks, who is affected, how to fix
// it, where to look in DefendSec, and the key. It fits max characters (Autotask's
// description field is 8000): members are listed until the room runs out and the
// rest are counted, never the footer.
func Description(g Group, tag string, generation int, now time.Time, max int) string {
	var head strings.Builder
	head.WriteString("DefendSec: Fix this week\n")
	head.WriteString(g.Title + "\n\n")
	head.WriteString("Why it ranks: " + g.Why + "\n")
	head.WriteString("Urgency: " + g.Urgency + "\n\n")

	var tail strings.Builder
	tail.WriteString("\nHow to fix:\n" + strings.TrimSpace(g.Fix) + "\n")
	if g.Link != "" {
		tail.WriteString("\nIn DefendSec: " + g.Link + "\n")
	}
	fmt.Fprintf(&tail, "\n---\nDefendSec key: %s | action: %s | opened %s\nDo not edit the key: DefendSec finds this ticket by it. DefendSec adds notes here when hosts or findings join and when it sees them fixed.", tag, g.Key, now.UTC().Format("2006-01-02"))

	room := max - utf8.RuneCountInString(head.String()) - utf8.RuneCountInString(tail.String())
	var list strings.Builder
	fmt.Fprintf(&list, "Affected (%d):\n", len(g.Members))
	listed := 0
	for _, m := range g.Members {
		line := "- " + m.Line + "\n"
		more := fmt.Sprintf("- and %d more; DefendSec has the full list\n", len(g.Members)-listed-1)
		if utf8.RuneCountInString(list.String())+utf8.RuneCountInString(line)+utf8.RuneCountInString(more) > room && listed < len(g.Members)-1 {
			break
		}
		if utf8.RuneCountInString(list.String())+utf8.RuneCountInString(line) > room {
			line = "- " + truncRunes(m.Line, 200) + "\n"
		}
		list.WriteString(line)
		listed++
	}
	if listed < len(g.Members) {
		fmt.Fprintf(&list, "- and %d more; DefendSec has the full list\n", len(g.Members)-listed)
	}
	out := head.String() + list.String() + tail.String()
	if utf8.RuneCountInString(out) > max {
		// The footer must survive; whatever else is over goes.
		out = truncRunes(head.String()+list.String(), max-utf8.RuneCountInString(tail.String())-1) + "\n" + tail.String()
	}
	return out
}

// Delta is what changed in an action since its ticket last heard of it.
type Delta struct {
	Joined  []Member
	Changed []Member
	// Resolved lines say how each member that is no longer open closed.
	Resolved    []string
	UrgencyFrom string
	UrgencyTo   string
	// Returned: the action was resolved and its findings are back.
	Returned bool
	// AllResolved: nothing of the action is open any more.
	AllResolved bool
	// Completing says what happens to the ticket: "completing" (auto-complete is
	// on) or "left open" (it is off, the default).
	Completing bool
	Open       int
}

// Empty reports whether there is nothing to tell.
func (d Delta) Empty() bool {
	return len(d.Joined) == 0 && len(d.Changed) == 0 && len(d.Resolved) == 0 && d.UrgencyFrom == "" && !d.Returned && !d.AllResolved
}

// NoteTitle is the note's title.
func NoteTitle(now time.Time) string { return "DefendSec update " + now.UTC().Format(timeLayout) }

// NoteText words a Delta for a ticket note, within max characters.
func NoteText(d Delta, max int) string {
	var b strings.Builder
	section := func(head string, lines []string) {
		if len(lines) == 0 {
			return
		}
		b.WriteString(head + "\n")
		for _, l := range lines {
			b.WriteString("- " + l + "\n")
		}
		b.WriteString("\n")
	}
	if d.Returned {
		b.WriteString("DefendSec sees this again: findings of this action are open after they had been resolved.\n\n")
	}
	var joined, changed []string
	for _, m := range d.Joined {
		joined = append(joined, m.Line)
	}
	for _, m := range d.Changed {
		changed = append(changed, m.Line)
	}
	section(fmt.Sprintf("New since this ticket was opened (%d):", len(joined)), joined)
	section(fmt.Sprintf("What is open changed on (%d):", len(changed)), changed)
	section(fmt.Sprintf("No longer open (%d):", len(d.Resolved)), d.Resolved)
	if d.UrgencyFrom != "" {
		fmt.Fprintf(&b, "Urgency went from %s to %s. This ticket's priority was not changed; raise it if you agree.\n\n", d.UrgencyFrom, d.UrgencyTo)
	}
	switch {
	case d.AllResolved && d.Completing:
		b.WriteString("DefendSec no longer sees any open finding for this action. Auto-complete is on, so DefendSec is completing this ticket.\n")
	case d.AllResolved:
		b.WriteString("DefendSec no longer sees any open finding for this action. The ticket is left open: close it when you have checked.\n")
	default:
		fmt.Fprintf(&b, "Still open in DefendSec: %d.\n", d.Open)
	}
	return truncRunes(strings.TrimRight(b.String(), "\n"), max)
}

// ResolvedLine words one member that closed, from the evidence.
func ResolvedLine(label string, ev Evidence) string {
	if !ev.Found {
		return fmt.Sprintf("%s: no longer reported by DefendSec (the host, asset or account was removed, so how it closed is not on record)", label)
	}
	return fmt.Sprintf("%s: %s at %s", label, ev.Detail, ev.ResolvedAt.UTC().Format(timeLayout))
}
