package idposture

import (
	"sort"
	"strings"
)

// DefaultFinanceTerms are the words and senders that mark mail a fraudster wants
// hidden: the payment-redirection pattern of a business email compromise. They
// match whole words, case-insensitively, in a rule's sender and keyword
// conditions, so "ach" matches "ACH payment" and not "reach". The operator can
// add terms (settings); the defaults are not removable, because a client that
// never typed a term should still be covered.
var DefaultFinanceTerms = []string{
	"invoice", "payment", "remittance", "wire", "ach", "bank", "quickbooks", "intuit",
	"payroll", "bill.com", "purchase order", "direct deposit",
}

// DefaultSecurityTerms are the words of the mail an attacker hides so the owner
// does not see a security notice about the account itself.
var DefaultSecurityTerms = []string{
	"security alert", "password", "verification code", "sign-in", "suspicious", "unusual activity",
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// ContainsTerm reports whether haystack contains term as a whole word (or
// phrase), case-insensitively. A term that starts or ends with a letter or digit
// must not be glued to another letter or digit there.
func ContainsTerm(haystack, term string) bool {
	h, t := strings.ToLower(haystack), strings.ToLower(strings.TrimSpace(term))
	if t == "" {
		return false
	}
	for from := 0; from <= len(h)-len(t); {
		i := strings.Index(h[from:], t)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(t)
		startOK := !isAlnum(t[0]) || i == 0 || !isAlnum(h[i-1])
		endOK := !isAlnum(t[len(t)-1]) || end == len(h) || !isAlnum(h[end])
		if startOK && endOK {
			return true
		}
		from = i + 1
	}
	return false
}

// ConditionText is one of a rule's conditions with where it is.
type ConditionText struct {
	Where string // "sender", "subject keyword", "body keyword", "recipient", ...
	Text  string
}

// Match is a term found in a condition.
type Match struct {
	Term  string `json:"term"`
	Where string `json:"in"`
}

// FindTerms lists the terms found in the conditions, once per term and place.
func FindTerms(texts []ConditionText, terms []string) []Match {
	var out []Match
	seen := map[string]bool{}
	for _, c := range texts {
		for _, t := range terms {
			if ContainsTerm(c.Text, t) {
				k := c.Where + "\x00" + strings.ToLower(t)
				if !seen[k] {
					seen[k] = true
					out = append(out, Match{Term: strings.ToLower(t), Where: c.Where})
				}
			}
		}
	}
	return out
}

// DomainOf is the lower-case domain of an address, or "" when it has none.
func DomainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[i+1:]))
}

// Dedupe drops repeats of a string, ignoring case, keeping the first spelling.
func Dedupe(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// QuoteList writes strings in typographic quotes, comma separated.
func QuoteList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = "“" + s + "”"
	}
	return strings.Join(q, ", ")
}

// TermList is the distinct terms of the matches, sorted, comma separated.
func TermList(ms []Match) string {
	seen := map[string]bool{}
	var t []string
	for _, m := range ms {
		if !seen[m.Term] {
			seen[m.Term] = true
			t = append(t, m.Term)
		}
	}
	sort.Strings(t)
	return strings.Join(t, ", ")
}

// WithExtraTerms returns the default finance words plus the operator's own.
func WithExtraTerms(extra []string) []string {
	fin := append([]string{}, DefaultFinanceTerms...)
	for _, t := range extra {
		if t = strings.TrimSpace(t); t != "" {
			fin = append(fin, t)
		}
	}
	return fin
}
