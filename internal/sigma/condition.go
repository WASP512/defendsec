package sigma

import (
	"fmt"
	"strings"

	"defendsec/internal/events"
)

// The condition expression language.
//
// Sigma conditions are small but not trivial: `selection and not filter`,
// `(sel1 or sel2) and not (filter1 or filter2)`, `all of selection_*`,
// `1 of them`. A regular expression would handle the first two and quietly
// mis-parse the rest, so this is a real tokeniser and a precedence-climbing
// parser. It is about a hundred lines and it is correct, which matters because
// a mis-parsed condition produces a rule that looks fine and fires on the
// wrong events — or on all of them.

type expr interface {
	eval(e *events.Event, selections map[string]matcher) bool
}

type refExpr struct{ name string }

func (r refExpr) eval(e *events.Event, selections map[string]matcher) bool {
	m, ok := selections[r.name]
	if !ok {
		return false
	}
	return m.match(e)
}

type notExpr struct{ inner expr }

func (n notExpr) eval(e *events.Event, selections map[string]matcher) bool {
	return !n.inner.eval(e, selections)
}

type andExpr struct{ left, right expr }

func (a andExpr) eval(e *events.Event, selections map[string]matcher) bool {
	return a.left.eval(e, selections) && a.right.eval(e, selections)
}

type orExpr struct{ left, right expr }

func (o orExpr) eval(e *events.Event, selections map[string]matcher) bool {
	return o.left.eval(e, selections) || o.right.eval(e, selections)
}

// quantExpr is "all of X" / "1 of X" / "any of X".
type quantExpr struct {
	names []string
	all   bool
}

func (q quantExpr) eval(e *events.Event, selections map[string]matcher) bool {
	if len(q.names) == 0 {
		// "1 of selection_*" with nothing matching the pattern is false;
		// "all of" over an empty set would vacuously be true, which is not
		// what a rule author means, so both are false.
		return false
	}
	for _, name := range q.names {
		m, ok := selections[name]
		if !ok {
			if q.all {
				return false
			}
			continue
		}
		if m.match(e) {
			if !q.all {
				return true
			}
			continue
		}
		if q.all {
			return false
		}
	}
	return q.all
}

// --- tokenising ---

type token struct {
	kind  string // "ident", "(", ")", "and", "or", "not", "of", "number"
	value string
}

func tokenize(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			out = append(out, token{kind: string(c)})
			i++
		default:
			start := i
			for i < len(s) && !strings.ContainsRune(" \t\n\r()", rune(s[i])) {
				i++
			}
			word := s[start:i]
			switch strings.ToLower(word) {
			case "and", "or", "not", "of", "them":
				out = append(out, token{kind: strings.ToLower(word), value: word})
			default:
				out = append(out, token{kind: "ident", value: word})
			}
		}
	}
	return out
}

// --- parsing ---

type parser struct {
	tokens     []token
	pos        int
	selections []string
}

// parseCondition compiles a condition against the rule's selection names.
func parseCondition(condition string, selections []string) (expr, error) {
	if strings.TrimSpace(condition) == "" {
		return nil, fmt.Errorf("condition is empty")
	}
	p := &parser{tokens: tokenize(condition), selections: selections}
	e, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("unexpected %q in condition %q", p.tokens[p.pos].value, condition)
	}
	return e, nil
}

func (p *parser) peek() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos]
}

func (p *parser) parseOr() (expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind != "or" {
			return left, nil
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orExpr{left: left, right: right}
	}
}

func (p *parser) parseAnd() (expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind != "and" {
			return left, nil
		}
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andExpr{left: left, right: right}
	}
}

func (p *parser) parseUnary() (expr, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("condition ends unexpectedly")
	}
	if t.kind == "not" {
		p.pos++
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notExpr{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (expr, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("condition ends unexpectedly")
	}

	if t.kind == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closing := p.peek()
		if closing == nil || closing.kind != ")" {
			return nil, fmt.Errorf("unbalanced parenthesis in condition")
		}
		p.pos++
		return inner, nil
	}

	if t.kind != "ident" {
		return nil, fmt.Errorf("unexpected %q in condition", t.value)
	}

	// "all of X" / "1 of X" / "any of X".
	word := strings.ToLower(t.value)
	if word == "all" || word == "1" || word == "any" {
		if next := p.lookahead(1); next != nil && next.kind == "of" {
			p.pos += 2
			target := p.peek()
			if target == nil {
				return nil, fmt.Errorf("%q of what?", word)
			}
			p.pos++
			names, err := p.resolveTargets(target)
			if err != nil {
				return nil, err
			}
			return quantExpr{names: names, all: word == "all"}, nil
		}
	}

	p.pos++
	// A reference to a selection that does not exist is a rule that can never
	// fire as written. Usually a typo, occasionally a half-edited rule, and
	// either way worth refusing rather than silently evaluating to false.
	if !p.known(t.value) {
		return nil, fmt.Errorf("condition references %q, which is not a selection in this rule", t.value)
	}
	return refExpr{name: t.value}, nil
}

func (p *parser) lookahead(n int) *token {
	if p.pos+n >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos+n]
}

func (p *parser) known(name string) bool {
	for _, s := range p.selections {
		if s == name {
			return true
		}
	}
	return false
}

// resolveTargets expands "them" and wildcard selection references.
func (p *parser) resolveTargets(t *token) ([]string, error) {
	if t.kind == "them" {
		return append([]string(nil), p.selections...), nil
	}
	if t.kind != "ident" {
		return nil, fmt.Errorf("unexpected %q after 'of'", t.value)
	}
	pattern := t.value
	if !strings.ContainsAny(pattern, "*?") {
		if !p.known(pattern) {
			return nil, fmt.Errorf("condition references %q, which is not a selection in this rule", pattern)
		}
		return []string{pattern}, nil
	}

	re, err := wildcardRegexp(strings.ToLower(pattern))
	if err != nil {
		return nil, fmt.Errorf("unusable selection pattern %q", pattern)
	}
	var out []string
	for _, name := range p.selections {
		if re.MatchString(strings.ToLower(name)) {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no selection matches %q", pattern)
	}
	return out, nil
}
