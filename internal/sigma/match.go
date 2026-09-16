package sigma

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"defendsec/internal/events"
)

// Field matching.
//
// Sigma's comparison rules are specific and easy to get subtly wrong, and
// wrong here means a rule that looks right and never fires. The ones that
// matter:
//
//   - String comparison is case-insensitive by default. A rule written for
//     "cmd.exe" must match "CMD.EXE", and on Linux the same applies to values
//     that are case-normalised by the tooling that produced them.
//   - A list of values is an OR. A map of fields is an AND.
//   - "*" is a wildcard and "?" matches one character, in plain values —
//     which means a literal asterisk in a value has to be escaped, and a rule
//     that does not escape it gets wildcard behaviour. That is Sigma's rule,
//     not ours.
//   - A null value matches only when the field is absent.

type matcher interface {
	match(e *events.Event) bool
}

// andMatcher requires every child to match: a map of fields.
type andMatcher []matcher

func (m andMatcher) match(e *events.Event) bool {
	for _, child := range m {
		if !child.match(e) {
			return false
		}
	}
	return true
}

// orMatcher requires any child: a list of maps.
type orMatcher []matcher

func (m orMatcher) match(e *events.Event) bool {
	for _, child := range m {
		if child.match(e) {
			return true
		}
	}
	return false
}

// alwaysMatcher is an empty selection, which Sigma treats as matching.
type alwaysMatcher struct{}

func (alwaysMatcher) match(*events.Event) bool { return true }

// fieldMatcher compares one field against one or more values.
type fieldMatcher struct {
	field string
	// compares holds one predicate per listed value, rather than a single
	// predicate over all of them. That distinction is what makes |all
	// possible: with one combined OR predicate, "every value must match"
	// collapses into "any value matches", repeated — which is just OR again.
	compares []func(value string) bool
	// requireAll is set by the |all modifier: every listed value must match
	// the field, rather than any of them.
	requireAll bool
	values     []string
	// matchNull is set when the rule tests for an absent field.
	matchNull bool
}

func (m *fieldMatcher) match(e *events.Event) bool {
	raw := e.Field(m.field)
	if m.matchNull {
		return raw == nil
	}
	if raw == nil {
		return false
	}

	// A multi-valued field (an argv list, several capabilities) matches when
	// any of its values does. Treating it as a single joined string would
	// make a rule for "-e" match "-exec".
	fieldValues := events.Values(raw)

	if m.requireAll {
		// Every listed value must be satisfied by some value of the field.
		for _, compare := range m.compares {
			if !anyValueMatches(fieldValues, compare) {
				return false
			}
		}
		return true
	}
	// Any listed value satisfied by any value of the field.
	for _, compare := range m.compares {
		if anyValueMatches(fieldValues, compare) {
			return true
		}
	}
	return false
}

func anyValueMatches(values []string, pred func(string) bool) bool {
	for _, v := range values {
		if pred(v) {
			return true
		}
	}
	return false
}

// compileSelection turns a detection block entry into a matcher.
func compileSelection(raw any) (matcher, error) {
	switch typed := raw.(type) {
	case nil:
		return alwaysMatcher{}, nil

	case map[string]any:
		return compileFieldMap(typed)

	case []any:
		// A list of maps is an OR. A list of bare strings under a selection
		// name is Sigma's "keywords" form, which searches the whole event.
		var out orMatcher
		for _, item := range typed {
			switch inner := item.(type) {
			case map[string]any:
				m, err := compileFieldMap(inner)
				if err != nil {
					return nil, err
				}
				out = append(out, m)
			case string:
				out = append(out, keywordMatcher(inner))
			default:
				return nil, fmt.Errorf("unsupported entry %T in a selection list", item)
			}
		}
		if len(out) == 0 {
			return alwaysMatcher{}, nil
		}
		return out, nil

	case string:
		return keywordMatcher(typed), nil

	default:
		return nil, fmt.Errorf("unsupported selection type %T", raw)
	}
}

func compileFieldMap(fields map[string]any) (matcher, error) {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	// Sorted so a rule compiles identically every time, which matters because
	// the rule hash ends up on the alert.
	sort.Strings(names)

	var out andMatcher
	for _, name := range names {
		m, err := compileField(name, fields[name])
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return alwaysMatcher{}, nil
	}
	return out, nil
}

// compileField builds a matcher for "Field|modifier|modifier: value".
func compileField(spec string, raw any) (matcher, error) {
	parts := strings.Split(spec, "|")
	field := strings.TrimSpace(parts[0])
	modifiers := parts[1:]

	if raw == nil {
		return &fieldMatcher{field: field, matchNull: true}, nil
	}

	values := valueList(raw)
	if len(values) == 0 {
		// An explicit empty list can never match, and saying so beats
		// compiling something that silently never fires.
		return nil, fmt.Errorf("field %q has an empty value list, which can never match", spec)
	}

	m := &fieldMatcher{field: field, values: values}

	var (
		useContains, useStartswith, useEndswith, useRegex, useCIDR bool
		useBase64Offset, useBase64, useWindash                     bool
	)
	for _, mod := range modifiers {
		switch strings.ToLower(strings.TrimSpace(mod)) {
		case "contains":
			useContains = true
		case "startswith":
			useStartswith = true
		case "endswith":
			useEndswith = true
		case "re", "re|i":
			useRegex = true
		case "cidr":
			useCIDR = true
		case "all":
			m.requireAll = true
		case "base64offset":
			useBase64Offset = true
		case "base64":
			useBase64 = true
		case "windash":
			useWindash = true
		case "":
			// A trailing pipe. Harmless.
		default:
			// Refused rather than ignored. Ignoring an unknown modifier
			// changes what the rule means — dropping |base64 turns a search
			// for encoded text into a search for plain text, which matches
			// nothing and looks like a quiet network.
			return nil, fmt.Errorf("field %q uses unsupported modifier %q", spec, mod)
		}
	}

	switch {
	case useRegex:
		for _, v := range values {
			// Case-insensitive by default, matching Sigma's string semantics.
			re, err := regexp.Compile("(?i)" + v)
			if err != nil {
				return nil, fmt.Errorf("field %q: %q is not a valid regular expression: %w", spec, v, err)
			}
			m.compares = append(m.compares, re.MatchString)
		}

	case useCIDR:
		for _, v := range values {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("field %q: %q is not a CIDR range: %w", spec, v, err)
			}
			prefix := p
			m.compares = append(m.compares, func(value string) bool {
				addr, err := netip.ParseAddr(strings.TrimSpace(value))
				if err != nil {
					// A hostname where an address was expected is not a
					// match, and is not an error either — sensors emit both.
					ip := net.ParseIP(value)
					if ip == nil {
						return false
					}
					addr, _ = netip.AddrFromSlice(ip)
				}
				return prefix.Contains(addr.Unmap())
			})
		}

	default:
		expanded := values
		if useBase64Offset {
			expanded = base64Offsets(values)
		} else if useBase64 {
			expanded = base64Plain(values)
		}
		if useWindash {
			expanded = windashVariants(expanded)
		}

		for _, v := range expanded {
			want := strings.ToLower(v)
			m.compares = append(m.compares, func(value string) bool {
				return matchOne(strings.ToLower(value), want, useContains, useStartswith, useEndswith)
			})
		}
	}
	return m, nil
}

func matchOne(value, want string, contains, startswith, endswith bool) bool {
	// A value carrying backslash escapes goes through the pattern path even
	// with no live wildcard left, because the escapes still have to be
	// removed before comparison. Comparing the raw text would look for a
	// literal backslash the event never contains.
	if needsPattern(want) {
		switch {
		case contains:
			return wildcardMatch(value, "*"+want+"*")
		case startswith:
			return wildcardMatch(value, want+"*")
		case endswith:
			return wildcardMatch(value, "*"+want)
		default:
			return wildcardMatch(value, want)
		}
	}
	switch {
	case contains:
		if hasWildcard(want) {
			return wildcardMatch(value, "*"+want+"*")
		}
		return strings.Contains(value, want)
	case startswith:
		if hasWildcard(want) {
			return wildcardMatch(value, want+"*")
		}
		return strings.HasPrefix(value, want)
	case endswith:
		if hasWildcard(want) {
			return wildcardMatch(value, "*"+want)
		}
		return strings.HasSuffix(value, want)
	default:
		// Plain values still honour wildcards: that is Sigma's rule, and a
		// great many community rules rely on it.
		if hasWildcard(want) {
			return wildcardMatch(value, want)
		}
		return value == want
	}
}

// needsPattern reports whether a value has to be compiled rather than
// compared directly: either it has a live wildcard, or it has escapes that
// must be resolved first.
func needsPattern(s string) bool {
	return hasWildcard(s) || strings.Contains(s, `\`)
}

func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

// wildcardMatch compiles the pattern to a regular expression, escaping
// everything that is not an unescaped wildcard. Doing it by hand would mean
// re-implementing backtracking for `?`.
func wildcardMatch(value, pattern string) bool {
	re, err := wildcardRegexp(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

var wildcardCache = map[string]*regexp.Regexp{}

func wildcardRegexp(pattern string) (*regexp.Regexp, error) {
	if re, ok := wildcardCache[pattern]; ok {
		return re, nil
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < len(pattern):
			// An escaped wildcard is a literal. Sigma uses backslash for this.
			i++
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	wildcardCache[pattern] = re
	return re, nil
}

// keywordMatcher searches every field value, which is what a bare string in a
// detection block means.
func keywordMatcher(keyword string) matcher {
	want := strings.ToLower(keyword)
	wild := hasWildcard(want)
	return &keywordSearch{want: want, wildcard: wild}
}

type keywordSearch struct {
	want     string
	wildcard bool
}

func (k *keywordSearch) match(e *events.Event) bool {
	for _, name := range e.FieldNames() {
		for _, v := range events.Values(e.Field(name)) {
			v = strings.ToLower(v)
			if k.wildcard {
				if wildcardMatch(v, k.want) {
					return true
				}
				continue
			}
			if strings.Contains(v, k.want) {
				return true
			}
		}
	}
	return false
}

func valueList(raw any) []string {
	switch typed := raw.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	case nil:
		return nil
	default:
		return []string{fmt.Sprintf("%v", raw)}
	}
}

// base64Offsets produces the three encodings a string can have depending on
// its byte offset within a larger base64 blob, which is what |base64offset
// exists for: a command line embedded in an encoded payload does not start on
// a three-byte boundary.
func base64Offsets(values []string) []string {
	var out []string
	for _, v := range values {
		for offset := 0; offset < 3; offset++ {
			padded := strings.Repeat("\x00", offset) + v
			encoded := base64.StdEncoding.EncodeToString([]byte(padded))
			// Trim the bytes that encode the padding and the trailing
			// partial group, leaving the stable middle.
			start := (offset*8 + 5) / 6
			if start >= len(encoded) {
				continue
			}
			end := len(encoded) - ((len(padded)%3)*8+5)/6
			if end <= start || end > len(encoded) {
				end = len(encoded)
			}
			out = append(out, encoded[start:end])
		}
	}
	return out
}

func base64Plain(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, base64.StdEncoding.EncodeToString([]byte(v)))
	}
	return out
}

// windashVariants covers the dash characters Windows accepts interchangeably.
// Kept because community rules use it, even though DefendSec's sensor is
// Linux: a rule directory synced from upstream contains both.
func windashVariants(values []string) []string {
	dashes := []string{"-", "/", "–", "—", "―"}
	var out []string
	for _, v := range values {
		out = append(out, v)
		if !strings.HasPrefix(v, "-") {
			continue
		}
		for _, d := range dashes[1:] {
			out = append(out, d+strings.TrimPrefix(v, "-"))
		}
	}
	return out
}

func hashOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
