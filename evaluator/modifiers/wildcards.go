package modifiers

import "strings"

// Sigma values can contain the wildcards * (any number of characters) and ? (exactly one character).
// A backslash escapes a wildcard or another backslash. Any other backslash is a plain backslash.
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#string-wildcard
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escape-character

type wildcardToken struct {
	kind wildcardKind
	r    rune
}

type wildcardKind uint8

const (
	literalRune wildcardKind = iota
	anyRune                  // ?
	anyRunes                 // *
)

type wildcardPattern []wildcardToken

// parseValue parses a Sigma value. If the value contains unescaped wildcards then a pattern is returned.
// Otherwise, pattern is nil and literal is the value with any escape sequences removed.
func parseValue(value string) (literal string, pattern wildcardPattern) {
	if !strings.ContainsAny(value, `*?\`) {
		// fast path for the common case
		return value, nil
	}

	runes := []rune(value)
	hasWildcards := false
	pattern = make(wildcardPattern, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		switch r := runes[i]; {
		case r == '\\' && i+1 < len(runes) && (runes[i+1] == '*' || runes[i+1] == '?' || runes[i+1] == '\\'):
			i++
			pattern = append(pattern, wildcardToken{kind: literalRune, r: runes[i]})
		case r == '*':
			hasWildcards = true
			pattern = append(pattern, wildcardToken{kind: anyRunes})
		case r == '?':
			hasWildcards = true
			pattern = append(pattern, wildcardToken{kind: anyRune})
		default:
			pattern = append(pattern, wildcardToken{kind: literalRune, r: r})
		}
	}
	if hasWildcards {
		return "", pattern
	}

	unescaped := make([]rune, len(pattern))
	for i, token := range pattern {
		unescaped[i] = token.r
	}
	return string(unescaped), nil
}

// matchesValue reports whether an event value matches the pattern.
// A missing value (nil) never matches, even if the pattern is just "*".
func (p wildcardPattern) matchesValue(actual any, toLower, anyPrefix, anySuffix bool) bool {
	if actual == nil {
		return false
	}
	s := CoerceString(actual)
	if toLower {
		s = strings.ToLower(s)
	}
	return p.matches(s, anyPrefix, anySuffix)
}

// matches reports whether s matches the pattern.
// anyPrefix and anySuffix allow arbitrary text before and after the pattern (for endswith, startswith and contains).
func (p wildcardPattern) matches(s string, anyPrefix, anySuffix bool) bool {
	const noStar = -2
	star, starPos := noStar, 0 // the last * seen and the position in s it is currently matched up to
	if anyPrefix {
		star = -1 // a virtual * before the start of the pattern
	}

	str := []rune(s)
	pi, si := 0, 0
	for si < len(str) {
		switch {
		case anySuffix && pi == len(p):
			return true
		case pi < len(p) && p[pi].kind == anyRunes:
			star, starPos = pi, si
			pi++
		case pi < len(p) && (p[pi].kind == anyRune || p[pi].r == str[si]):
			pi++
			si++
		case star != noStar:
			// backtrack: let the last * consume one more rune
			starPos++
			pi, si = star+1, starPos
		default:
			return false
		}
	}

	for pi < len(p) && p[pi].kind == anyRunes {
		pi++
	}
	return pi == len(p)
}
