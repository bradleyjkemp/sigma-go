package modifiers

import (
	"fmt"
	"testing"
)

// Wildcards and escaping are defined in the String Wildcard and Escape Character sections of the Sigma specification:
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#string-wildcard
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escape-character
func Test_parseValue(t *testing.T) {
	tests := []struct {
		value        string
		wantLiteral  string
		wantWildcard bool
	}{
		{`foo`, `foo`, false},
		{`C:\Windows\System32`, `C:\Windows\System32`, false}, // a plain backslash can be written as \
		{`C:\\Windows`, `C:\Windows`, false},                  // or as \\
		{`foo\*bar`, `foo*bar`, false},                        // escaped wildcards are plain characters
		{`foo\?`, `foo?`, false},
		{`\\\*`, `\*`, false},    // escaped backslash followed by an escaped wildcard
		{`\\\\`, `\\`, false},    // four backslashes are a double backslash
		{`\\\`, `\\`, false},     // as are three
		{`foo\`, `foo\`, false},  // trailing backslash
		{`*`, ``, true},          // wildcard
		{`foo?bar`, ``, true},    // wildcard
		{`\\*`, ``, true},        // escaped backslash followed by a wildcard
		{`\*foo*`, ``, true},     // escaped and unescaped wildcards
		{`fö\*ö`, `fö*ö`, false}, // non-ASCII
		{`fö?ö`, ``, true},       // non-ASCII
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			literal, pattern := parseValue(tt.value)
			if (pattern != nil) != tt.wantWildcard {
				t.Fatalf("parseValue(%q) pattern = %v, want wildcard: %v", tt.value, pattern, tt.wantWildcard)
			}
			if !tt.wantWildcard && literal != tt.wantLiteral {
				t.Errorf("parseValue(%q) literal = %q, want %q", tt.value, literal, tt.wantLiteral)
			}
		})
	}
}

func Test_wildcardPattern_matches(t *testing.T) {
	tests := []struct {
		pattern   string
		s         string
		anyPrefix bool
		anySuffix bool
		want      bool
	}{
		{`*`, ``, false, false, true},
		{`*`, `anything`, false, false, true},
		{`?`, ``, false, false, false},
		{`?`, `a`, false, false, true},
		{`?`, `ab`, false, false, false},
		{`?`, `ö`, false, false, true}, // ? matches a single character, not a single byte
		{`a*c`, `ac`, false, false, true},
		{`a*c`, `abbbc`, false, false, true},
		{`a*c`, `abbbcd`, false, false, false},
		{`a*c`, `abcbc`, false, false, true},
		{`a?c`, `abc`, false, false, true},
		{`a?c`, `abbc`, false, false, false},
		{`*.exe`, `cmd.exe`, false, false, true},
		{`*.exe`, `cmd.exe.txt`, false, false, false},
		{`a*b*c`, `aXbYc`, false, false, true},
		{`a*b*c`, `aXcYb`, false, false, false},
		{`**a`, `bba`, false, false, true},
		{`\\*`, `\foo`, false, false, true},
		{`\\*`, `foo`, false, false, false},
		{`\**`, `*foo`, false, false, true},
		{`\**`, `foo`, false, false, false},
		{`\??`, `?x`, false, false, true},
		{`\??`, `ax`, false, false, false},

		// endswith
		{`a?c`, `xxabc`, true, false, true},
		{`a?c`, `xxabcx`, true, false, false},
		// startswith
		{`a?c`, `abcxx`, false, true, true},
		{`a?c`, `xabc`, false, true, false},
		// contains
		{`a?c`, `xxabcxx`, true, true, true},
		{`a?c`, `xxacxx`, true, true, false},
		{`b*d`, `abcde`, true, true, true},
		{`b*d`, `abce`, true, true, false},
		{`aab`, `aaab`, true, true, true},
		{`aab`, `abab`, true, true, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s_%v_%v", tt.pattern, tt.s, tt.anyPrefix, tt.anySuffix), func(t *testing.T) {
			_, pattern := parseValue(tt.pattern)
			if pattern == nil {
				// not a wildcard pattern so construct one by hand to still exercise the matching algorithm
				for _, r := range tt.pattern {
					pattern = append(pattern, wildcardToken{kind: literalRune, r: r})
				}
			}
			if got := pattern.matches(tt.s, tt.anyPrefix, tt.anySuffix); got != tt.want {
				t.Errorf("%q.matches(%q, %v, %v) = %v, want %v", tt.pattern, tt.s, tt.anyPrefix, tt.anySuffix, got, tt.want)
			}
		})
	}
}

func TestComparators_Wildcards(t *testing.T) {
	tests := []struct {
		modifier string
		actual   any
		expected string
		want     bool
		wantCS   bool // result with ComparatorsCaseSensitive (the default comparator is always case-insensitive)
	}{
		{"", `C:\Windows\System32\cmd.exe`, `C:\Windows\\*\cmd.exe`, true, true},  // a backslash before a wildcard must be escaped
		{"", `C:\Windows\System32\cmd.exe`, `C:\Windows\*\cmd.exe`, false, false}, // otherwise it escapes the wildcard
		{"", `C:\Windows*\cmd.exe`, `C:\Windows\*\cmd.exe`, true, true},
		{"", `C:\Windows\System32\CMD.EXE`, `c:\windows\\*\cmd.exe`, true, true},
		{"", `C:\Windows\System32\cmd.exe`, `C:\Windows\\*\powershell.exe`, false, false},
		{"", `cmd.exe`, `cmd.ex?`, true, true},
		{"", `cmd.exe`, `cmd.exe?`, false, false},
		{"", `a*b`, `a\*b`, true, true},
		{"", `axb`, `a\*b`, false, false},
		{"", `C:\Windows`, `C:\\Windows`, true, true},
		{"", nil, `*`, false, false}, // a missing field doesn't match a wildcard
		{"", nil, `null`, true, true},
		{"", 4444, `44?4`, true, true},

		{"contains", `powershell -enc AAAA`, ` -e* `, true, true},
		{"contains", `powershell -ENC AAAA`, ` -e* `, true, false},
		{"contains", `powershell -nop`, ` -e* `, false, false},
		{"contains", `rm -rf /*`, `/\*`, true, true},
		{"contains", `rm -rf /tmp`, `/\*`, false, false},

		{"startswith", `/tmp/x/payload`, `/tmp/?/`, true, true},
		{"startswith", `/TMP/x/payload`, `/tmp/?/`, true, false},
		{"startswith", `/var/tmp/x/payload`, `/tmp/?/`, false, false},

		{"endswith", `C:\Users\bob\AppData\evil.exe`, `\AppData\\*.exe`, true, true},
		{"endswith", `C:\Users\bob\AppData\EVIL.EXE`, `\AppData\\*.exe`, true, false},
		{"endswith", `C:\Users\bob\AppData\evil.dll`, `\AppData\\*.exe`, false, false},

		// wildcards are not interpreted by the other comparators
		{"re", `foo*`, `^foo\*$`, true, true},
		{"cidr", `10.1.2.3`, `10.0.0.0/8`, true, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%v_%s", tt.modifier, tt.actual, tt.expected), func(t *testing.T) {
			for _, cs := range []bool{false, true} {
				comparators, want := Comparators, tt.want
				if cs {
					comparators, want = ComparatorsCaseSensitive, tt.wantCS
				}
				var modifiers []string
				if tt.modifier != "" {
					modifiers = []string{tt.modifier}
				}
				comparator, err := GetComparator("field", comparators, modifiers...)
				if err != nil {
					t.Fatal(err)
				}
				got, err := comparator(tt.actual, tt.expected)
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Errorf("caseSensitive=%v: got %v, want %v", cs, got, want)
				}
			}
		})
	}
}
