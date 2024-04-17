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
