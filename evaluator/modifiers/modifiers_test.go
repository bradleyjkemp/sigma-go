package modifiers

import (
	"fmt"
	"math/rand"
	"testing"
)

func Test_compareNumeric(t *testing.T) {
	tests := []struct {
		left    interface{}
		right   interface{}
		wantGt  bool
		wantGte bool
		wantLt  bool
		wantLte bool
	}{
		{1, 2, false, false, true, true},
		{1.1, 1.2, false, false, true, true},
		{1, 1.2, false, false, true, true},
		{1.1, 2, false, false, true, true},
		{1, "2", false, false, true, true},
		{"1.1", 1.2, false, false, true, true},
		{"1.1", 1.1, false, true, false, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v_%v", tt.left, tt.right), func(t *testing.T) {
			gotGt, gotGte, gotLt, gotLte, err := compareNumeric(tt.left, tt.right)
			if err != nil {
				t.Errorf("compareNumeric() error = %v", err)
				return
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

var foo = map[string]interface{}{
	"foobar": 1,
}

func Test_coerceNumeric(t *testing.T) {
	tests := []struct {
		left      interface{}
		right     interface{}
		wantLeft  interface{}
		wantRight interface{}
		wantError bool
	}{
		{"foo", 1, nil, nil, true},
		{1.1, 2, 1.1, 2.0, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v_%v", tt.left, tt.right), func(t *testing.T) {
			left, right, err := coerceNumeric(tt.left, tt.right)
			if (err != nil) != tt.wantError {
				t.Errorf("coerceNumeric() error = %v, wanted %t", err, tt.wantError)
				return
			}
			if left != tt.wantLeft {
				t.Errorf("coerceNumeric() gotGt = %v, want %v", left, tt.wantLeft)
			}
			if right != tt.wantRight {
				t.Errorf("coerceNumeric() gotGte = %v, want %v", right, tt.wantRight)
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
