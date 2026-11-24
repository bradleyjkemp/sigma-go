package evaluator

import (
	"reflect"
	"testing"
)

func Test_compileRegex(t *testing.T) {
	tests := []struct {
		expr    string
		wantErr bool
	}{
		{"foo.*baz", false},
		{"(?i)foo.*baz", false},
		{"foo(", true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			first, err := compileRegex(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("compileRegex() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// the cached result must be the same as computing it directly
			ss, caseInsensitive, err := regexStrings(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first.ss, ss) || first.caseInsensitive != caseInsensitive {
				t.Errorf("compileRegex() = %#v, %v, want %#v, %v", first.ss, first.caseInsensitive, ss, caseInsensitive)
			}
			if first.re.String() != tt.expr {
				t.Errorf("compileRegex() regex = %v, want %v", first.re, tt.expr)
			}

			second, err := compileRegex(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			if first.re != second.re {
				t.Error("expected compileRegex to return the cached regex")
			}
		})
	}
}
