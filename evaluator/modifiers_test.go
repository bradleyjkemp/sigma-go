package evaluator

import (
	"fmt"
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
		t.Run(fmt.Sprintf("%s_%s", tt.left, tt.right), func(t *testing.T) {
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
