package evaluator

import (
	"reflect"
	"testing"
)

func Test_coerceNumeric(t *testing.T) {
	tests := []struct {
		name      string
		left      interface{}
		right     interface{}
		wantLeft  interface{}
		wantRight interface{}
		wantErr   bool
	}{
		{"Two integers", 1, 2, 1, 2, false},
		{"Two floats", 1.1, 1.2, 1.1, 1.2, false},
		{"One int, one float", 1, 1.2, float64(1.0), 1.2, false},
		{"One float, one int", 1.1, 2, 1.1, float64(2.0), false},
		{"One int, one string", 1, "2", 1, 2, false},
		{"One string, one float", "1.1", 1.2, 1.1, 1.2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := coerceNumeric(tt.left, tt.right)
			if (err != nil) != tt.wantErr {
				t.Errorf("coerceNumeric() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.wantLeft) {
				t.Errorf("coerceNumeric() got = %v, want %v", got, tt.wantLeft)
			}
			if !reflect.DeepEqual(got1, tt.wantRight) {
				t.Errorf("coerceNumeric() got1 = %v, want %v", got1, tt.wantRight)
			}
		})
	}
}
