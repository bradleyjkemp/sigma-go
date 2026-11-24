package aggregators

import (
	"context"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

func TestInMemory_SumAverage(t *testing.T) {
	tests := []struct {
		condition string
		values    []float64
		want      []bool
	}{
		{"selection | sum(bytes) by src_ip > 100", []float64{40, 50, 20}, []bool{false, false, true}},
		{"selection | avg(bytes) by src_ip > 100", []float64{50, 250, 0}, []bool{false, true, false}},
	}
	for _, tt := range tests {
		t.Run(tt.condition, func(t *testing.T) {
			rule, err := sigma.ParseRule([]byte(`
title: sum and avg
logsource:
  product: test
detection:
  selection:
    action: upload
  timeframe: 1h
  condition: ` + tt.condition))
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}
			e := evaluator.ForRule(rule, InMemory(rule.Detection.Timeframe)...)

			for i, value := range tt.values {
				result, err := e.Matches(context.Background(), map[string]interface{}{"action": "upload", "src_ip": "10.0.0.1", "bytes": value})
				if err != nil {
					t.Fatalf("event %d: error evaluating rule: %v", i, err)
				}
				if result.Match != tt.want[i] {
					t.Errorf("event %d (bytes=%v): Match = %v, want %v", i, value, result.Match, tt.want[i])
				}
			}
		})
	}
}
