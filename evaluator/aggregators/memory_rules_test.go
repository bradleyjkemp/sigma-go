package aggregators

import (
	"context"
	"testing"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

// Aggregation state must not be shared between rules, even when they share an aggregator (as they do with ForRules)
func TestInMemory_RulesDoNotShareCounts(t *testing.T) {
	parse := func(id, action string) sigma.Rule {
		rule, err := sigma.ParseRule([]byte(`
title: count ` + action + `
id: ` + id + `
logsource:
  product: test
detection:
  selection:
    action: ` + action + `
  timeframe: 1h
  condition: selection | count() by src_ip > 2
`))
		if err != nil {
			t.Fatalf("error parsing rule: %v", err)
		}
		return rule
	}
	bundle := evaluator.ForRules([]sigma.Rule{
		parse("11111111-1111-1111-1111-111111111111", "login"),
		parse("22222222-2222-2222-2222-222222222222", "upload"),
	}, InMemory(time.Hour)...)

	events := []struct {
		action string
		want   []bool // the match result for each rule
	}{
		{"login", []bool{false, false}},
		{"login", []bool{false, false}},
		{"upload", []bool{false, false}}, // the upload rule has seen 1 event, not 3
		{"login", []bool{true, false}},
		{"upload", []bool{false, false}},
		{"upload", []bool{false, true}},
	}
	for i, tt := range events {
		results, err := bundle.Matches(context.Background(), map[string]interface{}{"action": tt.action, "src_ip": "10.0.0.1"})
		if err != nil {
			t.Fatalf("event %d: error evaluating rules: %v", i, err)
		}
		for r, result := range results {
			if result.Match != tt.want[r] {
				t.Errorf("event %d (%s): rule %s Match = %v, want %v", i, tt.action, result.Rule.Title, result.Match, tt.want[r])
			}
		}
	}
}
