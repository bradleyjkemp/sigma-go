package evaluator

import (
	"context"
	"fmt"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

// count(field) counts the distinct values of field, see the Aggregation expression section of the Sigma specification:
// "The count aggregation counts all matching events if no field name is given. With field name it counts the distinct values in this field."
// https://github.com/SigmaHQ/sigma-specification/blob/v1.0.5/Sigma_specification.md#condition
func TestRuleEvaluator_Matches_CountDistinct(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: count distinct
logsource:
  product: test
detection:
  selection:
    EventID: 4625
  timeframe: 1h
  condition: selection | count(UserName) by SourceWorkstation > 2
`))
	if err != nil {
		t.Fatalf("error parsing rule: %v", err)
	}

	// a minimal (non-windowed) implementation: the set of distinct values per GroupedByValues
	distinct := map[string]map[string]bool{}
	var gotKeys []GroupedByValues
	e := ForRule(rule, CountDistinctImplementation(func(ctx context.Context, key GroupedByValues, value interface{}) (float64, error) {
		gotKeys = append(gotKeys, key)
		if distinct[key.Key()] == nil {
			distinct[key.Key()] = map[string]bool{}
		}
		if value != nil {
			distinct[key.Key()][fmt.Sprint(value)] = true
		}
		return float64(len(distinct[key.Key()])), nil
	}))

	tests := []struct {
		event map[string]interface{}
		want  bool
	}{
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws1", "UserName": "alice"}, false},
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws1", "UserName": "alice"}, false}, // repeated value
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws1", "UserName": "bob"}, false},
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws2", "UserName": "carol"}, false}, // different group
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws1"}, false},                      // missing field
		{map[string]interface{}{"EventID": 4624, "SourceWorkstation": "ws1", "UserName": "dave"}, false},  // doesn't match the search
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws1", "UserName": "erin"}, true},   // third distinct value
		{map[string]interface{}{"EventID": 4625, "SourceWorkstation": "ws1", "UserName": "alice"}, true},
	}
	for i, tt := range tests {
		result, err := e.Matches(context.Background(), tt.event)
		if err != nil {
			t.Fatalf("event %d: error evaluating rule: %v", i, err)
		}
		if result.Match != tt.want {
			t.Errorf("event %d (%v): Match = %v, want %v", i, tt.event, result.Match, tt.want)
		}
	}

	if len(gotKeys) == 0 || gotKeys[0].EventValues["SourceWorkstation"] != "ws1" {
		t.Errorf("expected the aggregation to be grouped by SourceWorkstation, got %v", gotKeys)
	}
}

func TestRuleEvaluator_Matches_CountDistinctNotImplemented(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: count distinct
logsource:
  product: test
detection:
  selection:
    EventID: 4625
  condition: selection | count(UserName) > 2
`))
	if err != nil {
		t.Fatalf("error parsing rule: %v", err)
	}

	_, err = ForRule(rule).Matches(context.Background(), map[string]interface{}{"EventID": 4625, "UserName": "alice"})
	if err == nil {
		t.Fatal("expected an error when no CountDistinctImplementation is provided")
	}
}

func TestGroupedByValues_Key(t *testing.T) {
	tests := []struct {
		name string
		gb   GroupedByValues
		want string
	}{
		{
			name: "without a rule ID the key is unchanged",
			gb:   GroupedByValues{ConditionID: 1, EventValues: map[string]interface{}{"src_ip": "10.0.0.1"}},
			want: `{"condition_id":1,"event_values":{"src_ip":"10.0.0.1"}}`,
		},
		{
			name: "with a rule ID",
			gb:   GroupedByValues{ConditionID: 1, EventValues: map[string]interface{}{"src_ip": "10.0.0.1"}, RuleID: "rule-a"},
			want: `{"condition_id":1,"event_values":{"src_ip":"10.0.0.1"},"rule_id":"rule-a"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.gb.Key(); got != tt.want {
				t.Errorf("Key() = %s, want %s", got, tt.want)
			}
		})
	}
}
