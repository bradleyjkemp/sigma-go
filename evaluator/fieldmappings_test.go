package evaluator

import (
	"context"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

func TestRuleEvaluator_HandlesBasicFieldMappings(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					FieldMatchers: []sigma.FieldMatcher{{
						Field:  "name",
						Values: []string{"value"},
					}},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "test"}}},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"mapped-name"}},
		},
	}))

	matches, _ := rule.Matches(context.Background(), map[string]interface{}{
		"name": "value",
	})
	if matches {
		t.Error("If a field is mapped, the old name shouldn't be used")
	}

	matches, _ = rule.Matches(context.Background(), map[string]interface{}{"mapped-name": "value"})
	if !matches {
		t.Error("If a field is mapped, the mapped name should work")
	}
}

func TestRuleEvaluator_HandlesJSONPathFieldMappings(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					FieldMatchers: []sigma.FieldMatcher{{
						Field:  "name",
						Values: []string{"value"},
					}},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "test"}}},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"$.mapped.name"}},
		},
	}))

	matches, _ := rule.Matches(context.Background(), map[string]interface{}{
		"name": "value",
	})
	if matches {
		t.Error("If a field is mapped, the old name shouldn't be used")
	}

	matches, _ = rule.Matches(context.Background(), map[string]interface{}{
		"mapped": map[string]interface{}{
			"name": "value",
		},
	})
	if !matches {
		t.Error("If a fieldmapping is a JSONPath expression, the nested field should be matched")
	}
}

func TestRuleEvaluator_HandlesJSONPathByteSlice(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					FieldMatchers: []sigma.FieldMatcher{{
						Field:  "name",
						Values: []string{"value"},
					}},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "test"}}},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"$.mapped.name"}},
		},
	}))

	matches, _ := rule.Matches(context.Background(), map[string]interface{}{
		"mapped": `{"name": "value"}`,
	})
	if !matches {
		t.Error("If a JSONPath expression encounters a string, the string should be parsed and then matched")
	}
}
