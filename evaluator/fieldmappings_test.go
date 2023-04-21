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
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value"},
						}},
					},
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

	result, _ := rule.Matches(context.Background(), map[string]interface{}{
		"name": "value",
	})
	if result.Match {
		t.Error("If a field is mapped, the old name shouldn't be used")
	}

	result, _ = rule.Matches(context.Background(), map[string]interface{}{"mapped-name": "value"})
	if !result.Match {
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
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value"},
						}},
					},
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

	result, _ := rule.Matches(context.Background(), map[string]interface{}{
		"name": "value",
	})
	if result.Match {
		t.Error("If a field is mapped, the old name shouldn't be used")
	}

	result, _ = rule.Matches(context.Background(), map[string]interface{}{
		"mapped": map[string]interface{}{
			"name": "value",
		},
	})
	if !result.Match {
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
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value"},
						}},
					},
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

	result, _ := rule.Matches(context.Background(), map[string]interface{}{
		"mapped": `{"name": "value"}`,
	})
	if !result.Match {
		t.Error("If a JSONPath expression encounters a string, the string should be parsed and then matched")
	}
}

func TestRuleEvaluator_HandlesToplevelJSONPath(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value"},
						}},
					},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "test"}}},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"$.toplevel"}},
		},
	}))

	result, _ := rule.Matches(context.Background(), map[string]interface{}{
		"toplevel": "value",
	})
	if !result.Match {
		t.Error("A single-level JSONPath expression (e.g. Name: $.name) should be behave identically to a plain field mapping (e.g. Name: name)")
	}
}

func TestRuleEvaluator_GetFieldValuesFromEvent(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value"},
						}},
					},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "test"}}},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"$.toplevel"}},
		},
	}))

	expected := "value"
	actual, err := rule.GetFieldValuesFromEvent("name", map[string]interface{}{
		"toplevel": "value",
	})
	if err != nil {
		t.Error(err)
	}

	if len(actual) != 1 {
		t.Error("Expected 1 value in the resulting array of GetFieldValuesFromEvent")
	}

	if expected != actual[0] {
		t.Error("The field obtained from GetFieldValuesFromEvent() does not match the expected value.")
	}
}

func TestRuleEvaluator_HandlesToplevelNestedJSONPath(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value1"},
						}},
					},
				},
				"field2": {
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "field2",
							Values: []interface{}{"hello"},
						}},
					},
				},
			},
			Conditions: []sigma.Condition{
				{
					Search: sigma.And{
						sigma.SearchIdentifier{Name: "test"},
						sigma.SearchIdentifier{Name: "field2"},
					},
				},
				{
					Search: sigma.AllOfThem{},
				},
			},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name":   {TargetNames: []string{"$.toplevel[*].field1"}},
			"field2": {TargetNames: []string{"$.toplevel[*].field2"}},
		},
	}))

	result, _ := rule.Matches(context.Background(), map[string]interface{}{
		"toplevel": []interface{}{
			map[string]interface{}{"field1": "value1", "field2": "hello"},
			map[string]interface{}{"field1": "value2"},
		},
	})
	if !result.Match {
		t.Error("A nested JSON field (e.g. Values: $.values[*]) should perform an evaluation on all entries in the array")
	}
}

func TestRuleEvaluator_HandlesConflictingJSONPathFieldMappings(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Logsource: sigma.Logsource{
			Category: "category",
			Product:  "product",
			Service:  "service",
		},
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"test": {
					EventMatchers: []sigma.EventMatcher{
						{{
							Field:  "name",
							Values: []interface{}{"value"},
						}},
					},
				},
			},
			Conditions: []sigma.Condition{
				{Search: sigma.SearchIdentifier{Name: "test"}}},
		},
	}, WithConfig(sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"$.mapped.name"}},
		},
	}, sigma.Config{
		FieldMappings: map[string]sigma.FieldMapping{
			"name": {TargetNames: []string{"$.nonexistent.name"}},
		},
	}))

	result, _ := rule.Matches(context.Background(), map[string]interface{}{
		"name": "value",
	})
	if result.Match {
		t.Error("If a field is mapped, the old name shouldn't be used")
	}

	result, _ = rule.Matches(context.Background(), map[string]interface{}{
		"mapped": map[string]interface{}{
			"name": "value",
		},
	})
	if !result.Match {
		t.Error("Both JSONPath mappings should be valid")
	}

	result, _ = rule.Matches(context.Background(), map[string]interface{}{
		"nonexistent": map[string]interface{}{
			"name": "value",
		},
	})
	if !result.Match {
		t.Error("Both JSONPath mappings should be valid")
	}
}
