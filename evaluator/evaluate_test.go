package evaluator

import (
	"context"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

func TestRuleEvaluator_Matches(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					FieldMatchers: []sigma.FieldMatcher{
						{
							Field: "foo-field",
							Values: []string{
								"foo-value",
							},
						},
					},
				},
				"bar": {
					FieldMatchers: []sigma.FieldMatcher{
						{
							Field: "bar-field",
							Values: []string{
								"bar-value",
							},
						},
					},
				},
				"baz": {
					FieldMatchers: []sigma.FieldMatcher{
						{
							Field: "baz-field",
							Values: []string{
								"baz-value",
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{
				{
					Search: sigma.And{
						sigma.SearchIdentifier{Name: "foo"},
						sigma.SearchIdentifier{Name: "bar"},
					},
				},
				{
					Search: sigma.AllOfThem{},
				},
			},
		},
	})

	result, err := rule.Matches(context.Background(), map[string]interface{}{
		"foo-field": "foo-value",
		"bar-field": "bar-value",
		"baz-field": "wrong-value",
	})
	switch {
	case err != nil:
		t.Fatal(err)
	case !result.Match:
		t.Fatal("rule should have matched")
	case !result.SearchResults["foo"] || !result.SearchResults["bar"] || result.SearchResults["baz"]:
		t.Fatal("expected foo and bar to be true but not baz")
	case !result.ConditionResults[0] || result.ConditionResults[1]:
		t.Fatal("expected first condition to be true and second condition to be false")
	}
}

func TestRuleEvaluator_Matches_WithPlaceholder(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					FieldMatchers: []sigma.FieldMatcher{
						{
							Field: "foo-field",
							Values: []string{
								"%foo-placeholder%",
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{
				{
					Search: sigma.SearchIdentifier{Name: "foo"},
				},
				{
					Search: sigma.AllOfThem{},
				},
			},
		},
	}, WithPlaceholderExpander(func(ctx context.Context, placeholderName string) ([]string, error) {
		if placeholderName != "%foo-placeholder%" {
			return nil, nil
		}

		return []string{"foo-value"}, nil
	}))

	result, err := rule.Matches(context.Background(), map[string]interface{}{
		"foo-field": "foo-value",
	})
	switch {
	case err != nil:
		t.Fatal(err)
	case !result.Match:
		t.Fatal("rule should have matched")
	}
}
