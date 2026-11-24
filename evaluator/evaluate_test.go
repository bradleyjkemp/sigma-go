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
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "foo-field",
								Values: []interface{}{
									"foo-value",
								},
							},
						},
					},
				},
				"bar": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "bar-field",
								Values: []interface{}{
									"bar-value",
								},
							},
						},
					},
				},
				"baz": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "baz-field",
								Values: []interface{}{
									"baz-value",
								},
							},
						},
					},
				},
				"null-field": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "non-existent-field",
								Values: []interface{}{
									"null",
								},
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
						sigma.SearchIdentifier{Name: "null-field"},
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
		t.Error("rule should have matched", result.SearchResults)
	case !result.SearchResults["foo"] || !result.SearchResults["bar"] || result.SearchResults["baz"]:
		t.Error("expected foo and bar to be true but not baz")
	case !result.ConditionResults[0] || result.ConditionResults[1]:
		t.Error("expected first condition to be true and second condition to be false")
	}
}

func TestRuleEvaluatorBundle_Matches(t *testing.T) {
	r1 := sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "field",
								Modifiers: []string{"contains"},
								Values: []interface{}{
									"foo",
								},
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{{
				Search: sigma.AllOfThem{},
			},
			},
		},
	}
	r2 := sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "field",
								Modifiers: []string{"contains"},
								Values: []interface{}{
									"bar",
								},
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{{
				Search: sigma.AllOfThem{},
			},
			},
		},
	}

	bundle := ForRules([]sigma.Rule{r1, r2})

	_, err := bundle.Matches(context.Background(), map[string]interface{}{
		"field": "foobar",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuleEvaluator_Matches_WithPlaceholder(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "foo-field",
								Values: []interface{}{
									"%foo-placeholder%",
								},
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

func TestRuleEvaluator_Matches_Regex(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "foo-field",
								Modifiers: []string{"re"},
								Values: []interface{}{
									"foo.*baz",
								},
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
	})

	result, err := rule.Matches(context.Background(), map[string]interface{}{
		"foo-field": "foo-bar-baz",
	})
	switch {
	case err != nil:
		t.Fatal(err)
	case !result.Match:
		t.Fatal("rule should have matched")
	}
}

func TestRuleEvaluator_Matches_CIDR(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "foo-field",
								Modifiers: []string{"cidr"},
								Values: []interface{}{
									"10.0.0.0/8",
								},
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
	})

	result, err := rule.Matches(context.Background(), map[string]interface{}{
		"foo-field": "10.1.2.3",
	})
	switch {
	case err != nil:
		t.Fatal(err)
	case !result.Match:
		t.Fatal("rule should have matched")
	}
}

func TestRuleEvaluator_MatchesCaseInsensitive(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "foo-field",
								Values: []interface{}{
									"foo-value",
								},
							},
						},
					},
				},
				"bar": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "bar-field",
								Values: []interface{}{
									"bAr-VaLuE",
								},
							},
						},
					},
				},
				"baz": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "baz-field",
								Values: []interface{}{
									"baz-value",
								},
							},
						},
					},
				},
				"null-field": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field: "non-existent-field",
								Values: []interface{}{
									"null",
								},
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
						sigma.SearchIdentifier{Name: "null-field"},
					},
				},
				{
					Search: sigma.AllOfThem{},
				},
			},
		},
	})

	result, err := rule.Matches(context.Background(), map[string]interface{}{
		"foo-field": "FoO-vAlUe",
		"bar-field": "bar-value",
		"baz-field": "WrOnG-vAlUe",
	})
	switch {
	case err != nil:
		t.Fatal(err)
	case !result.Match:
		t.Error("rule should have matched", result.SearchResults)
	case !result.SearchResults["foo"] || !result.SearchResults["bar"] || result.SearchResults["baz"]:
		t.Error("expected foo and bar to be true but not baz")
	case !result.ConditionResults[0] || result.ConditionResults[1]:
		t.Error("expected first condition to be true and second condition to be false")
	}
}

func TestRuleEvaluator_MatchesGreaterThan(t *testing.T) {
	rule := ForRule(sigma.Rule{
		Detection: sigma.Detection{
			Searches: map[string]sigma.Search{
				"foo1": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "foo-field",
								Modifiers: []string{"gt"},
								Values: []interface{}{
									"1",
								},
							},
						},
					},
				},
				"foo0.5": {
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:     "foo-field",
								Modifiers: []string{"gt"},
								Values: []interface{}{
									"0.5",
								},
							},
						},
					},
				},
			},
			Conditions: []sigma.Condition{
				{
					Search: sigma.SearchIdentifier{Name: "foo0.5"},
				},
			},
		},
	})

	result, err := rule.Matches(context.Background(), map[string]interface{}{
		"foo-field": 0.75,
	})
	switch {
	case err != nil:
		t.Fatal(err)
	case !result.Match:
		t.Error("rule should have matched", result.SearchResults)
	case !result.SearchResults["foo0.5"] || result.SearchResults["foo1"]:
		t.Error("expected foo0.5 to be true but not foo1")
	}
}

// Keyword searches are lists of strings that are searched for across the entire event.
// See the Lists and Keywords search sections of the Sigma specification:
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#lists
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#keywords-search
func TestRuleEvaluator_Matches_Keywords(t *testing.T) {
	tests := []struct {
		name      string
		detection string
		options   []Option
		event     map[string]interface{}
		want      bool
	}{
		{
			name: "keyword in any field",
			detection: `
  keywords:
    - 'event::clear'
    - 'event::drop'
  condition: keywords`,
			event: map[string]interface{}{"process": "mimikatz", "message": "mimikatz # event::drop"},
			want:  true,
		},
		{
			name: "keywords are case insensitive",
			detection: `
  keywords:
    - 'EVILSERVICE'
  condition: keywords`,
			event: map[string]interface{}{"message": "starting evilservice now"},
			want:  true,
		},
		{
			name: "no keyword present",
			detection: `
  keywords:
    - 'event::clear'
    - 'event::drop'
  condition: keywords`,
			event: map[string]interface{}{"message": "event::list"},
			want:  false,
		},
		{
			name: "keyword in a list value",
			detection: `
  keywords:
    - 'evil'
  condition: keywords`,
			event: map[string]interface{}{"args": []interface{}{"--good", "--evil"}},
			want:  true,
		},
		{
			name: "keyword in a non-string value",
			detection: `
  keywords:
    - '4444'
  condition: keywords`,
			event: map[string]interface{}{"port": 4444},
			want:  true,
		},
		{
			name: "null values are not searched",
			detection: `
  keywords:
    - 'nil'
  condition: keywords`,
			event: map[string]interface{}{"a": nil, "b": []interface{}{nil}},
			want:  false,
		},
		{
			name: "nested objects are not searched",
			detection: `
  keywords:
    - 'k:v'
  condition: keywords`,
			event: map[string]interface{}{"a": map[string]interface{}{"k": "v"}, "b": []interface{}{map[string]interface{}{"k": "v"}}},
			want:  false,
		},
		{
			name: "all modifier requires every keyword",
			detection: `
  keywords:
    '|all':
      - 'OabVirtualDirectory'
      - ' -ExternalUrl '
  condition: keywords`,
			event: map[string]interface{}{"message": "Set-OabVirtualDirectory -ExternalUrl https://example.com"},
			want:  true,
		},
		{
			name: "all modifier with a missing keyword",
			detection: `
  keywords:
    '|all':
      - 'OabVirtualDirectory'
      - ' -ExternalUrl '
  condition: keywords`,
			event: map[string]interface{}{"message": "Get-OabVirtualDirectory"},
			want:  false,
		},
		{
			name: "keywords combined with a field filter",
			detection: `
  keywords:
    - 'failed password'
  filter:
    user: root
  condition: keywords and not filter`,
			event: map[string]interface{}{"user": "root", "message": "Failed password for root"},
			want:  false,
		},
		{
			name: "keywords restricted to a field",
			detection: `
  keywords:
    - 'evil'
  condition: keywords`,
			options: []Option{WithKeywordFields("message")},
			event:   map[string]interface{}{"user": "evil", "message": "hello"},
			want:    false,
		},
		{
			name: "keywords restricted to a field that matches",
			detection: `
  keywords:
    - 'evil'
  condition: keywords`,
			options: []Option{WithKeywordFields("message")},
			event:   map[string]interface{}{"user": "bob", "message": "something evil"},
			want:    true,
		},
		{
			name: "case sensitive keywords",
			detection: `
  keywords:
    - 'EVILSERVICE'
  condition: keywords`,
			options: []Option{CaseSensitive},
			event:   map[string]interface{}{"message": "starting evilservice now"},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := sigma.ParseRule([]byte("title: keywords\nlogsource:\n  product: test\ndetection:" + tt.detection))
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}

			result, err := ForRule(rule, tt.options...).Matches(context.Background(), tt.event)
			if err != nil {
				t.Fatalf("error evaluating rule: %v", err)
			}
			if result.Match != tt.want {
				t.Errorf("Match = %v, want %v (searches: %v)", result.Match, tt.want, result.SearchResults)
			}

			// the bundle evaluator must agree with the standalone evaluator
			bundleResults, err := ForRules([]sigma.Rule{rule}, tt.options...).Matches(context.Background(), tt.event)
			if err != nil {
				t.Fatalf("error evaluating rule bundle: %v", err)
			}
			if len(bundleResults) != 1 || bundleResults[0].Match != tt.want {
				t.Errorf("bundle results = %v, want Match = %v", bundleResults, tt.want)
			}
		})
	}
}
