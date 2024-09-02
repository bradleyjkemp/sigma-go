package evaluator

import (
	"context"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

func TestRuleEvaluator_RelevantToEvent_LogsourceRewriting(t *testing.T) {
	rule := ForRule(sigma.Rule{Logsource: sigma.Logsource{
		Category: "category",
		Product:  "product",
		Service:  "service",
	}}, WithConfig(sigma.Config{
		Logsources: map[string]sigma.LogsourceMapping{
			"basic": {
				Logsource: sigma.Logsource{
					Category: "category",
				},
				Index:   []string{"just-category"},
				Rewrite: sigma.Logsource{},
			},
		}}, sigma.Config{
		Logsources: map[string]sigma.LogsourceMapping{
			"rewrite": {
				Logsource: sigma.Logsource{
					Category: "category",
				},
				Rewrite: sigma.Logsource{
					Category: "category-rewritten",
				},
			}}}, sigma.Config{
		Logsources: map[string]sigma.LogsourceMapping{
			"re-written": {
				Logsource: sigma.Logsource{
					Category: "category-rewritten",
				},
				Index:   []string{"category-rewritten-index"},
				Rewrite: sigma.Logsource{},
			},
		},
		DefaultIndex: "",
	}))

	relevant := []string{
		"just-category",
		"category-rewritten-index",
	}
	for _, tc := range relevant {
		relevant, _ := rule.RelevantToEvent(context.Background(), tc, nil)
		if !relevant {
			t.Fatal(tc, "should have been relevant")
		}
	}

	irrelevant := []string{
		"foobar",
	}
	for _, tc := range irrelevant {
		relevant, _ := rule.RelevantToEvent(context.Background(), tc, nil)
		if relevant {
			t.Fatal(tc, "shouldn't have been relevant")
		}
	}
}

func TestRuleEvaluator_ReleventToEvent_LogsourceConditions(t *testing.T) {
	rule := ForRule(sigma.Rule{Logsource: sigma.Logsource{
		Category: "category",
		Product:  "product",
		Service:  "service",
	}}, WithConfig(sigma.Config{
		Logsources: map[string]sigma.LogsourceMapping{
			"base": {
				Logsource: sigma.Logsource{
					Category: "category",
				},
				Index:   []string{"just-category"},
				Rewrite: sigma.Logsource{},
			},
			"conditin": {
				Logsource: sigma.Logsource{
					Category: "category",
					Product:  "product",
				},
				Conditions: sigma.Search{
					EventMatchers: []sigma.EventMatcher{
						{
							{
								Field:  "foo",
								Values: []interface{}{"bar"},
							},
						},
					},
				},
			},
		},
		FieldMappings: map[string]sigma.FieldMapping{
			"foo": {TargetNames: []string{"foo", "foo-mapped"}},
		}},
	))

	relevant := []map[string]interface{}{
		{
			"index": "just-category",
			"foo":   "bar",
		},
		{
			"index":      "just-category",
			"foo-mapped": "bar",
		},
	}
	for _, tc := range relevant {
		relevant, _ := rule.RelevantToEvent(context.Background(), tc["index"].(string), tc)
		if !relevant {
			t.Fatal(tc, "should have been relevant")
		}
	}

	irrelevant := []map[string]interface{}{
		{
			"index": "wrong-category",
			"foo":   "bar",
		},
		{
			"index": "just-category",
		},
		{
			"index": "wrong-category",
			"foo":   "baz",
		},
		{
			"index": "wrong-category",
			"bar":   "foo",
		},
	}
	for _, tc := range irrelevant {
		relevant, _ := rule.RelevantToEvent(context.Background(), tc["index"].(string), tc)
		if relevant {
			t.Fatal(tc, "shouldn't have been relevant")
		}
	}
}
