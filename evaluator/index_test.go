package evaluator

import (
	"fmt"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

func TestRuleEvaluator_RelevantToIndex(t *testing.T) {
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
				Index:      []string{"just-category"},
				Conditions: nil,
				Rewrite:    sigma.Logsource{},
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
				Index:      []string{"category-rewritten-index"},
				Conditions: nil,
				Rewrite:    sigma.Logsource{},
			},
		},
		DefaultIndex: "",
	}))

	fmt.Println(rule.Indexes())

	relevant := []string{
		"just-category",
		"category-rewritten-index",
	}
	for _, tc := range relevant {
		if !rule.RelevantToIndex(tc) {
			t.Fatal(tc, "should have been relevant")
		}
	}

	irrelevant := []string{
		"foobar",
	}
	for _, tc := range irrelevant {
		if rule.RelevantToIndex(tc) {
			t.Fatal(tc, "shouldn't have been relevant")
		}
	}
}
