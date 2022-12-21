package evaluator

import (
	"context"
	"testing"

	_ "embed"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/stretchr/testify/assert"
)

//go:embed logsource_a.config.yml
var vpnConfigYml []byte

//go:embed logsource_b.config.yml
var apiConfigYml []byte

//go:embed test_rule.yml
var testRuleYml []byte

func TestMultipleSamePaths(t *testing.T) {
	vpnConfig, err := sigma.ParseConfig(vpnConfigYml)
	assert.NoError(t, err)
	apiConfig, err := sigma.ParseConfig(apiConfigYml)
	assert.NoError(t, err)
	testRule, err := sigma.ParseRule(testRuleYml)
	assert.NoError(t, err)

	event := map[string]interface{}{
		"payload": map[string]interface{}{
			"something": map[string]interface{}{
				"user_id": "abc123",
			},
		},
	}

	ruleEvaluator := ForRule(testRule, WithConfig(vpnConfig, apiConfig), WithPlaceholderExpander(placeholderExpander))

	result, err := ruleEvaluator.Matches(context.Background(), event)
	assert.NoError(t, err)
	assert.False(t, result.SearchResults["TestCondition"])

}

func placeholderExpander(ctx context.Context, placeholderName string) ([]string, error) {
	return nil, nil
}
