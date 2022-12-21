package evaluator

import (
	"context"
	"testing"

	_ "embed"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/stretchr/testify/assert"
)

//go:embed logsource_a.config.yml
var logsourceAConfigYml []byte

//go:embed logsource_b.config.yml
var logsourceBConfigYml []byte

//go:embed test_rule.yml
var testRuleYml []byte

var event = map[string]interface{}{
	"payload": map[string]interface{}{
		"something": map[string]interface{}{
			"user_id": "abc123",
		},
	},
}

// Case where we only load one config
func TestOnePaths(t *testing.T) {
	logsourceAConfig, err := sigma.ParseConfig(logsourceAConfigYml)
	assert.NoError(t, err)
	testRule, err := sigma.ParseRule(testRuleYml)
	assert.NoError(t, err)

	ruleEvaluator := ForRule(testRule, WithConfig(logsourceAConfig), WithPlaceholderExpander(placeholderExpander))

	result, err := ruleEvaluator.Matches(context.Background(), event)
	assert.NoError(t, err)
	assert.True(t, result.SearchResults["TestCondition"])

}

// Case where we load two configs
func TestMultipleSamePaths(t *testing.T) {
	logsourceAConfig, err := sigma.ParseConfig(logsourceAConfigYml)
	assert.NoError(t, err)
	logsourceBConfig, err := sigma.ParseConfig(logsourceBConfigYml)
	assert.NoError(t, err)
	testRule, err := sigma.ParseRule(testRuleYml)
	assert.NoError(t, err)

	ruleEvaluator := ForRule(testRule, WithConfig(logsourceAConfig, logsourceBConfig), WithPlaceholderExpander(placeholderExpander))

	result, err := ruleEvaluator.Matches(context.Background(), event)
	assert.NoError(t, err)
	assert.False(t, result.SearchResults["TestCondition"])

	// Now check for other path
	otherEvent := map[string]interface{}{
		"payload": map[string]interface{}{
			"other": map[string]interface{}{
				"user_id": "abc123",
			},
		},
	}

	result, err = ruleEvaluator.Matches(context.Background(), otherEvent)
	assert.NoError(t, err)
	assert.False(t, result.SearchResults["TestCondition"])

}

func placeholderExpander(ctx context.Context, placeholderName string) ([]string, error) {
	return nil, nil
}
