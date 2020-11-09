package evaluator

import (
	"context"
	"encoding/json"

	"github.com/bradleyjkemp/sigma-go"
)

type RuleEvaluator struct {
	sigma.Rule
	config        []sigma.Config
	indexes       []string            // the list of indexes that this rule should be applied to. Computed from the Logsource field in the rule and any config that's supplied.
	fieldmappings map[string][]string // a compiled mapping from rule fieldnames to possible event fieldnames

	count   func(ctx context.Context, gb GroupedByValues) (float64, error)
	average func(ctx context.Context, gb GroupedByValues, value float64) (float64, error)
	sum     func(ctx context.Context, gb GroupedByValues, value float64) (float64, error)
	// TODO: support the other aggregation functions
}

// GroupedByValues contains the fields that uniquely identify a distinct aggregation statistic.
// Think of it like a ratelimit key.
//
// For example, if a Sigma rule has a condition like this (attempting to detect login brute forcing)
//
// detection:
//   login_attempt:
//     # something here
//   condition:
//     login_attempt | count() by (username) > 100
//	 timeframe: 1m
//
// Conceptually there's a bunch of boxes somewhere (one for each username) containing their current count.
// Each different GroupedByValues points to a different box.
//
// GroupedByValues
//      ||
//   ___↓↓___          ________
//  | User A |        | User B |
//  |__2041__|        |___01___|
//
// It's up to your implementation to ensure that different GroupedByValues map to different boxes
// (although a default Key() method is provided which is good enough for most use cases)
type GroupedByValues struct {
	ConditionID int // TODO: there's some forward/backward compatibility pitfalls here: what happens if you switch the order of conditions in your Sigma file?
	EventValues map[string]interface{}
}

func (a GroupedByValues) Key() string {
	// This is lazy and a terrible idea as the JSON output shouldn't be relied on to be stable across Go releases
	out, err := json.Marshal(map[string]interface{}{
		"condition_id": a.ConditionID,
		"event_values": a.EventValues,
	})
	if err != nil {
		panic(err)
	}
	return string(out)
}

func ForRule(rule sigma.Rule, options ...Option) *RuleEvaluator {
	e := &RuleEvaluator{Rule: rule}
	for _, option := range options {
		option(e)
	}
	return e
}

func (rule RuleEvaluator) Matches(ctx context.Context, event map[string]interface{}) (bool, error) {
	ruleMatches := false
	for conditionIndex, condition := range rule.Detection.Conditions {
		searchMatches := rule.evaluateSearchExpression(condition.Search, event)

		switch {
		// Event didn't match filters
		case !searchMatches:
			continue

		// Simple query without any aggregation
		case searchMatches && condition.Aggregation == nil:
			ruleMatches = true
			continue // need to continue in case other conditions contain aggregations that need to be evaluated

		// Search expression matched but still need to see if the aggregation returns true
		case searchMatches && condition.Aggregation != nil:
			aggregationMatches, err := rule.evaluateAggregationExpression(ctx, conditionIndex, condition.Aggregation, event)
			if err != nil {
				return false, err
			}
			if aggregationMatches {
				ruleMatches = true
			}
			continue
		}

	}

	return ruleMatches, nil
}
