package sigma

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type RuleEvaluator struct {
	Rule
	count func(ctx context.Context, gb GroupedByValues) float64 // TODO: how to pass an event timestamp here and enable running rules on historical events?
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

type EvaluatorOption func(*RuleEvaluator)

func Evaluator(rule Rule, options ...EvaluatorOption) *RuleEvaluator {
	e := &RuleEvaluator{Rule: rule}
	for _, option := range options {
		option(e)
	}
	return e
}

func CountImplementation(count func(ctx context.Context, key GroupedByValues) float64) func(evaluator *RuleEvaluator) {
	return func(e *RuleEvaluator) {
		e.count = count
	}
}

func (rule RuleEvaluator) Matches(ctx context.Context, event map[string]interface{}) bool {
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
			aggregationMatches := rule.evaluateAggregationExpression(ctx, conditionIndex, condition.Aggregation, event)
			if aggregationMatches {
				ruleMatches = true
			}
			continue
		}

	}

	return ruleMatches
}

func (rule RuleEvaluator) evaluateSearchExpression(search SearchExpr, event map[string]interface{}) bool {
	switch s := search.(type) {
	case And:
		return rule.evaluateSearchExpression(s.Left, event) && rule.evaluateSearchExpression(s.Right, event)

	case Or:
		return rule.evaluateSearchExpression(s.Left, event) || rule.evaluateSearchExpression(s.Right, event)

	case Not:
		return !rule.evaluateSearchExpression(s.Expr, event)

	case SearchIdentifier:
		search, ok := rule.Detection.Searches[s.Name]
		if !ok {
			panic("invalid search identifier")
		}
		return rule.evaluateSearch(search, event)
	}

	panic(false)
}

func (rule RuleEvaluator) evaluateSearch(search Search, event map[string]interface{}) bool {
	if len(search.Keywords) > 0 {
		panic("keywords unsupported")
	}

	for _, matcher := range search.FieldMatchers {
		andValues := false
		fieldModifiers := matcher.Modifiers
		if len(matcher.Modifiers) > 0 && fieldModifiers[len(fieldModifiers)-1] == "all" {
			andValues = true
			fieldModifiers = fieldModifiers[:len(fieldModifiers)-1]
		}

		valueMatcher := baseMatcher
		for _, name := range fieldModifiers {
			if modifiers[name] == nil {
				panic(fmt.Errorf("unsupported modifier %s", name))
			}
			valueMatcher = modifiers[name](valueMatcher)
		}

		matched := andValues
		for _, value := range matcher.Values {
			if andValues {
				matched = matched && valueMatcher(event[matcher.Field], value)
			} else {
				matched = matched || valueMatcher(event[matcher.Field], value)
			}
		}

		if !matched {
			// this field didn't match so the overall matcher doesn't match
			return false
		}
	}

	// all fields matched
	return true
}

type valueMatcher func(actual interface{}, expected string) bool

func baseMatcher(actual interface{}, expected string) bool {
	//fmt.Printf("=(%s, %s)\n", actual, expected)
	return fmt.Sprintf("%v", actual) == expected
}

type valueModifier func(next valueMatcher) valueMatcher

var modifiers = map[string]valueModifier{
	"contains": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			//fmt.Printf("contains(%s, %s)\n", actual, expected)
			return strings.Contains(fmt.Sprintf("%v", actual), expected)
		}
	},
	"endswith": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			//fmt.Printf("endswith(%s, %s)\n", actual, expected)
			return strings.HasSuffix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"startswith": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			//fmt.Printf("startswith(%s, %s)\n", actual, expected)
			return strings.HasPrefix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"base64": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			return next(actual, base64.StdEncoding.EncodeToString([]byte(expected)))
		}
	},
}

func (rule RuleEvaluator) evaluateAggregationExpression(ctx context.Context, conditionIndex int, aggregation AggregationExpr, event map[string]interface{}) bool {
	switch agg := aggregation.(type) {
	case Near:
		panic("near isn't supported yet")

	case Comparison:
		aggregationValue := rule.evaluateAggregationFunc(ctx, conditionIndex, agg.Func, event)
		switch agg.Op {
		case Equal:
			return aggregationValue == agg.Threshold
		case NotEqual:
			return aggregationValue != agg.Threshold
		case LessThan:
			return aggregationValue < agg.Threshold
		case LessThanEqual:
			return aggregationValue <= agg.Threshold
		case GreaterThan:
			return aggregationValue > agg.Threshold
		case GreaterThanEqual:
			return aggregationValue >= agg.Threshold
		default:
			panic(fmt.Sprintf("unsupported comparison operation %v", agg.Op))
		}

	default:
		panic("unknown aggregation expression")
	}
}

func (rule RuleEvaluator) evaluateAggregationFunc(ctx context.Context, conditionIndex int, aggregation AggregationFunc, event map[string]interface{}) float64 {
	switch agg := aggregation.(type) {
	case Count:
		if agg.Field == "" {
			// This is a simple count number of events
			return rule.count(ctx, GroupedByValues{
				ConditionID: conditionIndex,
				EventValues: map[string]interface{}{
					// TODO: it's out of spec but would be very useful to support multiple group-by fields.
					agg.GroupedBy: event[agg.GroupedBy],
				},
			})
		} else {
			// This is a more complex, count distinct values for a field
			// TODO: implement this
			panic("count_distinct not yet implemented")
		}

	default:
		panic("unsupported aggregation function")
	}
}
