package sigma

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type RuleEvaluator struct {
	Rule
	count         func(ctx context.Context, key AggregationKey, timeframe time.Duration) int
	countDistinct func(ctx context.Context, key AggregationKey, eventValue interface{}, timeframe time.Duration) int
	min           func(ctx context.Context, key AggregationKey, eventValue int, timeframe time.Duration) int
	max           func(ctx context.Context, key AggregationKey, eventValue int, timeframe time.Duration) int
	avg           func(ctx context.Context, key AggregationKey, eventValue int, timeframe time.Duration) int
	sum           func(ctx context.Context, key AggregationKey, eventValue int, timeframe time.Duration) int
	// TODO: support the "near" aggregation function
}

type AggregationKey struct {
	RuleID      string
	EventValues map[string]interface{}
}

func (a AggregationKey) String() string {
	// This is lazy and a terrible idea as the JSON output shouldn't be relied on to be stable across Go releases
	out, err := json.Marshal(map[string]interface{}{
		"rule_id":      a.RuleID,
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

func CountFunction(count func(ctx context.Context, key AggregationKey, timeframe time.Duration) int) func(evaluator *RuleEvaluator) {
	return func(e *RuleEvaluator) {
		e.count = count
	}
}

func (rule RuleEvaluator) Matches(ctx context.Context, event map[string]interface{}) bool {
	ruleMatches := false
	for _, condition := range rule.Detection.Conditions {
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
			aggregationMatches := rule.evaluateAggregationExpression(ctx, condition, event)
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

func (rule RuleEvaluator) evaluateAggregationExpression(ctx context.Context, condition Condition, event map[string]interface{}) bool {
	aggregation := condition.Aggregation
	var aggregationValue int
	switch aggregation.Function {
	case Count:
		if aggregation.Field == "" {
			// This is a simple count number of events
			aggregationValue = rule.count(ctx, AggregationKey{
				RuleID: rule.ID,
				// TODO: this is broken if a rule has multiple conditions. There needs to include a "condition ID" in this key.
				EventValues: map[string]interface{}{
					// TODO: it's out of spec but would be very useful to support multiple group-by fields.
					aggregation.GroupedBy: event[aggregation.GroupedBy],
				},
			}, rule.Detection.Timeframe)
		} else {
			// This is a more complex, count distinct values for a field
			// TODO: implement this
			panic("count_distinct not yet implemented")
		}

	default:
		panic("unsupported aggregation function")
	}

	switch aggregation.Comparison {
	case Equal:
		return aggregationValue == aggregation.Value
	case NotEqual:
		return aggregationValue != aggregation.Value
	case LessThan:
		return aggregationValue < aggregation.Value
	case LessThanEqual:
		return aggregationValue <= aggregation.Value
	case GreaterThan:
		return aggregationValue > aggregation.Value
	case GreaterThanEqual:
		return aggregationValue >= aggregation.Value
	default:
		panic(fmt.Sprintf("unsupported comparison operation %v", aggregation.Comparison))
	}
}
