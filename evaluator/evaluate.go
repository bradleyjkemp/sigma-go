package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator/modifiers"
)

type RuleEvaluator struct {
	sigma.Rule
	config          []sigma.Config
	indexes         []string            // the list of indexes that this rule should be applied to. Computed from the Logsource field in the rule and any config that's supplied.
	indexConditions []sigma.Search      // any field-value conditions that need to match for this rule to apply to events from []indexes
	fieldmappings   map[string][]string // a compiled mapping from rule fieldnames to possible event fieldnames

	expandPlaceholder func(ctx context.Context, placeholderName string) ([]string, error)
	caseSensitive     bool
	lazy              bool
	comparators       map[string]modifiers.Comparator

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
//
//	  login_attempt:
//	    # something here
//	  condition:
//	    login_attempt | count() by (username) > 100
//		 timeframe: 1m
//
// Conceptually there's a bunch of boxes somewhere (one for each username) containing their current count.
// Each different GroupedByValues points to a different box.
//
// GroupedByValues
//
//	    ||
//	 ___↓↓___          ________
//	| User A |        | User B |
//	|__2041__|        |___01___|
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
	e := &RuleEvaluator{Rule: rule, comparators: modifiers.Comparators}
	for _, option := range options {
		option(e)
	}
	return e
}

type Result struct {
	Match            bool            // whether this event matches the Sigma rule
	SearchResults    map[string]bool // For each Search, whether it matched the event
	ConditionResults []bool          // For each Condition, whether it matched the event
}

// Event should be some form a map[string]interface{} or map[string]string
type Event interface{}

func eventValue(e Event, key string) interface{} {
	switch evt := e.(type) {
	case map[string]string:
		return evt[key]
	case map[string]interface{}:
		return evt[key]
	default:
		return ""
	}
}

func (rule RuleEvaluator) Matches(ctx context.Context, event Event) (Result, error) {
	return rule.matches(ctx, event, rule.comparators)
}

func (rule RuleEvaluator) matches(ctx context.Context, event Event, comparators map[string]modifiers.Comparator) (Result, error) {
	result := Result{
		Match:            false,
		SearchResults:    map[string]bool{},
		ConditionResults: make([]bool, len(rule.Detection.Conditions)),
	}

	if !rule.lazy {
		// must evaluate all searches up front
		for identifier, search := range rule.Detection.Searches {
			var err error
			result.SearchResults[identifier], err = rule.evaluateSearch(ctx, search, event, comparators)
			if err != nil {
				return Result{}, fmt.Errorf("error evaluating search %s: %w", identifier, err)
			}
		}
	}

	var searchErr error
	searchResults := func(identifier string) bool {
		searchResult, ok := result.SearchResults[identifier]
		if ok {
			return searchResult
		}

		search, ok := rule.Detection.Searches[identifier]
		if !ok {
			return false // compatibility with old behaviour
		}
		var err error
		result.SearchResults[identifier], err = rule.evaluateSearch(ctx, search, event, comparators)
		if err != nil {
			searchErr = fmt.Errorf("error evaluating search %s: %w", identifier, err)
			return false
		}
		return result.SearchResults[identifier]
	}
	for conditionIndex, condition := range rule.Detection.Conditions {
		searchMatches := rule.evaluateSearchExpression(condition.Search, searchResults)

		switch {
		// Event didn't match filters
		case !searchMatches:
			result.ConditionResults[conditionIndex] = false
			continue

		// Simple query without any aggregation
		case searchMatches && condition.Aggregation == nil:
			result.ConditionResults[conditionIndex] = true
			result.Match = true
			continue // need to continue in case other conditions contain aggregations that need to be evaluated

		// Search expression matched but still need to see if the aggregation returns true
		case searchMatches && condition.Aggregation != nil:
			aggregationMatches, err := rule.evaluateAggregationExpression(ctx, conditionIndex, condition.Aggregation, event)
			if err != nil {
				return Result{}, err
			}
			if aggregationMatches {
				result.Match = true
				result.ConditionResults[conditionIndex] = true
			}
			continue
		}
	}

	return result, searchErr
}
