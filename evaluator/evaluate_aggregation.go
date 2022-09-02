package evaluator

import (
	"context"
	"fmt"
	"strconv"

	"github.com/bradleyjkemp/sigma-go"
)

func (rule RuleEvaluator) evaluateAggregationExpression(ctx context.Context, conditionIndex int, aggregation sigma.AggregationExpr, event Event) (bool, error) {
	switch agg := aggregation.(type) {
	case sigma.Near:
		return false, fmt.Errorf("near isn't supported yet")

	case sigma.Comparison:
		aggregationValue, err := rule.evaluateAggregationFunc(ctx, conditionIndex, agg.Func, event)
		if err != nil {
			return false, err
		}
		switch agg.Op {
		case sigma.Equal:
			return aggregationValue == agg.Threshold, nil
		case sigma.NotEqual:
			return aggregationValue != agg.Threshold, nil
		case sigma.LessThan:
			return aggregationValue < agg.Threshold, nil
		case sigma.LessThanEqual:
			return aggregationValue <= agg.Threshold, nil
		case sigma.GreaterThan:
			return aggregationValue > agg.Threshold, nil
		case sigma.GreaterThanEqual:
			return aggregationValue >= agg.Threshold, nil
		default:
			return false, fmt.Errorf("unsupported comparison operation %v", agg.Op)
		}

	default:
		return false, fmt.Errorf("unknown aggregation expression")
	}
}

func (rule RuleEvaluator) evaluateAggregationFunc(ctx context.Context, conditionIndex int, aggregation sigma.AggregationFunc, event Event) (float64, error) {
	switch agg := aggregation.(type) {
	case sigma.Count:
		if agg.Field == "" {
			// This is a simple count number of events
			return rule.count(ctx, GroupedByValues{
				ConditionID: conditionIndex,
				EventValues: map[string]interface{}{
					// TODO: it's out of spec but would be very useful to support multiple group-by fields.
					agg.GroupedBy: eventValue(event, agg.GroupedBy),
				},
			})
		} else {
			// This is a more complex, count distinct values for a field
			// TODO: implement this
			return 0, fmt.Errorf("count_distinct not yet implemented")
		}

	case sigma.Average:
		val, err := strconv.ParseFloat(fmt.Sprint(eventValue(event, agg.Field)), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid float value: %w", err)
		}
		return rule.average(ctx, GroupedByValues{
			ConditionID: conditionIndex,
			EventValues: map[string]interface{}{
				// TODO: it's out of spec but would be very useful to support multiple group-by fields.
				agg.GroupedBy: eventValue(event, agg.GroupedBy),
			},
		}, val)

	case sigma.Sum:
		val, err := strconv.ParseFloat(fmt.Sprint(eventValue(event, agg.Field)), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid float value: %w", err)
		}
		return rule.sum(ctx, GroupedByValues{
			ConditionID: conditionIndex,
			EventValues: map[string]interface{}{
				// TODO: it's out of spec but would be very useful to support multiple group-by fields.
				agg.GroupedBy: eventValue(event, agg.GroupedBy),
			},
		}, val)

	default:
		return 0, fmt.Errorf("unsupported aggregation function")
	}
}
