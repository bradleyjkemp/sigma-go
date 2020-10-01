package evaluator

import (
	"context"

	"github.com/bradleyjkemp/sigma-go"
)

type Option func(*RuleEvaluator)

func CountImplementation(count func(ctx context.Context, key GroupedByValues) float64) Option {
	return func(e *RuleEvaluator) {
		e.count = count
	}
}

func SumImplementation(sum func(ctx context.Context, key GroupedByValues, value float64) float64) Option {
	return func(e *RuleEvaluator) {
		e.sum = sum
	}
}

func AverageImplementation(average func(ctx context.Context, key GroupedByValues, value float64) float64) Option {
	return func(e *RuleEvaluator) {
		e.average = average
	}
}

func WithConfig(config ...sigma.Config) Option {
	return func(e *RuleEvaluator) {
		// TODO: assert that the configs are in the correct order
		e.config = append(e.config, config...)
		e.calculateIndexes()
		e.calculateFieldMappings()
	}
}
