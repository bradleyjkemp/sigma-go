package evaluator

import (
	"context"
	"github.com/bradleyjkemp/sigma-go/evaluator/modifiers"

	"github.com/bradleyjkemp/sigma-go"
)

type Option func(*RuleEvaluator)

func CountImplementation(count func(ctx context.Context, key GroupedByValues) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.count = count
	}
}

func SumImplementation(sum func(ctx context.Context, key GroupedByValues, value float64) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.sum = sum
	}
}

func AverageImplementation(average func(ctx context.Context, key GroupedByValues, value float64) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.average = average
	}
}

func WithPlaceholderExpander(f func(ctx context.Context, placeholderName string) ([]string, error)) Option {
	return func(e *RuleEvaluator) {
		e.expandPlaceholder = f
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

// CaseSensitive turns off the default Sigma behaviour that string operations are by default case-insensitive
// This can increase performance (especially for larger events) by skipping expensive calls to strings.ToLower
func CaseSensitive(e *RuleEvaluator) {
	e.caseSensitive = true
	e.comparators = modifiers.ComparatorsCaseSensitive
}

// LazyEvaluation allows the evaluator to skip evaluating searches if they won't affect the overall match result
func LazyEvaluation(e *RuleEvaluator) {
	e.lazy = true
}
