package sigma

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"strconv"
	"strings"
	"time"
)

type Correlation struct {
	RuleMetadata

	Type     CorrelationType // the type of correlation
	Rule     Rules           // a list of (possibly one) rule IDs that this correlates over
	GroupBy  []string        // a list of fields to group the correlation by
	Timespan Timespan        // the time window that correlated events must occur within

	Condition CorrelationCondition // for event_count or value_count rules, a numeric condition on the count necessary for this rule to fire
}

type CorrelationType string

var (
	CorrelationEventCount CorrelationType = "event_count"
	CorrelationValueCount CorrelationType = "value_count"
	CorrelationTemporal   CorrelationType = "temporal"
)

type Timespan time.Time

type CorrelationCondition struct {
	GreaterThan        *int
	GreaterThanEqual   *int
	LessThan           *int
	LessThanEqual      *int
	RangeMin, RangeMax *int
}

func (c *CorrelationCondition) UnmarshalYAML(value *yaml.Node) error {
	switch {
	case value.Kind != yaml.MappingNode:
		return fmt.Errorf("expected correlation condition to be a map")
	case len(value.Content) != 2:
		return fmt.Errorf("expected a single key-value pair, got %d", len(value.Content)/2)
	}

	operator := value.Content[0].Value
	threshold := value.Content[1]
	switch operator {
	case "gt":
		return threshold.Decode(c.GreaterThan)
	case "gte":
		return threshold.Decode(c.GreaterThanEqual)
	case "lt":
		return threshold.Decode(c.LessThan)
	case "lte":
		return threshold.Decode(c.LessThanEqual)
	case "range":
		min, max, _ := strings.Cut(threshold.Value, "..")
		var err error
		*c.RangeMin, err = strconv.Atoi(min)
		if err != nil {
			return fmt.Errorf("invalid range minimum: %v", err)
		}
		*c.RangeMax, err = strconv.Atoi(max)
		if err != nil {
			return fmt.Errorf("invalid range maximum: %v", err)
		}
	default:
		return fmt.Errorf("unknown operator \"%s\"", operator)
	}
	return nil
}

func (c CorrelationCondition) Matches(i int) bool {
	switch {
	case c.GreaterThan != nil:
		return i > *c.GreaterThan
	case c.GreaterThanEqual != nil:
		return i >= *c.GreaterThanEqual
	case c.LessThan != nil:
		return i < *c.LessThan
	case c.LessThanEqual != nil:
		return i <= *c.LessThanEqual
	case c.RangeMin != nil && c.RangeMax != nil:
		return i >= *c.RangeMin && i <= *c.RangeMax
	default:
		return false
	}
}

type Rules []string

func (i *Rules) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*i = []string{value.Value}
		return nil

	case yaml.SequenceNode:
		v := []string{}
		err := value.Decode(&v)
		*i = v
		return err
	default:
		return fmt.Errorf("unexpected node kind %v", value.Kind)
	}
}

func ParseCorrelation(input []byte) (Correlation, error) {
	correlation := Correlation{}
	err := yaml.Unmarshal(input, &correlation)
	return correlation, err
}
