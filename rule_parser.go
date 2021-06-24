package sigma

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	// Required fields
	Title     string
	Logsource Logsource
	Detection Detection

	ID          string
	Related     []string
	Status      string
	Description string
	Author      string
	References  []string
	Tags        []string

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline"`
}

type Logsource struct {
	Category   string
	Product    string
	Service    string
	Definition string
}

type Detection struct {
	Searches   map[string]Search `yaml:",inline"`
	Conditions Conditions        `yaml:"condition"`
	Timeframe  time.Duration     `yaml:",omitempty"`
}

type Conditions []Condition

func (c *Conditions) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var condition string
		if err := node.Decode(&condition); err != nil {
			return err
		}

		parsed, err := ParseCondition(condition)
		if err != nil {
			return err
		}
		*c = []Condition{parsed}

	case yaml.SequenceNode:
		var conditions []string
		if err := node.Decode(&conditions); err != nil {
			return err
		}
		for _, condition := range conditions {
			parsed, err := ParseCondition(condition)
			if err != nil {
				return fmt.Errorf("error parsing condition \"%s\": %w", condition, err)
			}
			*c = append(*c, parsed)
		}

	default:
		return fmt.Errorf("invalid condition node type %d", node.Kind)
	}

	return nil
}

type Search struct {
	Keywords      []string
	FieldMatchers []FieldMatcher
}

func (s *Search) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	// SearchIdentifiers can be a list of keywords
	case yaml.SequenceNode:
		return node.Decode(&s.Keywords)

	// Or SearchIdentifiers can a map of field names to values
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("internal: node.Content %% 2 != 0")
		}

		for i := 0; i < len(node.Content); i += 2 {
			matcher := FieldMatcher{}
			err := matcher.unmarshal(node.Content[i], node.Content[i+1])
			if err != nil {
				return err
			}
			s.FieldMatchers = append(s.FieldMatchers, matcher)
		}
		return nil

	default:
		return fmt.Errorf("invalid condition node type %d", node.Kind)
	}
}

type FieldMatcher struct {
	Field     string
	Modifiers []string
	Values    []string
}

func (f *FieldMatcher) unmarshal(field *yaml.Node, values *yaml.Node) error {
	fieldParts := strings.Split(field.Value, "|")
	f.Field, f.Modifiers = fieldParts[0], fieldParts[1:]

	switch values.Kind {
	case yaml.ScalarNode:
		f.Values = []string{values.Value}

	case yaml.SequenceNode:
		return values.Decode(&f.Values)
	}
	return nil
}

func ParseRule(input []byte) (Rule, error) {
	rule := Rule{}
	err := yaml.Unmarshal(input, &rule)
	return rule, err
}
