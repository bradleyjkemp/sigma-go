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
	Level       string
	References  []string
	Tags        []string

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline"`
}

type Logsource struct {
	Category   string `yaml:",omitempty"`
	Product    string `yaml:",omitempty"`
	Service    string `yaml:",omitempty"`
	Definition string `yaml:",omitempty"`
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

func (s Search) MarshalYAML() (interface{}, error) {
	if len(s.Keywords) > 0 {
		return s.Keywords, nil
	}

	fieldMatchers := map[string]interface{}{}
	for _, matcher := range s.FieldMatchers {
		key, val := matcher.marshal()
		fieldMatchers[key] = val
	}

	return fieldMatchers, nil
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

func (f *FieldMatcher) marshal() (string, interface{}) {
	key := f.Field
	for _, modifier := range f.Modifiers {
		key += "|" + modifier
	}

	var value interface{}
	if len(f.Values) == 1 {
		value = f.Values[0]
	} else {
		value = f.Values
	}
	return key, value
}

func ParseRule(input []byte) (Rule, error) {
	rule := Rule{}
	err := yaml.Unmarshal(input, &rule)
	return rule, err
}
