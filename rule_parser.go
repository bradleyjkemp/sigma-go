package sigma

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	RuleMetadata
	Logsource Logsource
	Detection Detection
}

type RuleMetadata struct {
	ID          string   // a unique ID identifying this rule
	Title       string   // a human-readable summary
	Description string   // a longer description of the rule
	Related     []string // a list of related rules (referenced by ID) TODO: update this to reflect the new Sigma format for this field
	Status      string   // the stability of this rule
	Level       string   // the severity of this rule
	Author      string   // who wrote this rule
	References  []string // hyperlinks to any supporting research
	Tags        []string // a set of tags (e.g. MITRE ATT&CK techniques)

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
	EventMatchers []EventMatcher
}

func (s *Search) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	// In the common case, SearchIdentifiers are a single EventMatcher (map of field names to values)
	case yaml.MappingNode:
		s.EventMatchers = []EventMatcher{{}}
		return node.Decode(&s.EventMatchers[0])

	// Or, SearchIdentifiers can be a list.
	// Either of keywords (not supported by this library) or a list of EventMatchers (maps of fields to values)
	case yaml.SequenceNode:
		switch node.Content[0].Kind {
		case yaml.ScalarNode:
			return node.Decode(&s.Keywords)
		case yaml.MappingNode:
			return node.Decode(&s.EventMatchers)
		default:
			return fmt.Errorf("invalid condition list node type %d", node.Kind)
		}

	default:
		return fmt.Errorf("invalid condition node type %d", node.Kind)
	}
}

type EventMatcher []FieldMatcher

func (f *EventMatcher) UnmarshalYAML(node *yaml.Node) error {
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("internal: node.Content %% 2 != 0")
	}

	for i := 0; i < len(node.Content); i += 2 {
		matcher := FieldMatcher{}
		err := matcher.unmarshal(node.Content[i], node.Content[i+1])
		if err != nil {
			return err
		}
		*f = append(*f, matcher)
	}
	return nil
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
