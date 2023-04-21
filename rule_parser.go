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
	ID          string   `yaml:",omitempty"` // a unique ID identifying this rule
	Title       string   `yaml:",omitempty"` // a human-readable summary
	Description string   `yaml:",omitempty"` // a longer description of the rule
	Related     []string `yaml:",omitempty"` // a list of related rules (referenced by ID) TODO: update this to reflect the new Sigma format for this field
	Status      string   `yaml:",omitempty"` // the stability of this rule
	Level       string   `yaml:",omitempty"` // the severity of this rule
	Author      string   `yaml:",omitempty"` // who wrote this rule
	References  []string `yaml:",omitempty"` // hyperlinks to any supporting research
	Tags        []string `yaml:",omitempty"` // a set of tags (e.g. MITRE ATT&CK techniques)

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline"`
}

type RelatedRule struct {
	ID   string
	Type string
}

type Logsource struct {
	Category   string `yaml:",omitempty"`
	Product    string `yaml:",omitempty"`
	Service    string `yaml:",omitempty"`
	Definition string `yaml:",omitempty"`

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline"`
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

// Marshal the conditions back to grammar expressions :sob:
func (c Conditions) MarshalYAML() (interface{}, error) {
	if len(c) == 1 {
		return c[0], nil
	} else {
		return []Condition(c), nil
	}
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
		if len(node.Content) == 0 {
			return fmt.Errorf("invalid search condition node (empty)")
		}

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

func (s Search) MarshalYAML() (interface{}, error) {

	var err error
	result := &yaml.Node{}

	if s.Keywords != nil {
		err = result.Encode(&s.Keywords)
	} else if len(s.EventMatchers) == 1 {
		err = result.Encode(&s.EventMatchers[0])
	} else if len(s.EventMatchers) == 0 {
		err = fmt.Errorf("no search criteria")
	} else {
		err = result.Encode(&s.EventMatchers)
	}

	return result, err
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

func (f EventMatcher) MarshalYAML() (interface{}, error) {

	// Event matchers are represented by mapping nodes
	result := &yaml.Node{
		Kind: yaml.MappingNode,
	}

	// Reconstruct the mapping node for this event matcher
	for _, matcher := range f {
		// Reconstruct the field and value nodes
		if field_node, value_node, err := matcher.marshal(); err != nil {
			return nil, err
		} else {
			// Store the field name/value
			result.Content = append(result.Content, field_node, value_node)
		}
	}

	return result, nil
}

type FieldMatcher struct {
	Field     string
	Modifiers []string
	Values    []interface{}
}

func (f *FieldMatcher) unmarshal(field *yaml.Node, values *yaml.Node) error {
	fieldParts := strings.Split(field.Value, "|")
	f.Field, f.Modifiers = fieldParts[0], fieldParts[1:]

	switch values.Kind {
	case yaml.ScalarNode:
		f.Values = []interface{}{nil}
		return values.Decode(&f.Values[0])
	case yaml.SequenceNode:
		return values.Decode(&f.Values)
	case yaml.MappingNode:
		f.Values = []interface{}{map[string]interface{}{}}
		return values.Decode(&f.Values[0])
	case yaml.AliasNode:
		return f.unmarshal(field, values.Alias)
	}
	return nil
}

func (f *FieldMatcher) marshal() (field_node *yaml.Node, value_node *yaml.Node, err error) {

	// Reconstruct the field name with modifiers
	field := f.Field
	if len(f.Modifiers) > 0 {
		field = field + "|" + strings.Join(f.Modifiers, "|")
	}

	// Encode the field name
	field_node = &yaml.Node{}
	err = field_node.Encode(&field)
	if err != nil {
		return nil, nil, err
	}

	// Encode the field value(s)
	value_node = &yaml.Node{}
	if len(f.Values) == 1 {
		err = value_node.Encode(&f.Values[0])
	} else {
		err = value_node.Encode(&f.Values)
	}
	if err != nil {
		return nil, nil, err
	}

	return field_node, value_node, err
}

func ParseRule(input []byte) (Rule, error) {
	rule := Rule{}
	err := yaml.Unmarshal(input, &rule)
	return rule, err
}
