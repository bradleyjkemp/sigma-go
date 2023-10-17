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

	ID          string        `yaml:",omitempty" json:",omitempty"`
	Related     []RelatedRule `yaml:",omitempty" json:",omitempty"`
	Status      string        `yaml:",omitempty" json:",omitempty"`
	Description string        `yaml:",omitempty" json:",omitempty"`
	Author      string        `yaml:",omitempty" json:",omitempty"`
	Level       string        `yaml:",omitempty" json:",omitempty"`
	References  []string      `yaml:",omitempty" json:",omitempty"`
	Tags        []string      `yaml:",omitempty" json:",omitempty"`

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline,omitempty" json:",inline,omitempty"`
}

type RelatedRule struct {
	ID   string
	Type string
}

type Logsource struct {
	Category   string `yaml:",omitempty" json:",omitempty"`
	Product    string `yaml:",omitempty" json:",omitempty"`
	Service    string `yaml:",omitempty" json:",omitempty"`
	Definition string `yaml:",omitempty" json:",omitempty"`

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline,omitempty" json:",inline,omitempty"`
}

type Detection struct {
	Searches   map[string]Search `yaml:",inline" json:",inline"`
	Conditions Conditions        `yaml:"condition" json:"condition"`
	Timeframe  time.Duration     `yaml:",omitempty" json:",omitempty"`
}

func (d *Detection) UnmarshalYAML(node *yaml.Node) error {
	// we need a custom unmarshaller here to handle the position information for searches
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return fmt.Errorf("cannot unmarshal %d into Detection", node.Kind)
	}

	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]

		switch key.Value {
		case "condition":
			if err := d.Conditions.UnmarshalYAML(value); err != nil {
				return err
			}
		case "timeframe":
			if err := node.Decode(&d.Timeframe); err != nil {
				return err
			}
		default:
			search := Search{}
			if err := search.UnmarshalYAML(value); err != nil {
				return err
			}
			search.node = key
			if d.Searches == nil {
				d.Searches = map[string]Search{}
			}
			d.Searches[key.Value] = search
		}

	}
	return nil
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
		parsed.node = node
		*c = []Condition{parsed}

	case yaml.SequenceNode:
		var conditions []string
		if err := node.Decode(&conditions); err != nil {
			return err
		}
		for i, condition := range conditions {
			parsed, err := ParseCondition(condition)
			if err != nil {
				return fmt.Errorf("error parsing condition \"%s\": %w", condition, err)
			}
			parsed.node = node.Content[i]
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
	node          *yaml.Node     `yaml:",omitempty" json:",omitempty"`
	Keywords      []string       `yaml:",omitempty" json:",omitempty"`
	EventMatchers []EventMatcher `yaml:",omitempty" json:",omitempty"`
}

func (s *Search) UnmarshalYAML(node *yaml.Node) error {
	s.node = node
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

// Position returns the line and column of this Search in the original input
func (s Search) Position() (int, int) {
	return s.node.Line - 1, s.node.Column - 1
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
	node      *yaml.Node    `yaml:",omitempty" json:",omitempty"`
	Field     string        `yaml:",omitempty" json:",omitempty"`
	Modifiers []string      `yaml:",omitempty" json:",omitempty"`
	Values    []interface{} `yaml:",omitempty" json:",omitempty"`
}

// Position returns the line and column of this FieldMatcher in the original input
func (f FieldMatcher) Position() (int, int) {
	return f.node.Line - 1, f.node.Column - 1
}

func (f *FieldMatcher) unmarshal(field *yaml.Node, values *yaml.Node) error {
	f.node = field
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
