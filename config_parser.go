package sigma

import (
	"gopkg.in/yaml.v3"
)

type Config struct {
	Title         string                      // A short description of what this configuration does
	Order         int                         `yaml:",omitempty"` // Defines the order of expansion when multiple config files are applicable
	Backends      []string                    `yaml:",omitempty"` // Lists the Sigma implementations that this config file is compatible with
	FieldMappings map[string]FieldMapping     `yaml:",omitempty"`
	Logsources    map[string]LogsourceMapping `yaml:",omitempty"`
	// TODO: LogsourceMerging option
	DefaultIndex string                   `yaml:",omitempty"` // Defines a default index if no logsources match
	Placeholders map[string][]interface{} `yaml:",omitempty"` // Defines values for placeholders that might appear in Sigma rules
}

type FieldMapping struct {
	TargetNames []string // The name(s) that appear in the events being matched
	// TODO: support conditional mappings?
}

func (f *FieldMapping) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		f.TargetNames = []string{value.Value}

	case yaml.SequenceNode:
		var values []string
		err := value.Decode(&values)
		if err != nil {
			return err
		}
		f.TargetNames = values
	}
	return nil
}

func (f FieldMapping) MarshalYAML() (interface{}, error) {
	if len(f.TargetNames) == 1 {
		return f.TargetNames[0], nil // just a plain string
	}

	return f.TargetNames, nil // an array of strings
}

type LogsourceMapping struct {
	Logsource  `yaml:",inline"` // Matches the logsource field in Sigma rules
	Index      LogsourceIndexes `yaml:",omitempty"` // The index(es) that should be used
	Conditions Search           `yaml:",omitempty"` // Conditions that are added to all rules targeting this logsource
	Rewrite    Logsource        `yaml:",omitempty"` // Rewrites this logsource (i.e. so that it can be matched by another lower precedence config)
}

type LogsourceIndexes []string

func (i *LogsourceIndexes) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*i = []string{value.Value}

	case yaml.SequenceNode:
		var values []string
		err := value.Decode(&values)
		if err != nil {
			return err
		}
		*i = values
	}
	return nil
}

func (i LogsourceIndexes) MarshalYAML() (interface{}, error) {
	if len(i) == 1 {
		return i[0], nil
	}

	return i, nil
}

func ParseConfig(contents []byte) (Config, error) {
	config := Config{}
	return config, yaml.Unmarshal(contents, &config)
}
