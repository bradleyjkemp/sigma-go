package sigma

import "gopkg.in/yaml.v3"

type Config struct {
	Title         string   // A short description of what this configuration does
	Order         int      // Defines the order of expansion when multiple config files are applicable
	Backends      []string // Lists the Sigma implementations that this config file is compatible with
	FieldMappings map[string]FieldMapping
	Logsources    map[string]LogsourceMapping
	// TODO: LogsourceMerging option
	DefaultIndex string                   // Defines a default index if no logsources match
	Placeholders map[string][]interface{} // Defines values for placeholders that might appear in Sigma rules
}

type FieldMapping struct {
	SourceName  string   // The name that appears in a Sigma rule
	TargetNames []string // The name(s) that appear in the events being matched
	// TODO: support conditional mappings?
}

type LogsourceMapping struct {
	Logsource  `yaml:",inline"`       // Matches the logsource field in Sigma rules
	Index      string                 // The index that should be used
	Conditions map[string]interface{} // Conditions that are added to all rules targeting this logsource
	Rewrite    Logsource              // Rewrites this logsource (i.e. so that it can be matched by another lower precedence config)
}

func ParseConfig(contents []byte) (Config, error) {
	config := Config{}
	return config, yaml.Unmarshal(contents, &config)
}
