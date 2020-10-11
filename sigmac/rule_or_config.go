package main

import (
	"gopkg.in/yaml.v3"
)

type ruleOrConfig string

func (r ruleOrConfig) IsRule() bool {
	return r == "rule"
}

func (r *ruleOrConfig) UnmarshalYAML(node *yaml.Node) error {
	// Check if there's a key called "detection".
	// This is a required field in a Sigma rule but doesn't exist in a config
	for _, node := range node.Content {
		if node.Kind == yaml.ScalarNode && node.Value == "detection" {
			*r = "rule"
			return nil
		}
	}
	return nil
}
