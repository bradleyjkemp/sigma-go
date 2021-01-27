package main

import (
	"gopkg.in/yaml.v3"
)

type fileType string

const (
	rule   fileType = "rule"
	config fileType = "config"
)

func (f *fileType) UnmarshalYAML(node *yaml.Node) error {
	// Check if there's a key called "detection".
	// This is a required field in a Sigma rule but doesn't exist in a config
	for _, node := range node.Content {
		if node.Kind == yaml.ScalarNode && node.Value == "detection" {
			*f = rule
			return nil
		}
		if node.Kind == yaml.ScalarNode && node.Value == "logsources" {
			*f = config
			return nil
		}
	}
	return nil
}
