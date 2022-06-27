package sigma

import (
	"gopkg.in/yaml.v3"
)

func InferFileType(contents []byte) FileType {
	var fileType FileType
	if err := yaml.Unmarshal(contents, &fileType); err != nil {
		fileType = InvalidFile
	}
	return fileType
}

type FileType string

const (
	UnknownFile FileType = ""
	InvalidFile FileType = "invalid"
	RuleFile    FileType = "rule"
	ConfigFile  FileType = "config"
)

func (f *FileType) UnmarshalYAML(node *yaml.Node) error {
	// Check if there's a key called "detection".
	// This is a required field in a Sigma rule but doesn't exist in a config
	for _, node := range node.Content {
		if node.Kind == yaml.ScalarNode && node.Value == "detection" {
			*f = RuleFile
			return nil
		}
		if node.Kind == yaml.ScalarNode && node.Value == "logsources" {
			*f = ConfigFile
			return nil
		}
	}
	return nil
}
