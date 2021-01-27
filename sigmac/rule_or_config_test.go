package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_isSigmaRule(t *testing.T) {
	tests := []struct {
		file         string
		expectedType fileType
	}{
		{
			`title: foo
logsources:
  foo:
    category: process_creation
    index: bar
`,
			config,
		},
		{
			`title: foo
detection:
    foo:
        - bar
        - baz
    selection: foo
`,
			rule,
		},
	}
	for _, tt := range tests {
		var fileType fileType
		err := yaml.Unmarshal([]byte(tt.file), &fileType)
		if err != nil {
			t.Fatal(err)
		}
		if fileType != tt.expectedType {
			t.Errorf("Expected\n%s to be detected as a rule", tt.file)
		}
	}
}
