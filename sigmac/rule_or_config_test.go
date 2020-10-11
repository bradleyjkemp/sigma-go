package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_isSigmaRule(t *testing.T) {
	tests := []struct {
		file           string
		expectedIsRule bool
	}{
		{
			`title: foo
logsources:
  foo:
    category: process_creation
    index: bar
`,
			false,
		},
		{
			`title: foo
detection:
    foo:
        - bar
        - baz
    selection: foo
`,
			true,
		},
	}
	for _, tt := range tests {
		var isRule ruleOrConfig
		err := yaml.Unmarshal([]byte(tt.file), &isRule)
		if err != nil {
			t.Fatal(err)
		}
		if isRule.IsRule() != tt.expectedIsRule {
			t.Errorf("Expected\n%s to be detected as a rule", tt.file)
		}
	}
}
