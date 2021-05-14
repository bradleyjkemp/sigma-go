package sigma

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_isSigmaRule(t *testing.T) {
	tests := []struct {
		file         string
		expectedType FileType
	}{
		{
			`title: foo
logsources:
  foo:
    category: process_creation
    index: bar
`,
			ConfigFile,
		},
		{
			`title: foo
detection:
    foo:
        - bar
        - baz
    selection: foo
`,
			RuleFile,
		},
	}
	for _, tt := range tests {
		var fileType FileType
		err := yaml.Unmarshal([]byte(tt.file), &fileType)
		if err != nil {
			t.Fatal(err)
		}
		if fileType != tt.expectedType {
			t.Errorf("Expected\n%s to be detected as a rule", tt.file)
		}
	}
}
