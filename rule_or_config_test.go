package sigma

import (
	"testing"
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
		{
			`this: |
isnt valid`,
			InvalidFile,
		},
	}
	for _, tt := range tests {
		fileType := InferFileType([]byte(tt.file))
		if fileType != tt.expectedType {
			t.Errorf("Expected\n%s to be detected as a rule", tt.file)
		}
	}
}
