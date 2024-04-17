package evaluator

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bradleyjkemp/sigma-go"
)

const testRule = `
id: TEST_RULE
detection:
  a:
    Foo|contains: bar
  b:
    Bar|endswith: baz
  condition: a and b
`

const testConfig = `
title: Test
logsources:
    test:
        product: test

fieldmappings:
    Foo: $.foo
    Bar: $.foobar.baz
`

func FuzzRuleMatches(f *testing.F) {
	f.Add(testRule, testConfig, `{"foo": "bar", "bar": "baz"}`)
	f.Fuzz(func(t *testing.T, rule, config, payload string) {
		r, err := sigma.ParseRule([]byte(rule))
		if err != nil {
			return
		}
		c, err := sigma.ParseConfig([]byte(config))
		if err != nil {
			return
		}

		var e Event
		json.Unmarshal([]byte(payload), &e)

		eval := ForRule(r, WithConfig(c))
		_, err = eval.Matches(context.Background(), e)
	})

}
