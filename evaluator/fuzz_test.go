package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
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

const testRuleRe = `
id: TEST_RULE
detection:
  a:
    Foo|re: bar
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

func FuzzRuleBundleMatches(f *testing.F) {
	f.Add(testRule, testRule, testConfig, `{"foo": "bar", "bar": "baz"}`, false)
	f.Add(testRule, testRuleRe, testConfig, `{"foo": "bar", "bar": "baz"}`, false)
	f.Fuzz(func(t *testing.T, rule1, rule2, config, payload string, caseSensitive bool) {
		var r1, r2 sigma.Rule
		var c sigma.Config
		var err error
		wg := sync.WaitGroup{}
		wg.Add(1)

		go func() {
			defer func() {
				wg.Done()
				if r := recover(); r != nil {
					err = fmt.Errorf("panic in parsing")
				}
			}()
			r1, err = sigma.ParseRule([]byte(rule1))
			if err != nil || len(r1.Detection.Searches) == 0 || len(r1.Detection.Conditions) == 0 {
				return
			}
			r2, err = sigma.ParseRule([]byte(rule2))
			if err != nil || len(r2.Detection.Searches) == 0 || len(r2.Detection.Conditions) == 0 {
				return
			}
			c, err = sigma.ParseConfig([]byte(config))
			if err != nil {
				return
			}
		}()
		wg.Wait()
		if err != nil {
			return
		}

		var e Event
		if err := json.Unmarshal([]byte(payload), &e); err != nil {
			return
		}
		if reflect.TypeOf(e).Kind() != reflect.Map {
			return
		}

		options := []Option{WithConfig(c)}
		if caseSensitive {
			options = append(options, CaseSensitive)
		}

		eval1 := ForRule(r1, WithConfig(c))
		eval2 := ForRule(r2, WithConfig(c))
		match1, err1 := eval1.Matches(context.Background(), e)
		if err1 != nil {
			return
		}
		match2, err2 := eval2.Matches(context.Background(), e)
		if err2 != nil {
			return
		}

		bundle := ForRules([]sigma.Rule{r1, r2}, WithConfig(c))
		matches, errs := bundle.Matches(context.Background(), e)
		if errs != nil {
			panic(errs)
		}
		if len(matches) != 2 {
			panic(fmt.Sprint("didn't get 2 matches, got", len(matches), err))
		}

		if !reflect.DeepEqual(matches[0].Result, match1) {
			panic(fmt.Sprint("difference in match1\nbundle:     ", matches[0].Result, "\nstandalone: ", match1))
		}
		if !reflect.DeepEqual(matches[1].Result, match2) {
			panic(fmt.Sprint("difference in match2\nbundle:     ", matches[1].Result, "\nstandalone: ", match2))
		}
	})
}
