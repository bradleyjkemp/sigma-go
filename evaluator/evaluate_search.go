package evaluator

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bradleyjkemp/sigma-go"
)

func (rule RuleEvaluator) evaluateSearchExpression(search sigma.SearchExpr, event map[string]interface{}) bool {
	switch s := search.(type) {
	case sigma.And:
		return rule.evaluateSearchExpression(s.Left, event) && rule.evaluateSearchExpression(s.Right, event)

	case sigma.Or:
		return rule.evaluateSearchExpression(s.Left, event) || rule.evaluateSearchExpression(s.Right, event)

	case sigma.Not:
		return !rule.evaluateSearchExpression(s.Expr, event)

	case sigma.SearchIdentifier:
		search, ok := rule.Detection.Searches[s.Name]
		if !ok {
			panic("invalid search identifier")
		}
		return rule.evaluateSearch(search, event)
	}

	panic(false)
}

func (rule RuleEvaluator) evaluateSearch(search sigma.Search, event map[string]interface{}) bool {
	if len(search.Keywords) > 0 {
		panic("keywords unsupported")
	}

	for _, matcher := range search.FieldMatchers {
		andValues := false
		fieldModifiers := matcher.Modifiers
		if len(matcher.Modifiers) > 0 && fieldModifiers[len(fieldModifiers)-1] == "all" {
			andValues = true
			fieldModifiers = fieldModifiers[:len(fieldModifiers)-1]
		}

		valueMatcher := baseMatcher
		for _, name := range fieldModifiers {
			if modifiers[name] == nil {
				panic(fmt.Errorf("unsupported modifier %s", name))
			}
			valueMatcher = modifiers[name](valueMatcher)
		}

		matched := andValues
		for _, value := range matcher.Values {
			if andValues {
				matched = matched && valueMatcher(event[matcher.Field], value)
			} else {
				matched = matched || valueMatcher(event[matcher.Field], value)
			}
		}

		if !matched {
			// this field didn't match so the overall matcher doesn't match
			return false
		}
	}

	// all fields matched
	return true
}

type valueMatcher func(actual interface{}, expected string) bool

func baseMatcher(actual interface{}, expected string) bool {
	//fmt.Printf("=(%s, %s)\n", actual, expected)
	return fmt.Sprintf("%v", actual) == expected
}

type valueModifier func(next valueMatcher) valueMatcher

var modifiers = map[string]valueModifier{
	"contains": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			//fmt.Printf("contains(%s, %s)\n", actual, expected)
			return strings.Contains(fmt.Sprintf("%v", actual), expected)
		}
	},
	"endswith": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			//fmt.Printf("endswith(%s, %s)\n", actual, expected)
			return strings.HasSuffix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"startswith": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			//fmt.Printf("startswith(%s, %s)\n", actual, expected)
			return strings.HasPrefix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"base64": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			return next(actual, base64.StdEncoding.EncodeToString([]byte(expected)))
		}
	},
}
