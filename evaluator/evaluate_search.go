package evaluator

import (
	"encoding/base64"
	"fmt"
	"path"
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

	case sigma.OneOfThem:
		for name := range rule.Detection.Searches {
			if rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, event) {
				return true
			}
		}
		return false

	case sigma.OneOfPattern:
		for name := range rule.Detection.Searches {
			matchesPattern, err := path.Match(s.Pattern, name)
			if err != nil {
				panic(err)
			}
			if !matchesPattern {
				continue
			}
			if rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, event) {
				return true
			}
		}
		return false

	case sigma.AllOfThem:
		for name := range rule.Detection.Searches {
			if !rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, event) {
				return false
			}
		}
		return true

	case sigma.AllOfPattern:
		for name := range rule.Detection.Searches {
			matchesPattern, err := path.Match(s.Pattern, name)
			if err != nil {
				panic(err)
			}
			if !matchesPattern {
				continue
			}
			if !rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, event) {
				return false
			}
		}
		return true
	}

	panic(false)
}

func (rule RuleEvaluator) evaluateSearch(search sigma.Search, event map[string]interface{}) bool {
	if len(search.Keywords) > 0 {
		panic("keywords unsupported")
	}

	// A Search is a series of "does this field match this value" conditions
	// all need to match, for the Search to evaluate to true
	for _, matcher := range search.FieldMatchers {
		// A field matcher can specify multiple values to match against
		// either the field should match all of these values or it should match any of them
		allValuesMustMatch := false
		fieldModifiers := matcher.Modifiers
		if len(matcher.Modifiers) > 0 && fieldModifiers[len(fieldModifiers)-1] == "all" {
			allValuesMustMatch = true
			fieldModifiers = fieldModifiers[:len(fieldModifiers)-1]
		}

		// field matchers can specify modifiers (FieldName|modifier1|modifier2) which change the matching behaviour
		valueMatcher := baseMatcher
		for _, name := range fieldModifiers {
			if modifiers[name] == nil {
				panic(fmt.Errorf("unsupported modifier %s", name))
			}
			valueMatcher = modifiers[name](valueMatcher)
		}

		fieldMatched := allValuesMustMatch
		for _, value := range matcher.Values {
			// There are multiple possible event fields that each value needs to be compared against
			var valueMatches bool
			if len(rule.fieldmappings[matcher.Field]) == 0 {
				// No FieldMapping exists so use the name directly from the rule
				valueMatches = valueMatcher(event[matcher.Field], value)
			} else {
				// FieldMapping does exist so check each of the possible mapped names instead of the name from the rule
				for _, field := range rule.fieldmappings[matcher.Field] {
					valueMatches = valueMatcher(event[field], value)
					if valueMatches {
						break
					}
				}
			}

			if allValuesMustMatch {
				fieldMatched = fieldMatched && valueMatches
			} else {
				fieldMatched = fieldMatched || valueMatches
			}
		}

		if !fieldMatched {
			// this field didn't match so the overall matcher doesn't match
			return false
		}
	}

	// all fields matched
	return true
}

type valueMatcher func(actual interface{}, expected string) bool

func baseMatcher(actual interface{}, expected string) bool {
	return fmt.Sprintf("%v", actual) == expected
}

type valueModifier func(next valueMatcher) valueMatcher

var modifiers = map[string]valueModifier{
	"contains": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			return strings.Contains(fmt.Sprintf("%v", actual), expected)
		}
	},
	"endswith": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			return strings.HasSuffix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"startswith": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			return strings.HasPrefix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"base64": func(next valueMatcher) valueMatcher {
		return func(actual interface{}, expected string) bool {
			return next(actual, base64.StdEncoding.EncodeToString([]byte(expected)))
		}
	},
}
