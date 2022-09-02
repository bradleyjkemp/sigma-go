package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/bradleyjkemp/sigma-go"
)

func (rule RuleEvaluator) evaluateSearchExpression(search sigma.SearchExpr, searchResults map[string]bool) bool {
	switch s := search.(type) {
	case sigma.And:
		for _, node := range s {
			if !rule.evaluateSearchExpression(node, searchResults) {
				return false
			}
		}
		return true

	case sigma.Or:
		for _, node := range s {
			if rule.evaluateSearchExpression(node, searchResults) {
				return true
			}
		}
		return false

	case sigma.Not:
		return !rule.evaluateSearchExpression(s.Expr, searchResults)

	case sigma.SearchIdentifier:
		// If `s.Name` is not defined, this is always false
		return searchResults[s.Name]

	case sigma.OneOfThem:
		for name := range rule.Detection.Searches {
			if rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return true
			}
		}
		return false

	case sigma.OneOfPattern:
		for name := range rule.Detection.Searches {
			// it's not possible for this call to error because the search expression parser won't allow this to contain invalid expressions
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				continue
			}
			if rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return true
			}
		}
		return false

	case sigma.AllOfThem:
		for name := range rule.Detection.Searches {
			if !rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return false
			}
		}
		return true

	case sigma.AllOfPattern:
		for name := range rule.Detection.Searches {
			// it's not possible for this call to error because the search expression parser won't allow this to contain invalid expressions
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				continue
			}
			if !rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return false
			}
		}
		return true
	}
	panic(fmt.Sprintf("unhandled node type %T", search))
}

func (rule RuleEvaluator) evaluateSearch(ctx context.Context, search sigma.Search, event Event) (bool, error) {
	if len(search.Keywords) > 0 {
		return false, fmt.Errorf("keywords unsupported")
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
		comparator := baseComparator
		for _, name := range fieldModifiers {
			if modifiers[name] == nil {
				return false, fmt.Errorf("unsupported modifier %s", name)
			}
			comparator = modifiers[name](comparator)
		}

		matcherValues, err := rule.getMatcherValues(ctx, matcher)
		if err != nil {
			return false, err
		}
		values, err := rule.GetFieldValuesFromEvent(matcher.Field, event)
		if !rule.matcherMatchesValues(matcherValues, comparator, allValuesMustMatch, values) {
			// this field didn't match so the overall matcher doesn't match
			return false, nil
		}
	}

	// all fields matched
	return true, nil
}

func (rule *RuleEvaluator) getMatcherValues(ctx context.Context, matcher sigma.FieldMatcher) ([]string, error) {
	matcherValues := []string{}
	for _, value := range matcher.Values {
		if strings.HasPrefix(value, "%") && strings.HasSuffix(value, "%") {
			// expand placeholder to values
			placeholderValues, err := rule.expandPlaceholder(ctx, value)
			if err != nil {
				return nil, fmt.Errorf("failed to expand placeholder: %w", err)
			}
			matcherValues = append(matcherValues, placeholderValues...)
		} else {
			matcherValues = append(matcherValues, value)
		}
	}
	return matcherValues, nil
}

func (rule *RuleEvaluator) GetFieldValuesFromEvent(field string, event Event) ([]interface{}, error) {
	// First collect this list of event values we're matching against
	var actualValues []interface{}
	if len(rule.fieldmappings[field]) == 0 {
		// No FieldMapping exists so use the name directly from the rule
		actualValues = []interface{}{eventValue(event, field)}
	} else {
		// FieldMapping does exist so check each of the possible mapped names instead of the name from the rule
		for _, mapping := range rule.fieldmappings[field] {
			var v interface{}
			var err error

			switch {
			case strings.HasPrefix(mapping, "$.") || strings.HasPrefix(mapping, "$["):
				v, err = evaluateJSONPath(mapping, event)
			default:
				v = eventValue(event, mapping)
			}
			if err != nil {
				return nil, err
			}

			actualValues = append(actualValues, toGenericSlice(v)...)
		}
	}
	return actualValues, nil
}

func (rule *RuleEvaluator) matcherMatchesValues(matcherValues []string, comparator valueComparator, allValuesMustMatch bool, actualValues []interface{}) bool {
	matched := allValuesMustMatch
	for _, expectedValue := range matcherValues {
		valueMatchedEvent := false
		// There are multiple possible event fields that each expected value needs to be compared against
		for _, actualValue := range actualValues {
			if comparator(actualValue, expectedValue) {
				valueMatchedEvent = true
				break
			}
		}

		if allValuesMustMatch {
			matched = matched && valueMatchedEvent
		} else {
			matched = matched || valueMatchedEvent
		}
	}
	return matched
}

// This is a hack because none of the JSONPath libraries expose the parsed AST :(
// Matches JSONPaths with either a $.fieldname or $["fieldname"] prefix and extracts 'fieldname'
var firstJSONPathField = regexp.MustCompile(`^\$(?:[.]|\[")([a-zA-Z0-9_\-]+)(?:"])?`)

func evaluateJSONPath(expr string, event Event) (interface{}, error) {
	// First, just try to evaluate the JSONPath expression directly
	value, err := jsonpath.Get(expr, event)
	if err == nil {
		// Got no error so return the value directly
		return value, nil
	}
	if !strings.HasPrefix(err.Error(), "unsupported value type") {
		return nil, err
	}

	// Got an error: "unsupported value type X for select, expected map[string]interface{} or []interface{}"
	// This means we tried to access a nested field that hasn't yet been unmarshalled.
	// We try to fix this by finding the top-level field being selected and attempting to unmarshal it.
	// This is best effort and only works for top-level fields.
	// A longer term solution would be to either build this into the JSONPath library directly or remove this feature and let the user do it.

	jsonPathField := firstJSONPathField.FindStringSubmatch(expr)
	if jsonPathField == nil {
		return nil, fmt.Errorf("couldn't parse JSONPath expression")
	}

	var subValue interface{}
	switch e := event.(type) {
	case map[string]string:
		json.Unmarshal([]byte(e[jsonPathField[1]]), &subValue)
	case map[string]interface{}:
		switch sub := e[jsonPathField[1]].(type) {
		case string:
			json.Unmarshal([]byte(sub), &subValue)
		case []byte:
			json.Unmarshal(sub, &subValue)
		default:
			// Oh well, don't try to unmarshal the nested field
			value, _ := jsonpath.Get(expr, event)
			return value, nil
		}
	}

	value, _ = jsonpath.Get(expr, map[string]interface{}{
		jsonPathField[1]: subValue,
	})
	return value, nil
}

func toGenericSlice(v interface{}) []interface{} {
	rv := reflect.ValueOf(v)

	// if this isn't a slice, then return a slice containing the
	// original value
	if rv.Kind() != reflect.Slice {
		return []interface{}{v}
	}

	var out []interface{}
	for i := 0; i < rv.Len(); i++ {
		out = append(out, rv.Index(i).Interface())
	}

	return out
}
