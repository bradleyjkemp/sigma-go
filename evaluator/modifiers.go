package evaluator

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

type valueComparator func(actual interface{}, expected string) bool

func baseComparator(actual interface{}, expected string) bool {
	switch {
	case actual == nil && expected == "null":
		// special case: "null" should match the case where a field isn't present (and so actual is nil)
		return true
	default:
		return fmt.Sprintf("%v", actual) == expected
	}
}

type valueModifier func(next valueComparator) valueComparator

var modifiers = map[string]valueModifier{
	"contains": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			return strings.Contains(fmt.Sprintf("%v", actual), expected)
		}
	},
	"endswith": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			return strings.HasSuffix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"startswith": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			return strings.HasPrefix(fmt.Sprintf("%v", actual), expected)
		}
	},
	"base64": func(next valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			return next(actual, base64.StdEncoding.EncodeToString([]byte(expected)))
		}
	},
	"re": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			re, err := regexp.Compile(expected)
			if err != nil {
				// TODO: what to do here?
				return false
			}

			return re.MatchString(fmt.Sprintf("%v", actual))
		}
	},
}
