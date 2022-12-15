package evaluator

import (
	"encoding/base64"
	"fmt"
	"net"
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
		// The Sigma spec defines that by default comparisons are case-insensitive
		return strings.EqualFold(fmt.Sprintf("%v", actual), expected)
	}
}

type valueModifier func(next valueComparator) valueComparator

var modifiers = map[string]valueModifier{
	"contains": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return strings.Contains(strings.ToLower(fmt.Sprintf("%v", actual)), strings.ToLower(expected))
		}
	},
	"endswith": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return strings.HasSuffix(strings.ToLower(fmt.Sprintf("%v", actual)), strings.ToLower(expected))
		}
	},
	"startswith": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			return strings.HasPrefix(strings.ToLower(fmt.Sprintf("%v", actual)), strings.ToLower(expected))
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
	"cidr": func(_ valueComparator) valueComparator {
		return func(actual interface{}, expected string) bool {
			_, cidr, err := net.ParseCIDR(expected)
			if err != nil {
				// TODO: what to do here?
				return false
			}

			ip := net.ParseIP(fmt.Sprintf("%v", actual))
			return cidr.Contains(ip)
		}
	},
}
